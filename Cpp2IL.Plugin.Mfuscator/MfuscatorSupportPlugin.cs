using System.Runtime.InteropServices;
using AssetRipper.Primitives;
using Cpp2IL.Core.Api;
using Cpp2IL.Core.Attributes;
using LibCpp2IL;
using LibCpp2IL.Metadata;

[assembly:RegisterCpp2IlPlugin(typeof(Cpp2IL.Plugin.Mfuscator.MfuscatorSupportPlugin))]

namespace Cpp2IL.Plugin.Mfuscator;

public class MfuscatorSupportPlugin : Cpp2IlPlugin
{
    private const int MaxHeaderSize = 480; //somewhat arbitrary

    private const int StringLiteralsSectionIndex = 0;
    private const int StringLiteralsDataSectionIndex = 1;
    private const int StringsSectionIndex = 2;
    private const int PropertiesSectionIndex = 4;
    private const int MethodsSectionIndex = 5;
    private const int FieldsSectionIndex = 11;

    //Lets us ask a metadata class how much it reads without having any metadata to hand.
    private sealed class RecordSizingReader(Stream stream, float metadataVersion) : ClassReadingBinaryReader(stream)
    {
        public override float MetadataVersion { get; } = metadataVersion;
    }

    //A section of fixed-size records can only be a whole number of records long, which rules out
    //most of the values in the mangled header. Rather than keep our own copy of the sizes, read
    //one record of each and count the bytes. Sections of raw bytes have no size and are left out.
    private Dictionary<int, int>? GetSectionRecordSizes(byte metadataVersion, int assembliesSectionIndex)
    {
        //From v38 index widths depend on metadata we haven't read yet, so records can't be
        //measured up front. The section numbering below is the usual layout.
        if (metadataVersion >= 38 || assembliesSectionIndex != 21)
            return null;

        using var stream = new MemoryStream(new byte[4096]);
        var reader = new RecordSizingReader(stream, metadataVersion);

        int SizeOf<T>() where T : ReadableClass, new()
        {
            try
            {
                reader.Position = 0;
                reader.ReadReadable<T>(0);
                return (int) reader.Position;
            }
            catch (Exception)
            {
                return 0; //couldn't measure it, so don't constrain that section
            }
        }

        var sizes = new Dictionary<int, int>
        {
            { 0, SizeOf<Il2CppStringLiteral>() },
            { 3, SizeOf<Il2CppEventDefinition>() },
            { 4, SizeOf<Il2CppPropertyDefinition>() },
            { 5, SizeOf<Il2CppMethodDefinition>() },
            { 6, SizeOf<Il2CppParameterDefaultValue>() },
            { 7, SizeOf<Il2CppFieldDefaultValue>() },
            { 10, SizeOf<Il2CppParameterDefinition>() },
            { 11, SizeOf<Il2CppFieldDefinition>() },
            { 12, SizeOf<Il2CppGenericParameter>() },
            { 13, sizeof(int) },  //generic parameter constraints are bare type indices
            { 14, SizeOf<Il2CppGenericContainer>() },
            { 15, SizeOf<Il2CppNestedTypeIndex>() },
            { 16, sizeof(int) },  //interfaces are bare type indices
            { 17, sizeof(uint) }, //vtable methods are bare encoded tokens
            { 18, SizeOf<Il2CppInterfaceOffset>() },
            { 19, SizeOf<Il2CppTypeDefinition>() },
            { 20, SizeOf<Il2CppImageDefinition>() },
            { 21, SizeOf<Il2CppAssemblyDefinition>() },
            { 22, SizeOf<Il2CppFieldRef>() },
            { 23, sizeof(int) },  //referenced assemblies are bare indices
            { 25, SizeOf<Il2CppCustomAttributeDataRange>() },
            { 26, sizeof(int) },  //unresolved virtual call parameter types are bare type indices
            { 30, sizeof(int) },  //exported types are bare type indices
        };

        //A record holding an index whose width isn't known until metadata has been read can't be
        //measured here, so those sections go unconstrained rather than wrongly constrained.
        foreach (var sectionIndex in sizes.Where(pair => pair.Value <= 0).Select(pair => pair.Key).ToList())
            sizes.Remove(sectionIndex);

        Logger.VerboseNewline($"Constraining sections {string.Join(", ", sizes.Keys.Order())} to a whole number of records.");

        return sizes.Count > 0 ? sizes : null;
    }

    private record struct ReconstructedSection(int OffsetAccordingToHeader, int Length, int Delta)
    {
        public int ActualOffset => OffsetAccordingToHeader + Delta;
    }

    private record struct DeadEnd(int depth, int deadEndNumber, int actualPos, string reason, List<ReconstructedSection> sections) : IComparable<DeadEnd>
    {
        public int CompareTo(DeadEnd other)
        {
            //inverted so largest first
            return other.depth.CompareTo(depth);
        }
    }
    
    private class SectionRangeComparer : IEqualityComparer<(int Start, int End)[]>
    {
        public bool Equals((int Start, int End)[]? x, (int Start, int End)[]? y)
        {
            return x != null && y != null && x.SequenceEqual(y);
        }

        public int GetHashCode((int Start, int End)[] obj)
        {
            return obj.Aggregate(0, (hash, range) => HashCode.Combine(hash, range.Start, range.End));
        }
    }
    
    public override string Name => "Mfuscator Support"; //more like midfuscator amirite
    public override string Description => "Supports loading metadata files which have been mangled by mfuscator.";
    public override void OnLoad()
    {
        RegisterMetadataFixupFunc(TryFixupMfuscatorMetadata);
    }
    
    private static void CyclicXorHeader(ReadOnlySpan<byte> data, Span<byte> output, byte xorKey, bool isPlus, int offset = 0)
    {
        for (var i = 0; i < data.Length; i++)
        {
            var keyByte = (byte) ((isPlus 
                ? (xorKey + offset + i) 
                : (xorKey - (offset + i))) & 0xFF);
            output[i] = (byte) (data[i] ^ keyByte);
        }
    }

    private static void CyclicXor(ReadOnlySpan<byte> data, Span<byte> output, byte xorKey, bool isPlus, int offset = 0)
    {
        for (var i = 0; i < data.Length; i++)
        {
            var keyByte = (byte) ((isPlus 
                ? (xorKey + offset + i) 
                : (i - offset - xorKey)) & 0xFF);
            output[i] = (byte) (data[i] ^ keyByte);
        }
    }
    
    //No header field can be larger than the file, since each is an offset into it or a length
    //within it. The right key therefore decrypts a long run of values that fit, and a wrong one
    //stops almost immediately - giving us the key, the rotation and the header size at once.
    private static bool TryDeriveHeaderKey(Span<byte> encryptedMetadata, out byte xorKey, out bool isPlus, out int headerSize)
    {
        xorKey = 0;
        isPlus = false;
        headerSize = 0;

        var fileSize = (uint) encryptedMetadata.Length;
        var maxWords = Math.Min(MaxHeaderSize, encryptedMetadata.Length) / 4;
        var bestRun = 0;
        var waysToGetBestRun = 0;

        for (var key = 0; key < 256; key++)
        {
            for (var direction = 0; direction < 2; direction++)
            {
                var plus = direction == 0;

                var run = 0;
                while (run < maxWords)
                {
                    var offset = run * 4;
                    uint word = 0;
                    for (var i = 0; i < 4; i++)
                    {
                        var keyByte = (byte) ((plus ? (key + offset + i) : (key - (offset + i))) & 0xFF);
                        word |= (uint) (encryptedMetadata[offset + i] ^ keyByte) << (8 * i);
                    }

                    if (word >= fileSize)
                        break;

                    run++;
                }

                if (run > bestRun)
                {
                    bestRun = run;
                    xorKey = (byte) key;
                    isPlus = plus;
                    waysToGetBestRun = 1;
                }
                else if (run == bestRun && run > 0)
                {
                    waysToGetBestRun++;
                }
            }
        }

        headerSize = bestRun * 4;

        //A real header is dozens of fields long and only one key produces it.
        return bestRun >= 8 && waysToGetBestRun == 1;
    }

    private byte[] DecryptHeader(Span<byte> encryptedHeader, out byte stringLiteralsXorKey, out bool stringLiteralsIsPlus)
    {
        if (!TryDeriveHeaderKey(encryptedHeader, out var xorKey, out var isPlus, out var headerSize))
            throw new Exception("Failed to derive XOR key");

        if (headerSize + 8 > encryptedHeader.Length)
            throw new Exception("Failed to determine header size");

        Logger.VerboseNewline($"Derived header XOR key: 0x{xorKey:X2}. Header fields use {(isPlus ? "plus" : "minus")} rotation. Header is {headerSize} bytes.");

        var decryptedHeader = new byte[headerSize];
        CyclicXorHeader(encryptedHeader[..headerSize], decryptedHeader, xorKey, isPlus);

        //String literal data starts where the header stops, and its first bytes are zero in the
        //clear, so the encrypted bytes there are the key stream for that section.
        var encryptedWord = encryptedHeader[headerSize..(headerSize + 4)];
        var nextEncryptedWord = encryptedHeader[(headerSize + 4)..(headerSize + 8)];

        stringLiteralsXorKey = encryptedWord[0];
        stringLiteralsIsPlus = nextEncryptedWord[0] == encryptedWord[0] + 4;

        return decryptedHeader;
    }

    //Returns every complete section chain that fits within maxEnd and where each one ends, which
    //is the metadata length it implies. One search against an upper bound covers every length.
    private List<(List<ReconstructedSection> Sections, int EndPos)> FindPathsThroughMetadata(uint[] headerWords, int dataStart, int maxEnd, out SortedCollection<DeadEnd> bestDeadEnds, int maxResults = 10, int debugBestN = 10, int? expectedSectionCount = null, Dictionary<int, int>? alignBefore = null, int? originalHeaderSize = null, Dictionary<int, int>? recordSizes = null)
    {
        alignBefore ??= new();
        var realOriginalHeaderSize = originalHeaderSize ?? dataStart;
        var maxAlignPad = alignBefore.Values.DefaultIfEmpty(1).Max() - 1;

        var totalDeadEnds = 0;
        var deadEndCounter = 0;
        List<DeadEnd> deadEnds = new();
        var localBestDeadEnds = bestDeadEnds = new();

        //The pool only ever changes which words are spoken for, never its size, so a sorted array
        //plus a used flag keeps claiming and releasing O(1) and lets us binary search it.
        var pool = headerWords.ToArray();
        Array.Sort(pool);
        var used = new bool[pool.Length];

        List<(List<ReconstructedSection> Sections, int EndPos)> results = new();

        DepthFirstSearch(dataStart, []);

        return results;

        //Index of the last word that is <= value, or -1 if there is no such word.
        int LastAtMost(long value)
        {
            int lo = 0, hi = pool.Length - 1, found = -1;
            while (lo <= hi)
            {
                var mid = (lo + hi) >> 1;
                if (pool[mid] <= value)
                {
                    found = mid;
                    lo = mid + 1;
                }
                else
                    hi = mid - 1;
            }

            return found;
        }

        //Index of the first word that is >= value, or pool.Length if there is no such word.
        int FirstAtLeast(long value)
        {
            int lo = 0, hi = pool.Length;
            while (lo < hi)
            {
                var mid = (lo + hi) >> 1;
                if (pool[mid] < value)
                    lo = mid + 1;
                else
                    hi = mid;
            }

            return lo;
        }

        void TrackDeadEnd(int actualPos, List<ReconstructedSection> sections, string reason)
        {
            if(debugBestN <= 0)
                return; //we're not tracking dead ends, so ignore this
            
            totalDeadEnds++;
            deadEndCounter++;
            var depth = sections.Count;
            
            if(localBestDeadEnds.Count > 0 && depth < localBestDeadEnds[0].depth)
                return; //we've already got better dead ends, so ignore this one

            var entry = new DeadEnd(depth, deadEndCounter, actualPos, reason, sections.ToList());
            deadEnds.Add(entry);
            
            localBestDeadEnds.Add(entry);
            if (localBestDeadEnds.Count > debugBestN)
                localBestDeadEnds.RemoveAt(localBestDeadEnds.Count - 1);
        }

        //Alignment is according to the header before it was mangled, i.e. with original header size
        int ApplyAlignment(int actualPos, int sectionIndex)
        {
            if(!alignBefore.TryGetValue(sectionIndex, out var align))
                return actualPos;

            var originalOffset = realOriginalHeaderSize + (actualPos - dataStart);
            var remainder = originalOffset % align;
            if (remainder == 0)
                return actualPos;
            
            var padding = align - remainder;
            return actualPos + padding;
        }

        void DepthFirstSearch(int actualPos, List<ReconstructedSection> sections)
        {
            if(results.Count >= maxResults)
                return;

            var sectionIndex = sections.Count;
            actualPos = ApplyAlignment(actualPos, sectionIndex);

            //A full chain is a candidate answer and actualPos is the length it implies. Accepting
            //here rather than at a fixed file end is what lets one search cover every length.
            if (expectedSectionCount != null && sections.Count == expectedSectionCount)
            {
                results.Add(([..sections], actualPos));
                return;
            }

            if (actualPos >= maxEnd)
            {
                if (expectedSectionCount == null)
                    results.Add(([..sections], actualPos));

                return; //we've gone past the end of the file, so this is invalid
            }

            const int MinDelta = 0x10;
            const int MaxDelta = 0x40;

            //A section's offset field sits a little way either side of where the section really
            //starts, so only two narrow windows of the sorted pool can supply it.
            var beforeFrom = FirstAtLeast((long)actualPos - MaxDelta);
            var beforeTo = LastAtMost((long)actualPos - MinDelta);
            var afterFrom = FirstAtLeast((long)actualPos + MinDelta);
            var afterTo = LastAtMost((long)actualPos + MaxDelta);

            //Largest length that still fits. Working downwards from it tries longer sections first,
            //surfacing the layouts that consume most of the file before maxResults is reached.
            var lengthLimit = LastAtMost((long)maxEnd + maxAlignPad - actualPos);

            var sectionRecordSize = recordSizes != null && recordSizes.TryGetValue(sectionIndex, out var rs) ? rs : 0;

            var anyOffsetFound = false;
            var anyLengthFound = false;

            for (var window = 0; window < 2; window++)
            {
                var from = window == 0 ? beforeFrom : afterFrom;
                var to = window == 0 ? beforeTo : afterTo;

                for (var i = from; i <= to; i++)
                {
                    if (used[i])
                        continue;

                    //Equal words are interchangeable, so only take the first free one of each run.
                    //Trying the rest would just rediscover the same layouts.
                    if (i > from && pool[i] == pool[i - 1] && !used[i - 1])
                        continue;

                    anyOffsetFound = true;

                    var candidateOffset = pool[i];
                    var delta = actualPos - candidateOffset;
                    used[i] = true;

                    for (var j = lengthLimit; j >= 0; j--)
                    {
                        if (used[j])
                            continue;

                        if (j < lengthLimit && pool[j] == pool[j + 1] && !used[j + 1])
                            continue;

                        var length = pool[j];

                        //this cuts down on the number of invalid paths we get quite significantly
                        if (sectionIndex < 26 && length == 0)
                            //don't allow zero lengths for the first 26 sections
                            continue;

                        //A section of fixed-size records can only be a whole number of them long
                        if (sectionRecordSize != 0 && length % sectionRecordSize != 0)
                            continue;

                        used[j] = true;
                        anyLengthFound = true;
                        sections.Add(new ReconstructedSection((int)candidateOffset, (int)length, (int)delta));

                        DepthFirstSearch((int)(actualPos + length), sections);

                        sections.RemoveAt(sections.Count - 1);
                        used[j] = false;
                    }

                    used[i] = false;
                }
            }

            if (!anyOffsetFound)
            {
                TrackDeadEnd(actualPos, sections, "No valid candidate offsets");
                return; //no more valid offsets, so this is a dead end
            }

            if (!anyLengthFound)
            {
                TrackDeadEnd(actualPos, sections, "No valid length found for any candidate offset");
            }
        }
    }
    
    private Dictionary<int, byte[]> DecryptEncryptedSections(byte[] encryptedMetadata, List<(int Start, int End)> sections, byte stringLiteralsXorKey, bool stringLiteralsIsPlus, int assembliesSectionIndex)
    {
        var decryptedSectionBytes = new Dictionary<int, byte[]>();
        
        //Use the size of the section and the information we worked out earlier to derive the key shared between all sections
        var stringLiteralsStart = sections[StringLiteralsSectionIndex].Start;
        var stringLiteralsSize = sections[StringLiteralsSectionIndex].End - sections[StringLiteralsSectionIndex].Start;

        foreach (var usingOffsetNotSize in stackalloc bool[] { true, false })
        {
            try
            {
                byte sectionsXorKeyAddend = 0;
                var stringLiteralsKeyComponent = usingOffsetNotSize ? stringLiteralsStart : stringLiteralsSize;
                var testAddend = (byte)((stringLiteralsIsPlus ? (stringLiteralsXorKey - stringLiteralsKeyComponent) : (stringLiteralsXorKey + stringLiteralsKeyComponent)) & 0xFF);

                //Now decrypt the string literals section
                var decryptedLiterals = new byte[stringLiteralsSize];
                CyclicXor(
                    encryptedMetadata.AsSpan(sections[StringLiteralsSectionIndex].Start, stringLiteralsSize),
                    decryptedLiterals,
                    testAddend,
                    stringLiteralsIsPlus,
                    stringLiteralsKeyComponent
                );

                if (decryptedLiterals[0] == 0 && decryptedLiterals[1] == 0)
                {
                    sectionsXorKeyAddend = testAddend;
                    decryptedSectionBytes[StringLiteralsSectionIndex] = decryptedLiterals;
                }
                
                if (!decryptedSectionBytes.ContainsKey(StringLiteralsSectionIndex))
                    throw new Exception("Failed to determine whether section keys are based on offsets or sizes");
                
                Logger.VerboseNewlineIfDebug($"Section keys are based on {(usingOffsetNotSize ? "offsets" : "sizes")}, with addend 0x{sectionsXorKeyAddend:X2}");

                //String literal data starts with 2 00 bytes, so we can get the direction from that
                var stringLiteralDataStart = sections[StringLiteralsDataSectionIndex].Start;
                var stringLiteralDataSize = sections[StringLiteralsDataSectionIndex].End - sections[StringLiteralsDataSectionIndex].Start;
                var stringLiteralDataKeyComponent = usingOffsetNotSize ? stringLiteralDataStart : stringLiteralDataSize;

                var firstByte = encryptedMetadata[stringLiteralDataStart];
                var secondByte = encryptedMetadata[stringLiteralDataStart + 1];
                var stringLiteralDataIsPlus = ((firstByte + 1) & 0xFF) == secondByte;
                var stringLiteralDataIsMinus = ((firstByte - 1) & 0xFF) == secondByte;
                if (!stringLiteralDataIsPlus && !stringLiteralDataIsMinus)
                    throw new Exception("Failed to determine string literal data XOR direction");

                if (stringLiteralDataIsPlus)
                {
                    //check for underflow resulting in wrong initial key
                    var encryptedFirstWord = encryptedMetadata.AsSpan(stringLiteralDataStart, 4);
                    var decryptedFirstWord = new byte[4];
                    CyclicXor(
                        encryptedFirstWord,
                        decryptedFirstWord,
                        sectionsXorKeyAddend,
                        true,
                        stringLiteralDataKeyComponent
                    );
                    if (decryptedFirstWord[0] != 0)
                    {
                        stringLiteralDataIsPlus = false;
                        sectionsXorKeyAddend = (byte)((0 - stringLiteralsXorKey - stringLiteralsKeyComponent) & 0xFF);
                    }
                }

                //And decrypt it
                var decryptedLiteralData = decryptedSectionBytes[StringLiteralsDataSectionIndex] = new byte[stringLiteralDataSize];
                CyclicXor(
                    encryptedMetadata.AsSpan(stringLiteralDataStart, stringLiteralDataSize),
                    decryptedLiteralData,
                    sectionsXorKeyAddend,
                    stringLiteralDataIsPlus,
                    stringLiteralDataKeyComponent
                );

                //Strings are a bit harder, we need to look for the null terminators in the first 32 bytes
                var stringsSectionStart = sections[StringsSectionIndex].Start;
                var stringsSectionSize = sections[StringsSectionIndex].End - sections[StringsSectionIndex].Start;
                var stringsSectionKeyComponent = usingOffsetNotSize ? stringsSectionStart : stringsSectionSize;
                var stringsFirstXorByteOffset = 0;
                var stringsIsPlus = false;
                var foundZeroBytes = 0;
                foreach (var testIsPlus in new bool[] { true, false })
                {
                    foundZeroBytes = 0;
                    stringsIsPlus = testIsPlus;
                    for (var i = 0; i < 32; i++)
                    {
                        var assumedXorKey = (byte)((testIsPlus
                            ? (i + stringsSectionKeyComponent + sectionsXorKeyAddend)
                            : (i - stringsSectionKeyComponent - sectionsXorKeyAddend)) & 0xFF);
                        var xorByte = (byte)(encryptedMetadata[stringsSectionStart + i] ^ assumedXorKey);
                        if (xorByte == 0)
                        {
                            foundZeroBytes++;
                            if (foundZeroBytes == 1)
                                stringsFirstXorByteOffset = i;
                            else if (foundZeroBytes == 2)
                                break; //we've found the first two null terminators, which is enough to be confident we've got the right key direction
                        }
                    }

                    if (foundZeroBytes == 2)
                        break;
                }

                if (foundZeroBytes != 2)
                    throw new Exception("Failed to determine strings section XOR direction");

                //sanity check
                var stringsXorByte = (byte)((stringsIsPlus
                    ? (stringsFirstXorByteOffset + stringsSectionKeyComponent + sectionsXorKeyAddend)
                    : (stringsFirstXorByteOffset - stringsSectionKeyComponent - sectionsXorKeyAddend)) & 0xFF);

                if (encryptedMetadata[stringsSectionStart + stringsFirstXorByteOffset] != stringsXorByte)
                    throw new Exception("Strings section XOR key doesn't seem to be correct");

                //ok now decrypt strings
                var decryptedStrings = decryptedSectionBytes[StringsSectionIndex] = new byte[stringsSectionSize];
                CyclicXor(
                    encryptedMetadata.AsSpan(stringsSectionStart, stringsSectionSize),
                    decryptedStrings,
                    sectionsXorKeyAddend,
                    stringsIsPlus,
                    stringsSectionKeyComponent
                );

                //for the rest of the sections we can just check the 3rd byte is 0 to determine the direction
                var remainingEncryptedSections = new int[] { PropertiesSectionIndex, MethodsSectionIndex, FieldsSectionIndex, assembliesSectionIndex };
                foreach (var sectionIndex in remainingEncryptedSections)
                {
                    var sectionStart = sections[sectionIndex].Start;
                    var sectionSize = sections[sectionIndex].End - sections[sectionIndex].Start;
                    var sectionKeyComponent = usingOffsetNotSize ? sectionStart : sectionSize;

                    var decryptedSection = new byte[sectionSize];
                    foreach (var testIsPlus in new bool[] { true, false })
                    {
                        CyclicXor(
                            encryptedMetadata.AsSpan(sectionStart, sectionSize),
                            decryptedSection,
                            sectionsXorKeyAddend,
                            testIsPlus,
                            sectionKeyComponent
                        );
                        if (decryptedSection[3] == 0)
                        {
                            decryptedSectionBytes[sectionIndex] = decryptedSection;
                            break;
                        }
                    }

                    if (!decryptedSectionBytes.ContainsKey(sectionIndex))
                        throw new Exception($"Failed to determine XOR direction for section at index {sectionIndex}");
                }

                return decryptedSectionBytes;
            }
            catch (Exception)
            {
                continue;
            }
        }
        
        throw new Exception("Failed to decrypt sections with either offset-based or size-based keys");
    }
    
    private byte[] RebuildMetadata(byte[] encryptedMetadata, List<(int Start, int End)> sections, byte stringLiteralsXorKey, bool stringLiteralsIsPlus, int offsetDelta, byte metadataVersion, int assembliesSectionIndex)
    {
        var decryptedSections = DecryptEncryptedSections(encryptedMetadata, sections, stringLiteralsXorKey, stringLiteralsIsPlus, assembliesSectionIndex);
        
        var decryptedMetadata = new byte[encryptedMetadata.Length];
        Span<byte> magicAndVersion = [0xAF, 0x1B, 0xB1, 0xFA, metadataVersion, 0x00, 0x00, 0x00];
        magicAndVersion.CopyTo(decryptedMetadata);
        
        var headerSpan = decryptedMetadata.AsSpan(8, 256 - 8);

        for (var i = 0; i < sections.Count; i++)
        {
            var (start, end) = sections[i];
            
            //Write offset and length to header
            var offsetBytes = BitConverter.GetBytes(start + offsetDelta).AsSpan();
            var lengthBytes = BitConverter.GetBytes(end - start).AsSpan();
            offsetBytes.CopyTo(headerSpan);
            lengthBytes.CopyTo(headerSpan[4..]);
            headerSpan = headerSpan[8..];

            //And copy over data
            var sectionSpan = decryptedMetadata.AsSpan(start + offsetDelta, end - start);
            //Decrypted if it was encrypted, else copy straight from the original file
            var sectionData = decryptedSections.GetValueOrDefault(i) ?? encryptedMetadata.AsSpan(start, end - start).ToArray();
            sectionData.CopyTo(sectionSpan);
        }

        return decryptedMetadata;
    }

    private byte[]? TryFixupMfuscatorMetadata(byte[] originalBytes, UnityVersion unityVersion)
    {
        var decryptedHeader = DecryptHeader(originalBytes, out var stringLiteralsXorKey, out var stringLiteralsIsPlus);
        
        var headerLength = decryptedHeader.Length;
         
        var headerWords = MemoryMarshal.Cast<byte, uint>(decryptedHeader).ToArray();
        
        //There is some garbage data at the end of the file, which confuses the actual length of the metadata (which we use to find a chain through the real/fake values in the header to identify the real ones)
        //So we unfortunately have to bruteforce it, reducing the length of the metadata by 4 bytes at a time until we get a path.
        var metadataLength = originalBytes.Length;

        var sectionAlignments = new Dictionary<int, int>
        {
            { 8, 8 }, //fieldAndParameterDefaultValueData
        };

        byte MetadataVersion;
        if (unityVersion.LessThan(2017))
            MetadataVersion = 23;
        else if (unityVersion.LessThan(2020, 2))
            MetadataVersion = 24;
        else if (unityVersion.LessThan(2021, 3))
            MetadataVersion = 27;
        else if (unityVersion.LessThan(2022, 3, 33))
            MetadataVersion = 29;
        else if(unityVersion.LessThan(6000, 3, 0, UnityVersionType.Alpha, 2))
            MetadataVersion = 31;
        else if(unityVersion.LessThan(6000, 3, 0, UnityVersionType.Alpha, 5))
            MetadataVersion = 35;
        else if (unityVersion.LessThan(6000, 3, 0, UnityVersionType.Beta, 1))
            MetadataVersion = 38;
        else if (unityVersion.LessThan(6000, 5, 0, UnityVersionType.Alpha, 3))
            MetadataVersion = 39;
        else if (unityVersion.LessThan(6000, 5, 0, UnityVersionType.Alpha, 5))
            MetadataVersion = 104;
        else if (unityVersion.LessThan(6000, 3, 0, UnityVersionType.Alpha, 6))
            MetadataVersion = 105;
        else
            MetadataVersion = 106;

        var assembliesSectionIndex = 21;
        if (MetadataVersion > 103)
            assembliesSectionIndex = 22; //typeInlineArrays added before it
        else if (MetadataVersion == 24 && unityVersion.LessThan(2019))
            assembliesSectionIndex = 22; //pre-24.2 we have rgctxEntries before assemblies
        
        var expectedSectionCount = MetadataVersion switch
        {
            >= 104 => 32,
            >= 27 => 31,
            _ => throw new NotImplementedException("Metadata versions below 27 aren't currently supported (largely because mfuscator itself doesn't support these versions)")
        };
        var bytesPerSectionHeaderField = MetadataVersion switch
        {
            >= 38 => 12,
            _ => 8
        };
        
        if(bytesPerSectionHeaderField == 12)
            throw new NotImplementedException("Metadata versions with 12 bytes per section header field aren't currently supported");
        
        var originalHeaderSize = 8 + expectedSectionCount * bytesPerSectionHeaderField; //magic + version + 8 bytes per section header field
        var sectionRecordSizes = GetSectionRecordSizes(MetadataVersion, assembliesSectionIndex);

        Logger.InfoNewline($"Mfuscator header decrypted successfully. Header length: {headerLength} bytes. String literals XOR key: 0x{stringLiteralsXorKey:X2}. String literals use {(stringLiteralsIsPlus ? "plus" : "minus")} rotation. Will rebuild as version {MetadataVersion} metadata with assemblies section at index {assembliesSectionIndex}.");
        
        Logger.VerboseNewline("Decrypted header: " + string.Join("", decryptedHeader.Select(b => b.ToString("X2"))));
        
        //One search bounded by the largest the metadata could be covers every candidate length,
        //since each chain reports where it ends.
        var paths = FindPathsThroughMetadata(headerWords, headerLength, metadataLength, out _, maxResults: 65536, debugBestN: 0, expectedSectionCount: expectedSectionCount, alignBefore: sectionAlignments, originalHeaderSize: originalHeaderSize, recordSizes: sectionRecordSizes);

        if (paths.Count == 0)
            return null;

        //We'll likely get a couple dozen paths due to the fake offsets, which vary in supposed position and delta, but they should all agree on *actual* position in file.
        //We check that that's the case, and take those actual positions as gospel.
        //NB actually we don't check if that's the case because they sometimes differ in unimportant sections, too bad!
        Logger.VerboseNewlineIfDebug($"Found {paths.Count} possible section layouts.");

        //Longest first, matching the old behaviour of trying the largest metadata length first.
        var distinct = paths
            .OrderByDescending(path => path.EndPos)
            .Select(path => path.Sections.Select(section => (section.ActualOffset, section.ActualOffset + section.Length)).ToArray())
            .Distinct(new SectionRangeComparer())
            .ToArray();

        Logger.VerboseNewlineIfDebug($"These collapse to {distinct.Length} distinct actual section layouts.");

        foreach (var acceptedLayout in distinct)
        {
            Logger.VerboseNewlineIfDebug($"Trying section layout: " + string.Join(", ", acceptedLayout.Select(range => $"({range.Item1:X4}-{range.Item2:X4})")));

            try
            {
                var rebuiltMetadata = RebuildMetadata(originalBytes, acceptedLayout.ToList(), stringLiteralsXorKey, stringLiteralsIsPlus, offsetDelta: originalHeaderSize - headerLength, MetadataVersion, assembliesSectionIndex);

                Logger.InfoNewline("Returning decrypted metadata now...");
                return rebuiltMetadata;
            }
            catch (Exception)
            {
                continue;
            }
        }

        return null;
    }
}
