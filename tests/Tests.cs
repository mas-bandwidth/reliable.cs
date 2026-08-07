/*
    Tests.cs

    Console test runner for the C# reliable port. Zero third-party dependencies,
    including test frameworks (family value): each test prints its name, a failed
    check prints and exits nonzero — the exact shape of check / RUN_TEST in the C
    library.

    The suite is a test-for-test port of the C suite embedded in reliable.c
    (minus test_endian, irrelevant with explicit little-endian primitives), plus
    golden wire pins generated from the real C library, plus the C#-specific
    hostile-input, allocation and soak tests in Hostile.cs and Soak.cs.
*/

using System;
using Reliable;

namespace Reliable.Tests;

internal static partial class Tests
{
    // ------------------------------------------------------------
    // runner

    internal static void Check(bool condition, string message)
    {
        if (!condition)
        {
            Console.Error.WriteLine($"    check failed: {message}");
            Environment.Exit(1);
        }
    }

    // optional substring filter from the command line: run only matching tests
    private static string? s_filter;
    private static int s_testsRun;
    private static bool s_shortMode;

    private static void RunTest(string name, Action test)
    {
        if (s_filter != null && !name.Contains(s_filter, StringComparison.Ordinal))
        {
            return;
        }
        Console.WriteLine(name);
        s_testsRun++;
        test();
    }

    private static int Main(string[] args)
    {
        // usage: [short] [filter-substring]
        foreach (string arg in args)
        {
            if (arg == "short")
            {
                s_shortMode = true;
            }
            else
            {
                s_filter = arg;
            }
        }

        // the C suite, test for test
        RunTest("test_sequence_buffer", TestSequenceBuffer);
        RunTest("test_generate_ack_bits", TestGenerateAckBits);
        RunTest("test_packet_header", TestPacketHeader);
        RunTest("test_acks", TestAcks);
        RunTest("test_acks_packet_loss", TestAcksPacketLoss);
        RunTest("test_duplicate_packets", TestDuplicatePackets);
        RunTest("test_stale_packets", TestStalePackets);
        RunTest("test_ack_buffer_overflow", TestAckBufferOverflow);
        RunTest("test_packets", TestPackets);
        RunTest("test_large_packets", TestLargePackets);
        RunTest("test_sequence_buffer_rollover", TestSequenceBufferRollover);
        RunTest("test_fragment_cleanup", TestFragmentCleanup);
        RunTest("test_rtt", TestRtt);
        RunTest("test_endpoint_reset", TestEndpointReset);

        // golden wire pins, generated from the real C library (v1.4.0)
        RunTest("test_golden_packet_headers", TestGoldenPacketHeaders);
        RunTest("test_golden_fragments", TestGoldenFragments);

        // C#-specific: hostile input, API misuse, allocation discipline
        RunTest("test_hostile_truncated_headers", TestHostileTruncatedHeaders);
        RunTest("test_hostile_fragments", TestHostileFragments);
        RunTest("test_hostile_parser_fuzz", TestHostileParserFuzz);
        RunTest("test_process_reject_redelivery", TestProcessRejectRedelivery);
        RunTest("test_config_validation", TestConfigValidation);
        RunTest("test_zero_allocation", TestZeroAllocation);
        RunTest("test_fuzz_script", TestFuzzScript);

        // C#-specific: seeded adversarial soak (the fuzz.c link model)
        RunTest("test_soak", TestSoak);

        if (s_testsRun == 0)
        {
            Console.Error.WriteLine($"no tests matched filter '{s_filter}'");
            return 1;
        }

        Console.WriteLine($"\n{s_testsRun} tests passed");
        return 0;
    }

    // ------------------------------------------------------------
    // shared helpers (the C test harness shapes)

    internal sealed class TestContext
    {
        public bool Drop;
        public int AllowPackets = -1;
        public Endpoint? Sender;
        public Endpoint? Receiver;
    }

    private static TransmitPacketCallback MakeTransmit(TestContext context)
    {
        return (id, sequence, packetData) =>
        {
            if (context.Drop)
            {
                return;
            }

            if (context.AllowPackets >= 0)
            {
                if (context.AllowPackets == 0)
                {
                    return;
                }
                context.AllowPackets--;
            }

            if (id == 0)
            {
                context.Receiver!.ReceivePacket(packetData);
            }
            else if (id == 1)
            {
                context.Sender!.ReceivePacket(packetData);
            }
        };
    }

    private static readonly ProcessPacketCallback s_acceptAll = (id, sequence, packetData) => true;

    private static EndpointConfig DefaultConfig(TestContext context, ulong id, string name)
    {
        return new EndpointConfig
        {
            Name = name,
            Id = id,
            TransmitPacket = MakeTransmit(context),
            ProcessPacket = s_acceptAll,
        };
    }

    internal static ulong Fnv1a64(ReadOnlySpan<byte> data)
    {
        ulong hash = 14695981039346656037ul;
        for (int i = 0; i < data.Length; i++)
        {
            hash ^= data[i];
            hash = unchecked(hash * 1099511628211ul);
        }
        return hash;
    }

    internal static byte[] FromHex(string hex)
    {
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return result;
    }

    // ------------------------------------------------------------
    // test_sequence_buffer

    private struct TestSequenceData
    {
        public ushort Sequence;
    }

    private const int TestSequenceBufferSize = 256;

    private static void TestSequenceBuffer()
    {
        SequenceBuffer<TestSequenceData> sequenceBuffer = new SequenceBuffer<TestSequenceData>(TestSequenceBufferSize);

        Check(sequenceBuffer.Sequence == 0, "initial sequence must be 0");
        Check(sequenceBuffer.NumEntries == TestSequenceBufferSize, "num entries");

        for (int i = 0; i < TestSequenceBufferSize; ++i)
        {
            Check(sequenceBuffer.Find((ushort)i) == -1, $"find({i}) on empty buffer");
        }

        for (int i = 0; i <= TestSequenceBufferSize * 4; ++i)
        {
            int index = sequenceBuffer.Insert((ushort)i);
            Check(index >= 0, $"insert({i}) failed");
            sequenceBuffer.EntryAt(index).Sequence = (ushort)i;
            Check(sequenceBuffer.Sequence == (ushort)(i + 1), $"sequence after insert({i})");
        }

        for (int i = 0; i <= TestSequenceBufferSize; ++i)
        {
            Check(sequenceBuffer.Insert((ushort)i) == -1, $"stale insert({i}) must fail");
        }

        int findIndex = TestSequenceBufferSize * 4;
        for (int i = 0; i < TestSequenceBufferSize; ++i)
        {
            int index = sequenceBuffer.Find((ushort)findIndex);
            Check(index >= 0, $"find({findIndex})");
            Check(sequenceBuffer.EntryAt(index).Sequence == (ushort)findIndex, $"entry data at {findIndex}");
            findIndex--;
        }

        sequenceBuffer.Reset();

        Check(sequenceBuffer.Sequence == 0, "sequence after reset");
        Check(sequenceBuffer.NumEntries == TestSequenceBufferSize, "num entries after reset");

        for (int i = 0; i < TestSequenceBufferSize; ++i)
        {
            Check(sequenceBuffer.Find((ushort)i) == -1, $"find({i}) after reset");
        }
    }

    // ------------------------------------------------------------
    // test_generate_ack_bits

    private static void TestGenerateAckBits()
    {
        SequenceBuffer<TestSequenceData> sequenceBuffer = new SequenceBuffer<TestSequenceData>(TestSequenceBufferSize);

        sequenceBuffer.GenerateAckBits(out ushort ack, out uint ackBits);
        Check(ack == 0xFFFF, "ack on empty buffer");
        Check(ackBits == 0, "ack bits on empty buffer");

        for (int i = 0; i <= TestSequenceBufferSize; ++i)
        {
            sequenceBuffer.Insert((ushort)i);
        }

        sequenceBuffer.GenerateAckBits(out ack, out ackBits);
        Check(ack == TestSequenceBufferSize, "ack after inserts");
        Check(ackBits == 0xFFFFFFFF, "ack bits after inserts");

        sequenceBuffer.Reset();

        ushort[] inputAcks = { 1, 5, 9, 11 };
        for (int i = 0; i < inputAcks.Length; ++i)
        {
            sequenceBuffer.Insert(inputAcks[i]);
        }

        sequenceBuffer.GenerateAckBits(out ack, out ackBits);

        Check(ack == 11, "sparse ack");
        Check(ackBits == (1u | (1u << (11 - 9)) | (1u << (11 - 5)) | (1u << (11 - 1))), "sparse ack bits");
    }

    // ------------------------------------------------------------
    // test_packet_header

    private static void TestPacketHeader()
    {
        Span<byte> packetData = stackalloc byte[Wire.MaxPacketHeaderBytes];

        // worst case, sequence and ack are far apart, no packets acked.

        ushort writeSequence = 10000;
        ushort writeAck = 100;
        uint writeAckBits = 0;

        int bytesWritten = Wire.WritePacketHeader(packetData, writeSequence, writeAck, writeAckBits);

        Check(bytesWritten == Wire.MaxPacketHeaderBytes, "worst case must be the max header size");

        int bytesRead = Wire.ReadPacketHeader("test_packet_header", packetData.Slice(0, bytesWritten), out ushort readSequence, out ushort readAck, out uint readAckBits);

        Check(bytesRead == bytesWritten, "read bytes == written bytes (worst case)");
        Check(readSequence == writeSequence, "sequence (worst case)");
        Check(readAck == writeAck, "ack (worst case)");
        Check(readAckBits == writeAckBits, "ack bits (worst case)");

        // rare case. sequence and ack are far apart, significant # of acks are missing

        writeSequence = 10000;
        writeAck = 100;
        writeAckBits = 0xFEFEFFFE;

        bytesWritten = Wire.WritePacketHeader(packetData, writeSequence, writeAck, writeAckBits);

        Check(bytesWritten == 1 + 2 + 2 + 3, "rare case size");

        bytesRead = Wire.ReadPacketHeader("test_packet_header", packetData.Slice(0, bytesWritten), out readSequence, out readAck, out readAckBits);

        Check(bytesRead == bytesWritten, "read bytes == written bytes (rare case)");
        Check(readSequence == writeSequence, "sequence (rare case)");
        Check(readAck == writeAck, "ack (rare case)");
        Check(readAckBits == writeAckBits, "ack bits (rare case)");

        // common case under packet loss. sequence and ack are close together, some acks are missing

        writeSequence = 200;
        writeAck = 100;
        writeAckBits = 0xFFFEFFFF;

        bytesWritten = Wire.WritePacketHeader(packetData, writeSequence, writeAck, writeAckBits);

        Check(bytesWritten == 1 + 2 + 1 + 1, "common case size");

        bytesRead = Wire.ReadPacketHeader("test_packet_header", packetData.Slice(0, bytesWritten), out readSequence, out readAck, out readAckBits);

        Check(bytesRead == bytesWritten, "read bytes == written bytes (common case)");
        Check(readSequence == writeSequence, "sequence (common case)");
        Check(readAck == writeAck, "ack (common case)");
        Check(readAckBits == writeAckBits, "ack bits (common case)");

        // ideal case. no packet loss.

        writeSequence = 200;
        writeAck = 100;
        writeAckBits = 0xFFFFFFFF;

        bytesWritten = Wire.WritePacketHeader(packetData, writeSequence, writeAck, writeAckBits);

        Check(bytesWritten == 1 + 2 + 1, "ideal case size");

        bytesRead = Wire.ReadPacketHeader("test_packet_header", packetData.Slice(0, bytesWritten), out readSequence, out readAck, out readAckBits);

        Check(bytesRead == bytesWritten, "read bytes == written bytes (ideal case)");
        Check(readSequence == writeSequence, "sequence (ideal case)");
        Check(readAck == writeAck, "ack (ideal case)");
        Check(readAckBits == writeAckBits, "ack bits (ideal case)");
    }

    // ------------------------------------------------------------
    // test_acks

    private const int TestAcksNumIterations = 256;

    private static void TestAcks()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        const double deltaTime = 0.01;

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < TestAcksNumIterations; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
            context.Receiver.SendPacket(dummyPacket);

            context.Sender.Update(time);
            context.Receiver.Update(time);

            time += deltaTime;
        }

        bool[] senderAckedPacket = new bool[TestAcksNumIterations];
        ReadOnlySpan<ushort> senderAcks = context.Sender.GetAcks();
        for (int i = 0; i < senderAcks.Length; ++i)
        {
            if (senderAcks[i] < TestAcksNumIterations)
            {
                senderAckedPacket[senderAcks[i]] = true;
            }
        }
        for (int i = 0; i < TestAcksNumIterations / 2; ++i)
        {
            Check(senderAckedPacket[i], $"sender packet {i} must be acked");
        }

        bool[] receiverAckedPacket = new bool[TestAcksNumIterations];
        ReadOnlySpan<ushort> receiverAcks = context.Receiver.GetAcks();
        for (int i = 0; i < receiverAcks.Length; ++i)
        {
            if (receiverAcks[i] < TestAcksNumIterations)
            {
                receiverAckedPacket[receiverAcks[i]] = true;
            }
        }
        for (int i = 0; i < TestAcksNumIterations / 2; ++i)
        {
            Check(receiverAckedPacket[i], $"receiver packet {i} must be acked");
        }
    }

    // ------------------------------------------------------------
    // test_acks_packet_loss

    private static void TestAcksPacketLoss()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        const double deltaTime = 0.1;

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < TestAcksNumIterations; ++i)
        {
            context.Drop = (i % 2) != 0;

            context.Sender.SendPacket(dummyPacket);
            context.Receiver.SendPacket(dummyPacket);

            context.Sender.Update(time);
            context.Receiver.Update(time);

            time += deltaTime;
        }

        bool[] senderAckedPacket = new bool[TestAcksNumIterations];
        ReadOnlySpan<ushort> senderAcks = context.Sender.GetAcks();
        for (int i = 0; i < senderAcks.Length; ++i)
        {
            if (senderAcks[i] < TestAcksNumIterations)
            {
                senderAckedPacket[senderAcks[i]] = true;
            }
        }
        for (int i = 0; i < TestAcksNumIterations / 2; ++i)
        {
            Check(senderAckedPacket[i] == (((i + 1) % 2) != 0), $"sender packet {i} ack state");
        }

        bool[] receiverAckedPacket = new bool[TestAcksNumIterations];
        ReadOnlySpan<ushort> receiverAcks = context.Receiver.GetAcks();
        for (int i = 0; i < receiverAcks.Length; ++i)
        {
            if (receiverAcks[i] < TestAcksNumIterations)
            {
                receiverAckedPacket[receiverAcks[i]] = true;
            }
        }
        for (int i = 0; i < TestAcksNumIterations / 2; ++i)
        {
            Check(receiverAckedPacket[i] == (((i + 1) % 2) != 0), $"receiver packet {i} ack state");
        }
    }

    // ------------------------------------------------------------
    // test_duplicate_packets

    private const int TestDuplicatePacketsNumIterations = 16;

    private static void TestDuplicatePackets()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        int numProcessed = 0;

        // deliver each packet to the receiver twice, simulating duplication on the network
        TransmitPacketCallback duplicatingTransmit = (id, sequence, packetData) =>
        {
            if (id == 0)
            {
                context.Receiver!.ReceivePacket(packetData);
                context.Receiver!.ReceivePacket(packetData);
            }
        };

        EndpointConfig senderConfig = new EndpointConfig
        {
            Name = "sender",
            Id = 0,
            TransmitPacket = duplicatingTransmit,
            ProcessPacket = s_acceptAll,
        };

        EndpointConfig receiverConfig = new EndpointConfig
        {
            Name = "receiver",
            Id = 1,
            TransmitPacket = duplicatingTransmit,
            ProcessPacket = (id, sequence, packetData) => { numProcessed++; return true; },
        };

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < TestDuplicatePacketsNumIterations; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
        }

        Check(numProcessed == TestDuplicatePacketsNumIterations, $"processed {numProcessed}, expected {TestDuplicatePacketsNumIterations}");

        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsReceived) == 2 * TestDuplicatePacketsNumIterations, "received counter");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsDuplicate) == TestDuplicatePacketsNumIterations, "duplicate counter");

        // duplicate fragments arriving after their packet was delivered must not restart reassembly

        ushort fragmentedSequence = context.Sender.NextPacketSequence;

        byte[] largePacket = new byte[2048];
        context.Sender.SendPacket(largePacket);

        Check(numProcessed == TestDuplicatePacketsNumIterations + 1, "large packet must be processed exactly once");
        Check(!context.Receiver.FragmentReassemblyExists(fragmentedSequence), "no zombie reassembly after duplicate fragments");
    }

    // ------------------------------------------------------------
    // test_stale_packets

    private const int TestStalePacketsNumIterations = 300;

    private static void TestStalePackets()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        byte[] firstPacket = new byte[64];
        int firstPacketBytes = 0;
        int numProcessed = 0;

        TransmitPacketCallback transmit = (id, sequence, packetData) =>
        {
            if (id == 0)
            {
                if (sequence == 0 && firstPacketBytes == 0)
                {
                    packetData.CopyTo(firstPacket);
                    firstPacketBytes = packetData.Length;
                }

                context.Receiver!.ReceivePacket(packetData);
            }
        };

        EndpointConfig senderConfig = new EndpointConfig
        {
            Name = "sender",
            Id = 0,
            TransmitPacket = transmit,
            ProcessPacket = s_acceptAll,
        };

        EndpointConfig receiverConfig = new EndpointConfig
        {
            Name = "receiver",
            Id = 1,
            TransmitPacket = transmit,
            ProcessPacket = (id, sequence, packetData) => { numProcessed++; return true; },
        };

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        // send enough packets that sequence 0 falls out of the receive window (256 entries)

        byte[] dummyPacket = new byte[8];
        for (int i = 0; i < TestStalePacketsNumIterations; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
        }

        Check(numProcessed == TestStalePacketsNumIterations, "all packets processed");
        Check(firstPacketBytes > 0, "first packet captured");

        // replaying the first packet must be rejected as stale, not processed

        context.Receiver.ReceivePacket(firstPacket.AsSpan(0, firstPacketBytes));

        Check(numProcessed == TestStalePacketsNumIterations, "stale packet must not be processed");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsStale) == 1, "stale counter");
    }

    // ------------------------------------------------------------
    // test_ack_buffer_overflow

    private const int TestAckBufferOverflowNumPackets = 32;
    private const int TestAckBufferOverflowBufferSize = 16;

    private static void TestAckBufferOverflow()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        // undersized ack buffer on the sender, so a single received packet acking 32 sent packets overflows it

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.AckBufferSize = TestAckBufferOverflowBufferSize;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < TestAckBufferOverflowNumPackets; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
        }

        // one packet back from the receiver acks all 32, but only 16 fit in the ack buffer. the rest are dropped

        context.Receiver.SendPacket(dummyPacket);

        Check(context.Sender.GetAcks().Length == TestAckBufferOverflowBufferSize, "ack buffer must be exactly full");
        Check(context.Sender.GetCounter(EndpointCounter.NumPacketsAcked) == TestAckBufferOverflowBufferSize, "acked counter after overflow");

        // once the caller clears acks, the dropped acks are reported on the next packet that covers them

        context.Sender.ClearAcks();

        context.Receiver.SendPacket(dummyPacket);

        Check(context.Sender.GetAcks().Length == TestAckBufferOverflowNumPackets - TestAckBufferOverflowBufferSize, "remaining acks reported after clear");
        Check(context.Sender.GetCounter(EndpointCounter.NumPacketsAcked) == TestAckBufferOverflowNumPackets, "acked counter after recovery");
    }

    // ------------------------------------------------------------
    // test_packets

    private const int TestMaxPacketBytes = 4 * 1024;

    private static void GeneratePacketDataWithSize(ushort sequence, byte[] packetData, int packetBytes)
    {
        packetData[0] = (byte)(sequence & 0xFF);
        packetData[1] = (byte)((sequence >> 8) & 0xFF);
        for (int i = 2; i < packetBytes; ++i)
        {
            packetData[i] = (byte)((i + sequence) % 256);
        }
    }

    private static int GeneratePacketData(ushort sequence, byte[] packetData)
    {
        int packetBytes = ((sequence * 1023) % (TestMaxPacketBytes - 2)) + 2;
        GeneratePacketDataWithSize(sequence, packetData, packetBytes);
        return packetBytes;
    }

    private static void ValidatePacketData(ReadOnlySpan<byte> packetData)
    {
        int packetBytes = packetData.Length;
        Check(packetBytes >= 2, "validate: at least two bytes");
        Check(packetBytes <= TestMaxPacketBytes, "validate: within max");
        ushort sequence = (ushort)(packetData[0] | (packetData[1] << 8));
        Check(packetBytes == ((sequence * 1023) % (TestMaxPacketBytes - 2)) + 2, $"validate: size for sequence {sequence}");
        for (int i = 2; i < packetBytes; ++i)
        {
            Check(packetData[i] == (byte)((i + sequence) % 256), $"validate: byte {i} of sequence {sequence}");
        }
    }

    private static void TestPackets()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        ProcessPacketCallback validateProcess = (id, sequence, packetData) =>
        {
            ValidatePacketData(packetData);
            return true;
        };

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.FragmentAbove = 500;
        senderConfig.ProcessPacket = validateProcess;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.FragmentAbove = 500;
        receiverConfig.ProcessPacket = validateProcess;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        const double deltaTime = 0.1;

        byte[] packetData = new byte[TestMaxPacketBytes];

        for (int i = 0; i < 16; ++i)
        {
            {
                ushort sequence = context.Sender.NextPacketSequence;
                int packetBytes = GeneratePacketData(sequence, packetData);
                context.Sender.SendPacket(packetData.AsSpan(0, packetBytes));
            }

            {
                ushort sequence = context.Sender.NextPacketSequence;
                int packetBytes = GeneratePacketData(sequence, packetData);
                context.Sender.SendPacket(packetData.AsSpan(0, packetBytes));
            }

            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Sender.ClearAcks();
            context.Receiver.ClearAcks();

            time += deltaTime;
        }
    }

    // ------------------------------------------------------------
    // test_large_packets

    private static void TestLargePackets()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        ProcessPacketCallback validateLarge = (id, sequence, packetData) =>
        {
            int packetBytes = packetData.Length;
            Check(packetBytes >= 2, "large: at least two bytes");
            Check(packetBytes <= TestMaxPacketBytes, "large: within max");
            ushort dataBytes = (ushort)(packetData[0] | (packetData[1] << 8));
            Check(packetBytes == dataBytes + 2, "large: size prefix");
            for (int i = 2; i < dataBytes; ++i)
            {
                Check(packetData[i] == (byte)(i % 256), $"large: byte {i}");
            }
            return true;
        };

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.MaxPacketSize = TestMaxPacketBytes;
        senderConfig.FragmentAbove = TestMaxPacketBytes;
        senderConfig.ProcessPacket = validateLarge;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.MaxPacketSize = TestMaxPacketBytes;
        receiverConfig.FragmentAbove = TestMaxPacketBytes;
        receiverConfig.ProcessPacket = validateLarge;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        {
            byte[] packetData = new byte[TestMaxPacketBytes];
            int dataBytes = TestMaxPacketBytes - 2;
            packetData[0] = (byte)(dataBytes & 0xFF);
            packetData[1] = (byte)((dataBytes >> 8) & 0xFF);
            for (int i = 2; i < dataBytes; ++i)
            {
                packetData[i] = (byte)(i % 256);
            }
            context.Sender.SendPacket(packetData);
        }

        context.Sender.Update(time);
        context.Receiver.Update(time);

        context.Sender.ClearAcks();
        context.Receiver.ClearAcks();

        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsTooLargeToReceive) == 0, "too large counter must be 0");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsReceived) == 1, "received counter must be 1");
    }

    // ------------------------------------------------------------
    // test_sequence_buffer_rollover

    private static void TestSequenceBufferRollover()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.FragmentAbove = 500;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.FragmentAbove = 500;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        int numPacketsSent = 0;
        byte[] smallPacket = new byte[16];
        for (int i = 0; i <= 32767; ++i)
        {
            context.Sender.SendPacket(smallPacket);
            ++numPacketsSent;
        }

        byte[] bigPacket = new byte[TestMaxPacketBytes];
        context.Sender.SendPacket(bigPacket);
        ++numPacketsSent;

        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsReceived) == (ushort)numPacketsSent, "received counter across rollover");
        Check(context.Receiver.GetCounter(EndpointCounter.NumFragmentsInvalid) == 0, "no invalid fragments across rollover");
    }

    // ------------------------------------------------------------
    // test_fragment_cleanup

    private static void TestFragmentCleanup()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.FragmentReassemblyBufferSize = 4;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        const double deltaTime = 0.1;

        int[] packetSizes =
        {
            1024 + 512,   // fragment_size + fragment_size/2 with the default config
            10,
            10,
            10,
            10,
        };

        byte[] packetData = new byte[TestMaxPacketBytes];

        for (int i = 0; i < packetSizes.Length; ++i)
        {
            // Only allow one packet per transmit, so that our fragmented packets
            // are only partially delivered.
            context.AllowPackets = 1;
            {
                ushort sequence = context.Sender.NextPacketSequence;
                GeneratePacketDataWithSize(sequence, packetData, packetSizes[i]);
                context.Sender.SendPacket(packetData.AsSpan(0, packetSizes[i]));
            }

            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Sender.ClearAcks();
            context.Receiver.ClearAcks();

            time += deltaTime;
        }

        // more packets were sent than the 4-entry reassembly window, so the
        // buffer wrapped and the in-flight reassembly was EVICTED: its pooled
        // buffer must already be returned (the analog of the C suite's tracking
        // allocator proving eviction frees), and reset must not double-return
        Check(context.Receiver.OutstandingReassemblyBuffers == 0, "evicted reassembly buffer returned");
        context.Receiver.Reset();
        Check(context.Receiver.OutstandingReassemblyBuffers == 0, "no reassembly buffers outstanding after reset");
    }

    // ------------------------------------------------------------
    // test_rtt

    private static void TestRtt()
    {
        double time = 100.0;
        const double deltaTime = 0.01;

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < 1000; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
            context.Receiver.SendPacket(dummyPacket);

            context.Sender.Update(time);
            context.Receiver.Update(time);

            time += deltaTime;
        }

        float rtt = context.Sender.Rtt;
        float rttMin = context.Sender.RttMin;
        float rttMax = context.Sender.RttMax;
        float rttAvg = context.Sender.RttAvg;

        Check(!float.IsNaN(rtt) && rtt >= 0, "rtt is finite and non-negative");
        Check(rttMin >= 0 && rttMin <= rttAvg && rttAvg <= rttMax, "rtt min <= avg <= max");
        Check(rttMax < 1000.0f, "rtt is in milliseconds");
    }

    // ------------------------------------------------------------
    // test_endpoint_reset

    private static void TestEndpointReset()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.FragmentAbove = 500;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.FragmentAbove = 500;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        // exchange packets both ways so acks and counters accumulate

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < 8; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
            context.Receiver.SendPacket(dummyPacket);

            context.Sender.Update(time);
            context.Receiver.Update(time);

            time += 0.01;
        }

        Check(context.Sender.GetAcks().Length > 0, "acks accumulated before reset");
        Check(context.Sender.GetCounter(EndpointCounter.NumPacketsSent) > 0, "sent counter before reset");

        // leave a fragment reassembly in progress on the receiver by delivering only the first fragment of a large packet

        context.AllowPackets = 1;
        {
            byte[] largePacket = new byte[1500];
            context.Sender.SendPacket(largePacket);
        }
        context.AllowPackets = -1;

        Check(context.Receiver.OutstandingReassemblyBuffers == 1, "reassembly in flight before reset");

        context.Sender.Reset();
        context.Receiver.Reset();

        Check(context.Sender.NextPacketSequence == 0, "sender sequence after reset");
        Check(context.Receiver.NextPacketSequence == 0, "receiver sequence after reset");

        Check(context.Sender.GetAcks().Length == 0, "acks cleared by reset");

        for (int i = 0; i < Endpoint.NumCounters; ++i)
        {
            Check(context.Sender.Counters[i] == 0, $"sender counter {i} after reset");
            Check(context.Receiver.Counters[i] == 0, $"receiver counter {i} after reset");
        }

        // reset must have returned the in-progress reassembly buffer

        Check(context.Receiver.OutstandingReassemblyBuffers == 0, "reassembly buffers returned by reset");

        // the endpoints must work normally after reset

        for (int i = 0; i < 8; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
            context.Receiver.SendPacket(dummyPacket);

            context.Sender.Update(time);
            context.Receiver.Update(time);

            time += 0.01;
        }

        Check(context.Sender.GetAcks().Length > 0, "acks accumulate after reset");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsReceived) > 0, "packets received after reset");
    }

    // ------------------------------------------------------------
    // golden wire pins, generated from the real C library (mas-bandwidth/reliable
    // v1.4.0). regenerate with: compat/c/compat.c built against the C clone.

    private static readonly (ushort Sequence, ushort Ack, uint AckBits, string Hex)[] s_goldenHeaders =
    {
        (10000, 100, 0x00000000u, "1e1027640000000000"),
        (10000, 100, 0xFEFEFFFEu, "1a10276400fefefe"),
        (200, 100, 0xFFFEFFFFu, "28c80064fe"),
        (200, 100, 0xFFFFFFFFu, "20c80064"),
        (0, 65535, 0x00000000u, "3e00000100000000"),
        (0, 65535, 0xFFFFFFFFu, "20000001"),
        (32768, 0, 0xDEADBEEFu, "1e00800000efbeadde"),
        (65535, 65534, 0x00FF00FFu, "34ffff010000"),
    };

    private static void TestGoldenPacketHeaders()
    {
        Span<byte> buffer = stackalloc byte[Wire.MaxPacketHeaderBytes];

        foreach ((ushort sequence, ushort ack, uint ackBits, string hex) in s_goldenHeaders)
        {
            byte[] golden = FromHex(hex);

            int written = Wire.WritePacketHeader(buffer, sequence, ack, ackBits);
            Check(written == golden.Length, $"golden header ({sequence},{ack},{ackBits:x8}): length {written}, expected {golden.Length}");
            Check(buffer.Slice(0, written).SequenceEqual(golden), $"golden header ({sequence},{ack},{ackBits:x8}): bytes");

            int read = Wire.ReadPacketHeader("golden", golden, out ushort readSequence, out ushort readAck, out uint readAckBits);
            Check(read == golden.Length, $"golden header ({sequence},{ack},{ackBits:x8}): read consumed");
            Check(readSequence == sequence && readAck == ack && readAckBits == ackBits, $"golden header ({sequence},{ack},{ackBits:x8}): read fields");
        }
    }

    // fragment layout pins: an endpoint with MaxPacketSize=8000, FragmentAbove=500,
    // FragmentSize=1000, MaxFragments=8 sends patterned payloads of these sizes in
    // this order; the (length, fnv1a64) of every transmitted fragment is pinned
    // from the C library's output.
    private static readonly (int PayloadBytes, (int Length, ulong Fnv)[] Fragments)[] s_goldenFragments =
    {
        (501, new[] { (514, 0xcf4857c04faeb03aul) }),
        (999, new[] { (1012, 0x44925ef27a7807bcul) }),
        (1000, new[] { (1013, 0x973268bc11f5146aul) }),
        (1001, new[] { (1013, 0xeb460e44703e792ful), (6, 0x18b5c646aeb5d2a6ul) }),
        (1500, new[] { (1013, 0xc71dc96316035a51ul), (505, 0x25a09391ca91b556ul) }),
        (2200, new[] { (1013, 0x03232fd8ad5f233aul), (1005, 0x60360d2ed67cec76ul), (205, 0xbfe0fc5616171969ul) }),
        (4000, new[] { (1013, 0xc502958da11d419bul), (1005, 0x03bf6f273733264eul), (1005, 0x1418e60f1ee95199ul), (1005, 0xe54fbc7955d93d28ul) }),
        (7999, new[] { (1013, 0x087fe3a389f7ae79ul), (1005, 0xe4d981ebbce3a4fbul), (1005, 0xd153bd954e7a268cul), (1005, 0x2d4036dadcdd01b5ul), (1005, 0x339aad2182daaf0eul), (1005, 0xfdb7d71a029d9c87ul), (1005, 0xa53444b974f49ad8ul), (1004, 0xe0dd4a1397cd054dul) }),
        (8000, new[] { (1013, 0x56b553be3c00da2ful), (1005, 0x71c7bcea89be1f58ul), (1005, 0xe17d0f688c289d9ful), (1005, 0x4043ff1618e9c68eul), (1005, 0xee56e4564335207dul), (1005, 0x7737fffa35c0c68cul), (1005, 0x157a6c534a931733ul), (1005, 0x4ec1802df6e295f2ul) }),
    };

    // the first golden fragment set in full: payload 501 from a fresh endpoint,
    // one fragment: [frag header 5][packet header 8][payload 501], byte for byte
    private const string GoldenFragment0Hex =
        "01000000003e00000100000000000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122" +
        "232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152" +
        "535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182" +
        "838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2" +
        "b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2" +
        "e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112" +
        "131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142" +
        "434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172" +
        "737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2" +
        "a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2" +
        "d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4";

    private static void TestGoldenFragments()
    {
        int setIndex = 0;
        int fragmentIndex = 0;
        bool firstFragmentChecked = false;

        EndpointConfig config = new EndpointConfig
        {
            Name = "golden",
            MaxPacketSize = 8000,
            FragmentAbove = 500,
            FragmentSize = 1000,
            MaxFragments = 8,
            ProcessPacket = s_acceptAll,
            TransmitPacket = null!,
        };

        config.TransmitPacket = (id, sequence, packetData) =>
        {
            (int payloadBytes, (int Length, ulong Fnv)[] fragments) = s_goldenFragments[setIndex];
            Check(fragmentIndex < fragments.Length, $"golden fragments: too many fragments for payload {payloadBytes}");
            (int length, ulong fnv) = fragments[fragmentIndex];
            Check(packetData.Length == length, $"golden fragments: payload {payloadBytes} fragment {fragmentIndex} length {packetData.Length}, expected {length}");
            Check(Fnv1a64(packetData) == fnv, $"golden fragments: payload {payloadBytes} fragment {fragmentIndex} bytes differ from the C library");

            if (!firstFragmentChecked)
            {
                byte[] golden = FromHex(GoldenFragment0Hex);
                Check(packetData.SequenceEqual(golden), "golden fragments: first fragment full byte pin");
                firstFragmentChecked = true;
            }

            fragmentIndex++;
        };

        Endpoint endpoint = new Endpoint(config, 100.0);

        byte[] payload = new byte[8192];
        for (setIndex = 0; setIndex < s_goldenFragments.Length; setIndex++)
        {
            (int payloadBytes, (int Length, ulong Fnv)[] fragments) = s_goldenFragments[setIndex];
            ushort sequence = endpoint.NextPacketSequence;
            payload[0] = (byte)(sequence & 0xFF);
            payload[1] = (byte)((sequence >> 8) & 0xFF);
            for (int i = 2; i < payloadBytes; i++)
            {
                payload[i] = (byte)((i + sequence) % 256);
            }
            fragmentIndex = 0;
            endpoint.SendPacket(payload.AsSpan(0, payloadBytes));
            Check(fragmentIndex == fragments.Length, $"golden fragments: payload {payloadBytes} produced {fragmentIndex} fragments, expected {fragments.Length}");
        }

        Check(firstFragmentChecked, "golden fragments: first fragment pin exercised");
    }
}
