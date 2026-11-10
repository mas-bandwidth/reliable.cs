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
        RunTest("test_sequence_buffer_wrap_sizes", TestSequenceBufferWrapSizes);
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
        RunTest("test_sequence_wrap", TestSequenceWrap);
        RunTest("test_sequence_wrap_arithmetic", TestSequenceWrapArithmetic);
        RunTest("test_fragment_cleanup", TestFragmentCleanup);
        RunTest("test_unfinished_reassembly_respects_byte_budget", TestUnfinishedReassemblyRespectsByteBudget);
        RunTest("test_rtt", TestRtt);
        RunTest("test_packet_loss_estimator", TestPacketLossEstimator);
        RunTest("test_jitter_estimator", TestJitterEstimator);
        RunTest("test_bandwidth_estimators", TestBandwidthEstimators);
        RunTest("test_endpoint_reset", TestEndpointReset);
        RunTest("test_endpoint_create_invalid_config", TestEndpointCreateInvalidConfig);
        RunTest("test_fragment_counts", TestFragmentCounts);
        RunTest("test_truncated_packets", TestTruncatedPackets);
        RunTest("test_endpoint_reset_clears_stats", TestEndpointResetClearsStats);
        RunTest("test_rtt_min_large", TestRttMinLarge);
        RunTest("test_rtt_clamped_when_time_steps_back", TestRttClampedWhenTimeStepsBack);

        // golden wire pins, generated from the real C library (v1.4.0; the
        // interop vectors gate shows the pinned v1.4.5 emits the same bytes)
        RunTest("test_golden_packet_headers", TestGoldenPacketHeaders);
        RunTest("test_golden_fragments", TestGoldenFragments);

        // C#-specific: hostile input, API misuse, allocation discipline
        RunTest("test_hostile_truncated_headers", TestHostileTruncatedHeaders);
        RunTest("test_hostile_fragments", TestHostileFragments);
        RunTest("test_fragment_advances_received_window", TestFragmentAdvancesReceivedWindow);
        RunTest("test_two_fragment_packet_reassembles", TestTwoFragmentPacketReassembles);
        RunTest("test_hostile_parser_fuzz", TestHostileParserFuzz);
        RunTest("test_process_reject_redelivery", TestProcessRejectRedelivery);
        RunTest("test_receive_empty_packet_is_counted_invalid", TestReceiveEmptyPacketIsCountedInvalid);
        RunTest("test_config_validation", TestConfigValidation);
        RunTest("test_config_refuses_bad_sequence_buffer_sizes", TestConfigRefusesBadSequenceBufferSizes);
        RunTest("test_config_refuses_the_c_bounds", TestConfigRefusesTheCBounds);
        RunTest("test_reassembly_buffer_is_zeroed", TestReassemblyBufferIsZeroed);
        RunTest("test_zero_allocation", TestZeroAllocation);
        RunTest("test_fuzz_script", TestFuzzScript);

        // C#-specific: strict IEEE float evaluation, the canary for the C
        // build's -ffp-contract=off (the same rule the interop gate pins)
        RunTest("test_float_multiply_add_rounds_twice", FloatMultiplyAddRoundsTwice);

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

    private sealed class SequenceBufferReferenceModel
    {
        private readonly ushort?[] _entries;

        internal ushort Sequence;

        internal SequenceBufferReferenceModel(int numEntries)
        {
            _entries = new ushort?[numEntries];
        }

        internal bool TestInsert(ushort sequence)
        {
            return !Seq.LessThan(sequence, (ushort)(Sequence - (ushort)_entries.Length));
        }

        internal int Insert(ushort sequence)
        {
            if (Seq.LessThan(sequence, (ushort)(Sequence - (ushort)_entries.Length)))
            {
                return -1;
            }

            if (Seq.GreaterThan((ushort)(sequence + 1), Sequence))
            {
                RemoveEntries(Sequence, sequence);
                Sequence = (ushort)(sequence + 1);
            }

            int index = sequence % _entries.Length;
            _entries[index] = sequence;
            return index;
        }

        internal void Advance(ushort sequence)
        {
            if (Seq.GreaterThan((ushort)(sequence + 1), Sequence))
            {
                RemoveEntries(Sequence, sequence);
                Sequence = (ushort)(sequence + 1);
            }
        }

        internal void Remove(ushort sequence)
        {
            _entries[sequence % _entries.Length] = null;
        }

        internal int Find(ushort sequence)
        {
            int index = sequence % _entries.Length;
            return _entries[index] == sequence ? index : -1;
        }

        private void RemoveEntries(ushort startSequence, ushort finishSequence)
        {
            int start = startSequence;
            int finish = finishSequence;

            if (finish < start)
            {
                finish += 65536;
            }

            if (finish - start < _entries.Length)
            {
                for (int sequence = start; sequence <= finish; ++sequence)
                {
                    _entries[(ushort)sequence % _entries.Length] = null;
                }
            }
            else
            {
                Array.Clear(_entries, 0, _entries.Length);
            }
        }
    }

    private static void TestSequenceBufferWrapSizes()
    {
        int[] capacities = { 4, 3 };
        ushort[] sequences = { 65534, 65535, 0, 1 };
        ushort[] probes = { 65533, 65534, 65535, 0, 1, 2 };

        foreach (int capacity in capacities)
        {
            SequenceBuffer<TestSequenceData> sequenceBuffer = new SequenceBuffer<TestSequenceData>(capacity);
            SequenceBufferReferenceModel model = new SequenceBufferReferenceModel(capacity);

            sequenceBuffer.Advance(65533);
            model.Advance(65533);
            Check(sequenceBuffer.Sequence == model.Sequence, $"capacity {capacity}: sequence after advance");

            foreach (ushort sequence in sequences)
            {
                Check(sequenceBuffer.TestInsert(sequence) == model.TestInsert(sequence),
                    $"capacity {capacity}: test insert {sequence}");

                int index = sequenceBuffer.Insert(sequence);
                int expectedIndex = model.Insert(sequence);

                Check(index == expectedIndex, $"capacity {capacity}: insert {sequence} returned {index}, expected {expectedIndex}");
                Check(sequenceBuffer.Sequence == model.Sequence,
                    $"capacity {capacity}: sequence after insert {sequence} is {sequenceBuffer.Sequence}, expected {model.Sequence}");

                if (index >= 0)
                {
                    sequenceBuffer.EntryAt(index).Sequence = sequence;
                }

                foreach (ushort probe in probes)
                {
                    Check(sequenceBuffer.Find(probe) == model.Find(probe),
                        $"capacity {capacity}: find {probe} after insert {sequence}");
                }
            }

            foreach (ushort sequence in sequences)
            {
                sequenceBuffer.RemoveWithCleanup(sequence, _ => { });
                model.Remove(sequence);

                foreach (ushort probe in probes)
                {
                    Check(sequenceBuffer.Find(probe) == model.Find(probe),
                        $"capacity {capacity}: find {probe} after remove {sequence}");
                }
            }
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

    // the last 32 packets may not be acked yet when the loop ends
    private const int TestAcksNumChecked = TestAcksNumIterations - 32;

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
        for (int i = 0; i < TestAcksNumChecked; ++i)
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
        for (int i = 0; i < TestAcksNumChecked; ++i)
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
        for (int i = 0; i < TestAcksNumChecked; ++i)
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
        for (int i = 0; i < TestAcksNumChecked; ++i)
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

    private const int TestPacketsNumIterations = 16;

    private static void TestPackets()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        int[] numProcessed = new int[2];

        ProcessPacketCallback validateProcess = (id, sequence, packetData) =>
        {
            ValidatePacketData(packetData);
            numProcessed[id]++;
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

        for (int i = 0; i < TestPacketsNumIterations; ++i)
        {
            {
                ushort sequence = context.Sender.NextPacketSequence;
                int packetBytes = GeneratePacketData(sequence, packetData);
                context.Sender.SendPacket(packetData.AsSpan(0, packetBytes));
            }

            {
                ushort sequence = context.Receiver.NextPacketSequence;
                int packetBytes = GeneratePacketData(sequence, packetData);
                context.Receiver.SendPacket(packetData.AsSpan(0, packetBytes));
            }

            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Sender.ClearAcks();
            context.Receiver.ClearAcks();

            time += deltaTime;
        }

        Check(numProcessed[0] == TestPacketsNumIterations, $"sender processed {numProcessed[0]}, expected {TestPacketsNumIterations}");
        Check(numProcessed[1] == TestPacketsNumIterations, $"receiver processed {numProcessed[1]}, expected {TestPacketsNumIterations}");
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

    private static void TestSequenceWrap()
    {
        const int numPackets = 65536 + 4;

        double time = 100.0;

        TestContext context = new TestContext();

        int numProcessed = 0;

        ProcessPacketCallback validate = (id, sequence, packetData) =>
        {
            Check(packetData.Length == 8, $"wrap: payload size at sequence {sequence}");
            Check(sequence == (ushort)numProcessed, $"wrap: delivered sequence {sequence}, expected {(ushort)numProcessed}");
            numProcessed++;
            return true;
        };

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.ProcessPacket = validate;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        byte[] packetData = new byte[8];

        for (int i = 0; i < numPackets; ++i)
        {
            Check(context.Sender.NextPacketSequence == (ushort)i,
                $"wrap: next sequence {context.Sender.NextPacketSequence}, expected {(ushort)i}");
            context.Sender.SendPacket(packetData);
        }

        Check(context.Sender.NextPacketSequence == unchecked((ushort)numPackets), "wrap: next sequence after the walk");
        Check(numProcessed == numPackets, $"wrap: processed {numProcessed}, expected {numPackets}");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsReceived) == (ulong)numPackets,
            "wrap: received counter");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsInvalid) == 0, "wrap: no invalid packets");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsStale) == 0, "wrap: no stale packets");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsDuplicate) == 0, "wrap: no duplicate packets");

        context.Receiver.SendPacket(packetData);

        bool sawAckBeforeWrap = false;
        bool sawAckAfterWrap = false;
        foreach (ushort ack in context.Sender.GetAcks())
        {
            if (ack == 65535)
            {
                sawAckBeforeWrap = true;
            }
            if (ack == 0)
            {
                sawAckAfterWrap = true;
            }
        }

        Check(sawAckBeforeWrap, "wrap: ack for sequence 65535");
        Check(sawAckAfterWrap, "wrap: ack for sequence 0");
        Check(context.Sender.GetCounter(EndpointCounter.NumPacketsAcked) > 0, "wrap: sender recorded acks");
    }

    // ------------------------------------------------------------
    // test_sequence_wrap_arithmetic: 16 bit sequence arithmetic is modular at
    // sequence 0 and across 65535 -> 0, whether or not the build checks overflow

    private static void TestSequenceWrapArithmetic()
    {
        // sequence buffer at sequence 0, then walked across the wrap
        SequenceBuffer<TestSequenceData> sequenceBuffer = new SequenceBuffer<TestSequenceData>(TestSequenceBufferSize);
        Check(sequenceBuffer.TestInsert(0), "test insert at sequence 0");
        sequenceBuffer.GenerateAckBits(out ushort ack, out uint ackBits);
        Check(ack == 0xFFFF && ackBits == 0, "ack bits at sequence 0");
        for (int i = 65500; i < 65536 + 40; ++i)
        {
            ushort sequence = unchecked((ushort)i);
            Check(sequenceBuffer.Insert(sequence) >= 0, "insert across wrap");
            sequenceBuffer.Advance(sequence);
            sequenceBuffer.InsertWithCleanup(sequence, _ => { });
            sequenceBuffer.AdvanceWithCleanup(sequence, _ => { });
        }
        sequenceBuffer.GenerateAckBits(out ack, out ackBits);
        Check(ack == 39 && ackBits == 0xFFFFFFFF, "ack bits across wrap");

        // packet header whose ack is behind the sequence across the wrap
        Span<byte> packetData = stackalloc byte[Wire.MaxPacketHeaderBytes];
        int bytesWritten = Wire.WritePacketHeader(packetData, 3, 65534, 0xFFFFFFFF);
        int bytesRead = Wire.ReadPacketHeader("test_sequence_wrap_arithmetic", packetData.Slice(0, bytesWritten), out ushort readSequence, out ushort readAck, out uint readAckBits);
        Check(bytesRead == bytesWritten && readSequence == 3 && readAck == 65534 && readAckBits == 0xFFFFFFFF, "packet header across wrap");

        // endpoints sending from sequence 0 through 65535 -> 0
        double time = 100.0;
        TestContext context = new TestContext();
        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);
        byte[] dummyPacket = new byte[8];
        for (int i = 0; i < 65536 + 64; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
            context.Receiver.SendPacket(dummyPacket);
            if ((i & 1023) == 0)
            {
                context.Sender.Update(time);
                context.Receiver.Update(time);
                time += 0.01;
            }
        }
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsReceived) == 65536 + 64, "every packet received across wrap");
        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsStale) == 0, "no stale packets across wrap");
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
    // test_unfinished_reassembly_respects_byte_budget

    private static void TestUnfinishedReassemblyRespectsByteBudget()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.FragmentReassemblyByteBudget = 64 * 1024;

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(receiverConfig, time);

        const int numFragments = 16;
        int slotBytes = Wire.MaxPacketHeaderBytes + numFragments * receiverConfig.FragmentSize + 8;
        int byteBudget = 64 * 1024;

        // 64 last fragments for sequences 0..63, each claiming 16 fragments, with
        // fragment 0 never arriving. every one is a first fragment for its packet
        // and would allocate a full slot.
        for (int sequence = 0; sequence < 64; ++sequence)
        {
            byte[] fragment = BuildFragment((ushort)sequence, numFragments - 1, numFragments, 1024, 0, 0);
            context.Receiver.ReceivePacket(fragment);
            Check(context.Receiver.OutstandingReassemblyBytes <= byteBudget + slotBytes,
                $"outstanding reassembly bytes {context.Receiver.OutstandingReassemblyBytes} exceed budget + slot after sequence {sequence}");
        }

        Check(context.Receiver.OutstandingReassemblyBytes >= slotBytes, "the endpoint allocated at least one slot's worth of bytes");

        context.Receiver.Reset();
        Check(context.Receiver.OutstandingReassemblyBytes == 0, "outstanding reassembly bytes return to zero after reset");
        Check(context.Receiver.OutstandingReassemblyBuffers == 0, "no reassembly buffers outstanding after reset");
    }

    // ------------------------------------------------------------
    // test_rtt

    private static void TestRtt()
    {
        double time = 100.0;
        const double roundTripTime = 0.05;
        const int numRoundTrips = 10;
        const float expectedRtt = 50.0f;

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < numRoundTrips; ++i)
        {
            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Sender.SendPacket(dummyPacket);

            time += roundTripTime;

            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Receiver.SendPacket(dummyPacket);
        }

        context.Sender.Update(time);

        float rtt = context.Sender.Rtt;
        float rttMin = context.Sender.RttMin;
        float rttMax = context.Sender.RttMax;
        float rttAvg = context.Sender.RttAvg;

        Check(Math.Abs(rtt - expectedRtt) < 0.01f, $"rtt is {rtt}, expected {expectedRtt}");
        Check(Math.Abs(rttMin - expectedRtt) < 0.01f, $"rtt min is {rttMin}, expected {expectedRtt}");
        Check(Math.Abs(rttMax - expectedRtt) < 0.01f, $"rtt max is {rttMax}, expected {expectedRtt}");
        Check(Math.Abs(rttAvg - expectedRtt) < 0.01f, $"rtt avg is {rttAvg}, expected {expectedRtt}");
        Check(Math.Abs(context.Sender.JitterAvgVsMinRtt) < 0.01f, "jitter average vs min rtt is zero");
        Check(Math.Abs(context.Sender.JitterMaxVsMinRtt) < 0.01f, "jitter max vs min rtt is zero");
        Check(Math.Abs(context.Sender.JitterStddevVsAvgRtt) < 0.01f, "jitter stddev vs avg rtt is zero");
    }

    // ------------------------------------------------------------
    // test_packet_loss_estimator

    private static void TestPacketLossEstimator()
    {
        double time = 100.0;
        const double deltaTime = 0.01;
        const int numPackets = 8;

        TestContext context = new TestContext();

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.SentPacketsBufferSize = numPackets;
        senderConfig.PacketLossSmoothingFactor = 1.0f;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < numPackets; ++i)
        {
            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Drop = (i % 4) == 1;
            context.Sender.SendPacket(dummyPacket);
            context.Drop = false;
            context.Receiver.SendPacket(dummyPacket);

            time += deltaTime;
        }

        context.Sender.Update(time);

        float packetLoss = context.Sender.PacketLoss;

        Check(Math.Abs(packetLoss - 25.0f) < 0.01f, $"packet loss is {packetLoss}, expected 25");
    }

    // ------------------------------------------------------------
    // test_jitter_estimator

    private static void TestJitterEstimator()
    {
        double time = 100.0;

        float[] roundTripTimesMs = { 10.0f, 20.0f, 10.0f, 20.0f };

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        foreach (float roundTripTimeMs in roundTripTimesMs)
        {
            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Sender.SendPacket(dummyPacket);

            time += roundTripTimeMs / 1000.0;

            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Receiver.SendPacket(dummyPacket);
        }

        context.Sender.Update(time);

        Check(Math.Abs(context.Sender.RttMin - 10.0f) < 0.01f, $"rtt min is {context.Sender.RttMin}, expected 10");
        Check(Math.Abs(context.Sender.RttMax - 20.0f) < 0.01f, $"rtt max is {context.Sender.RttMax}, expected 20");
        Check(Math.Abs(context.Sender.RttAvg - 15.0f) < 0.01f, $"rtt avg is {context.Sender.RttAvg}, expected 15");
        Check(Math.Abs(context.Sender.JitterAvgVsMinRtt - 5.0f) < 0.01f, $"jitter average vs min rtt is {context.Sender.JitterAvgVsMinRtt}, expected 5");
        Check(Math.Abs(context.Sender.JitterMaxVsMinRtt - 10.0f) < 0.01f, $"jitter max vs min rtt is {context.Sender.JitterMaxVsMinRtt}, expected 10");
        Check(Math.Abs(context.Sender.JitterStddevVsAvgRtt - 5.0f) < 0.01f, $"jitter stddev vs avg rtt is {context.Sender.JitterStddevVsAvgRtt}, expected 5");
    }

    // ------------------------------------------------------------
    // test_bandwidth_estimators

    private static void TestBandwidthEstimators()
    {
        double time = 100.0;
        const double deltaTime = 0.01;
        const int numPackets = 8;
        const int packetHeaderSize = 28;
        const int wireHeaderBytes = 8;
        const int payloadBytes = 100;
        const int windowSamples = numPackets / 2;
        const double windowSeconds = (windowSamples - 1) * deltaTime;

        TestContext context = new TestContext();

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.SentPacketsBufferSize = numPackets;
        senderConfig.BandwidthSmoothingFactor = 1.0f;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.ReceivedPacketsBufferSize = numPackets;
        receiverConfig.BandwidthSmoothingFactor = 1.0f;

        context.Sender = new Endpoint(senderConfig, time);
        context.Receiver = new Endpoint(receiverConfig, time);

        byte[] packet = new byte[payloadBytes];

        for (int i = 0; i < numPackets; ++i)
        {
            context.Sender.Update(time);
            context.Receiver.Update(time);

            context.Sender.SendPacket(packet);
            context.Receiver.SendPacket(packet);

            time += deltaTime;
        }

        context.Sender.Update(time);
        context.Receiver.Update(time);

        float sentExpected = (float)(windowSamples * (packetHeaderSize + payloadBytes) / windowSeconds * 8.0 / 1000.0);
        float receivedExpected = (float)(windowSamples * (packetHeaderSize + wireHeaderBytes + payloadBytes) / windowSeconds * 8.0 / 1000.0);
        float ackedExpected = sentExpected;

        Check(Math.Abs(context.Sender.SentBandwidthKbps - sentExpected) < 0.01f, $"sent bandwidth is {context.Sender.SentBandwidthKbps}, expected {sentExpected}");
        Check(Math.Abs(context.Receiver.ReceivedBandwidthKbps - receivedExpected) < 0.01f, $"received bandwidth is {context.Receiver.ReceivedBandwidthKbps}, expected {receivedExpected}");
        Check(Math.Abs(context.Sender.AckedBandwidthKbps - ackedExpected) < 0.01f, $"acked bandwidth is {context.Sender.AckedBandwidthKbps}, expected {ackedExpected}");
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
    // test_endpoint_create_invalid_config

    private static void TestEndpointCreateInvalidConfig()
    {
        static EndpointConfig Valid()
        {
            return new EndpointConfig
            {
                TransmitPacket = (id, sequence, packetData) => { },
                ProcessPacket = s_acceptAll,
            };
        }

        static void Refused(Action<EndpointConfig> mutate, string what)
        {
            EndpointConfig config = Valid();
            mutate(config);
            try
            {
                _ = new Endpoint(config, 0.0);
            }
            catch (ArgumentException)
            {
                return;
            }
            Check(false, $"{what} must be refused");
        }

        static void Accepted(Action<EndpointConfig> mutate, string what)
        {
            EndpointConfig config = Valid();
            mutate(config);
            try
            {
                _ = new Endpoint(config, 0.0);
            }
            catch (ArgumentException)
            {
                Check(false, $"{what} must be accepted");
            }
        }

        Accepted(c => { }, "default config");

        try
        {
            _ = new Endpoint(null!, 0.0);
            Check(false, "null config must be refused");
        }
        catch (ArgumentNullException)
        {
        }

        // the relationship between fragment count, fragment size and packet size

        Refused(c => { c.MaxFragments = 4; c.FragmentSize = 1024; c.MaxPacketSize = 4 * 1024 + 1; }, "MaxFragments one short of MaxPacketSize");

        // exactly covering is allowed

        Accepted(c => { c.MaxFragments = 4; c.FragmentSize = 1024; c.MaxPacketSize = 4 * 1024; c.FragmentAbove = 1024; }, "MaxFragments exactly covering MaxPacketSize");

        // ranges

        Refused(c => c.MaxPacketSize = 0, "MaxPacketSize = 0");
        Refused(c => c.FragmentAbove = 0, "FragmentAbove = 0");
        Refused(c => c.FragmentSize = 0, "FragmentSize = 0");
        Refused(c => c.MaxFragments = 0, "MaxFragments = 0");
        Refused(c => c.MaxFragments = 257, "MaxFragments = 257");
        Refused(c => c.AckBufferSize = 0, "AckBufferSize = 0");
        Refused(c => c.SentPacketsBufferSize = -1, "SentPacketsBufferSize = -1");
        Refused(c => c.ReceivedPacketsBufferSize = 0, "ReceivedPacketsBufferSize = 0");
        Refused(c => c.FragmentReassemblyBufferSize = 0, "FragmentReassemblyBufferSize = 0");
        Refused(c => c.RttHistorySize = 0, "RttHistorySize = 0");
        Refused(c => c.TransmitPacket = null, "TransmitPacket = null");
        Refused(c => c.ProcessPacket = null, "ProcessPacket = null");

        // the smoothing factor boundaries 0 and 1 are accepted

        Accepted(c => { c.RttSmoothingFactor = 0.0f; c.PacketLossSmoothingFactor = 0.0f; c.BandwidthSmoothingFactor = 0.0f; }, "smoothing factors 0");
        Accepted(c => { c.RttSmoothingFactor = 1.0f; c.PacketLossSmoothingFactor = 1.0f; c.BandwidthSmoothingFactor = 1.0f; }, "smoothing factors 1");

        // the largest sequence buffer sizes create an endpoint pair that still sends and receives

        TestContext context = new TestContext();

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.SentPacketsBufferSize = 16384;
        senderConfig.ReceivedPacketsBufferSize = 16384;
        senderConfig.FragmentReassemblyBufferSize = 16384;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.SentPacketsBufferSize = 16384;
        receiverConfig.ReceivedPacketsBufferSize = 16384;
        receiverConfig.FragmentReassemblyBufferSize = 16384;

        context.Sender = new Endpoint(senderConfig, 0.0);
        context.Receiver = new Endpoint(receiverConfig, 0.0);

        context.Sender.SendPacket(new byte[8]);

        Check(context.Receiver.GetCounter(EndpointCounter.NumPacketsReceived) == 1, "largest buffer sizes still deliver");
    }

    // ------------------------------------------------------------
    // test_fragment_counts

    private static void TestFragmentCase(int fragmentSize, int maxFragments, int packetBytes, int expectedFragments)
    {
        TestContext context = new TestContext();

        int numProcessed = 0;
        byte[] processed = Array.Empty<byte>();

        ProcessPacketCallback capture = (id, sequence, packetData) =>
        {
            numProcessed++;
            processed = packetData.ToArray();
            return true;
        };

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.FragmentSize = fragmentSize;
        senderConfig.MaxFragments = maxFragments;
        senderConfig.MaxPacketSize = fragmentSize * maxFragments;
        senderConfig.FragmentAbove = fragmentSize;
        senderConfig.ProcessPacket = capture;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.FragmentSize = fragmentSize;
        receiverConfig.MaxFragments = maxFragments;
        receiverConfig.MaxPacketSize = fragmentSize * maxFragments;
        receiverConfig.FragmentAbove = fragmentSize;
        receiverConfig.ProcessPacket = capture;

        context.Sender = new Endpoint(senderConfig, 100.0);
        context.Receiver = new Endpoint(receiverConfig, 100.0);

        byte[] packet = new byte[packetBytes];
        for (int i = 0; i < packetBytes; ++i)
        {
            packet[i] = (byte)((i * 31) + 7);
        }

        context.Sender.SendPacket(packet);

        string what = $"fragment case ({fragmentSize}, {maxFragments}, {packetBytes})";

        Check(numProcessed == 1, $"{what}: processed {numProcessed}, expected 1");
        Check(processed.Length == packetBytes, $"{what}: processed {processed.Length} bytes");
        Check(processed.AsSpan().SequenceEqual(packet), $"{what}: processed bytes differ");

        ulong fragmentsSent = context.Sender.GetCounter(EndpointCounter.NumFragmentsSent);
        ulong fragmentsReceived = context.Receiver.GetCounter(EndpointCounter.NumFragmentsReceived);

        Check(fragmentsSent == (ulong)expectedFragments, $"{what}: {fragmentsSent} fragments sent, expected {expectedFragments}");
        Check(fragmentsReceived == (ulong)expectedFragments, $"{what}: {fragmentsReceived} fragments received, expected {expectedFragments}");
    }

    private static void TestFragmentCounts()
    {
        // an exact multiple of the fragment size, where the last fragment is full rather than a remainder
        TestFragmentCase(512, 16, 512 * 4, 4);

        // the largest packet the config allows, again an exact multiple
        TestFragmentCase(512, 16, 512 * 16, 16);

        // above the threshold by a single byte, and around the next boundary
        TestFragmentCase(512, 16, 513, 2);
        TestFragmentCase(512, 16, 1023, 2);
        TestFragmentCase(512, 16, 1025, 3);
        TestFragmentCase(64, 256, 65, 2);

        // 256 fragments, the maximum the wire format can express
        TestFragmentCase(64, 256, 64 * 256, 256);
        TestFragmentCase(64, 256, 64 * 255 + 1, 256);

        // at or below the threshold the packet is not fragmented
        TestFragmentCase(512, 16, 512, 0);
        TestFragmentCase(512, 16, 1, 0);
    }

    // ------------------------------------------------------------
    // test_truncated_packets

    private static void TestTruncatedPackets()
    {
        int numProcessed = 0;
        System.Collections.Generic.List<byte[]> captured = new System.Collections.Generic.List<byte[]>();

        EndpointConfig MakeConfig(string name)
        {
            return new EndpointConfig
            {
                Name = name,
                FragmentSize = 256,
                MaxFragments = 16,
                MaxPacketSize = 256 * 16,
                FragmentAbove = 256,
                TransmitPacket = (id, sequence, packetData) => captured.Add(packetData.ToArray()),
                ProcessPacket = (id, sequence, packetData) => { numProcessed++; return true; },
            };
        }

        Endpoint sender = new Endpoint(MakeConfig("sender"), 100.0);
        Endpoint receiver = new Endpoint(MakeConfig("receiver"), 100.0);

        // an unfragmented packet, captured on the wire

        byte[] packet = new byte[200];
        packet.AsSpan().Fill(0xAB);
        sender.SendPacket(packet);
        Check(captured.Count == 1, "one packet captured");

        // every truncation of it shorter than the header is rejected, and none is processed

        for (int truncatedBytes = 1; truncatedBytes < 4; ++truncatedBytes)
        {
            receiver.ReceivePacket(captured[0].AsSpan(0, truncatedBytes));
        }

        Check(receiver.GetCounter(EndpointCounter.NumPacketsInvalid) == 3, "truncated headers counted invalid");
        Check(numProcessed == 0, "no truncated packet processed");

        // the whole packet still arrives

        receiver.ReceivePacket(captured[0]);
        Check(numProcessed == 1, "whole packet processed");

        // now a fragmented packet

        captured.Clear();

        byte[] largePacket = new byte[1024];
        largePacket.AsSpan().Fill(0xCD);
        sender.SendPacket(largePacket);
        Check(captured.Count == 4, "four fragments captured");

        // a fragment truncated inside its header is rejected

        for (int truncatedBytes = 1; truncatedBytes < Wire.FragmentHeaderBytes; ++truncatedBytes)
        {
            receiver.ReceivePacket(captured[1].AsSpan(0, truncatedBytes));
        }

        Check(receiver.GetCounter(EndpointCounter.NumFragmentsReceived) == 0, "no truncated fragment received");
        Check(receiver.GetCounter(EndpointCounter.NumFragmentsInvalid) == (ulong)(Wire.FragmentHeaderBytes - 1), "truncated fragment headers counted invalid");

        // a fragment that is not the last one must carry exactly FragmentSize bytes,
        // so a truncated body is rejected too

        receiver.ReceivePacket(captured[1].AsSpan(0, captured[1].Length - 1));
        Check(receiver.GetCounter(EndpointCounter.NumFragmentsReceived) == 0, "truncated fragment body not received");
        Check(receiver.GetCounter(EndpointCounter.NumFragmentsInvalid) == (ulong)Wire.FragmentHeaderBytes, "truncated fragment body counted invalid");
        Check(numProcessed == 1, "truncated fragment not processed");

        // the intact fragments reassemble

        for (int i = 0; i < captured.Count; ++i)
        {
            receiver.ReceivePacket(captured[i]);
        }

        Check(receiver.GetCounter(EndpointCounter.NumFragmentsReceived) == 4, "all four fragments received");
        Check(numProcessed == 2, "fragmented packet processed");
    }

    // ------------------------------------------------------------
    // test_endpoint_reset_clears_stats: reset zeroes every statistic getter

    private static void TestEndpointResetClearsStats()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        for (int i = 0; i < 32; ++i)
        {
            context.Sender.SendPacket(dummyPacket);
            context.Receiver.Update(time);
            time += 0.05;
            context.Sender.Update(time);
            context.Receiver.Update(time);
            context.Receiver.SendPacket(dummyPacket);
            time += 0.05;
            context.Sender.Update(time);
            context.Receiver.Update(time);
        }

        // stats accumulate before reset
        Check(context.Sender.Rtt > 0.0f, "rtt accumulates before reset");

        context.Sender.Reset();
        context.Receiver.Reset();

        Check(context.Sender.Rtt == 0.0f, "rtt cleared by reset");
        Check(context.Sender.RttMin == 0.0f, "rtt_min cleared by reset");
        Check(context.Sender.RttMax == 0.0f, "rtt_max cleared by reset");
        Check(context.Sender.RttAvg == 0.0f, "rtt_avg cleared by reset");
        Check(context.Sender.JitterAvgVsMinRtt == 0.0f, "jitter_avg cleared by reset");
        Check(context.Sender.JitterMaxVsMinRtt == 0.0f, "jitter_max cleared by reset");
        Check(context.Sender.JitterStddevVsAvgRtt == 0.0f, "jitter_stddev cleared by reset");
        Check(context.Sender.PacketLoss == 0.0f, "packet_loss cleared by reset");
        Check(context.Sender.SentBandwidthKbps == 0.0f, "sent_kbps cleared by reset");
        Check(context.Sender.ReceivedBandwidthKbps == 0.0f, "received_kbps cleared by reset");
        Check(context.Sender.AckedBandwidthKbps == 0.0f, "acked_kbps cleared by reset");
    }

    // ------------------------------------------------------------
    // test_rtt_min_large: the rtt minimum is decided by a sample count, not a
    // sentinel, so a minimum of 10000 ms or more is reported instead of 0

    private static void TestRttMinLarge()
    {
        double time = 0.0;

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        double[] rttSeconds = { 10.0, 12.0, 20.0 };
        foreach (double rtt in rttSeconds)
        {
            context.Sender.SendPacket(dummyPacket);
            time += rtt;
            context.Sender.Update(time);
            context.Receiver.Update(time);
            context.Receiver.SendPacket(dummyPacket);

            context.Sender.ClearAcks();
            context.Receiver.ClearAcks();
        }

        context.Sender.Update(time);

        Check(context.Sender.RttMin == 10000.0f, "rtt_min reports 10000 ms when all samples are 10000 ms or more");
    }

    // ------------------------------------------------------------
    // test_rtt_clamped_when_time_steps_back: an ack processed after the
    // caller's clock moved backwards gives an rtt sample of 0, never negative

    private static void TestRttClampedWhenTimeStepsBack()
    {
        double time = 100.0;

        TestContext context = new TestContext();

        context.Sender = new Endpoint(DefaultConfig(context, 0, "sender"), time);
        context.Receiver = new Endpoint(DefaultConfig(context, 1, "receiver"), time);

        byte[] dummyPacket = new byte[8];

        context.Sender.SendPacket(dummyPacket);

        time -= 1.0;
        context.Sender.Update(time);
        context.Receiver.Update(time);
        context.Receiver.SendPacket(dummyPacket);

        Check(context.Sender.GetAcks().Length == 1, "the packet is acked");
        Check(context.Sender.Rtt >= 0.0f, "rtt stays non-negative when time steps back");

        context.Sender.Update(time);

        Check(context.Sender.RttMin >= 0.0f, "rtt_min stays non-negative when time steps back");
        Check(context.Sender.RttAvg >= 0.0f, "rtt_avg stays non-negative when time steps back");
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

    // ------------------------------------------------------------
    // test_float_multiply_add_rounds_twice
    //
    // The C# half of the contraction rule the C build's -ffp-contract=off pins:
    // a*b + c must round twice (once for the product, once for the add), never
    // fuse into a single-rounded FMA. The pairs below are chosen so a fused
    // evaluation leaves a nonzero residue where strict evaluation cancels to
    // zero, so a JIT that contracts (or a constant-folded input) turns this red.
    // The inputs live in static fields, not locals, so the JIT cannot prove
    // them constant and fold the whole expression at compile time.

    private static float s_fmaFloatA = BitConverter.Int32BitsToSingle(0x3F800800);
    private static float s_fmaFloatC = BitConverter.Int32BitsToSingle(unchecked((int)0xBF801000));
    private static double s_fmaDoubleA = BitConverter.Int64BitsToDouble(0x3FF0000002000000);
    private static double s_fmaDoubleC = BitConverter.Int64BitsToDouble(unchecked((long)0xBFF0000004000000));

    private static void FloatMultiplyAddRoundsTwice()
    {
        float a = s_fmaFloatA;
        float b = s_fmaFloatA;
        float c = s_fmaFloatC;

        uint productPlusAdd = BitConverter.SingleToUInt32Bits(a * b + c);
        Check(productPlusAdd == 0x00000000u,
            $"float a*b+c must round twice, got 0x{productPlusAdd:x8} (fused/FMA gives 0x33800000)");

        double da = s_fmaDoubleA;
        double db = s_fmaDoubleA;
        double dc = s_fmaDoubleC;

        ulong doubleProductPlusAdd = BitConverter.DoubleToUInt64Bits(da * db + dc);
        Check(doubleProductPlusAdd == 0x0000000000000000ul,
            $"double a*b+c must round twice, got 0x{doubleProductPlusAdd:x16} (fused/FMA gives 0x3c90000000000000)");
    }
}
