/*
    Hostile.cs

    C#-specific tests: hostile wire input against every rejection rule (nothing
    off the wire may ever throw — failures land in counters and the packet is
    dropped), API misuse validation, the zero-allocation steady-state proof, and
    a port of the C repo's fuzz_target.c operation-script harness.
*/

using System;
using System.Buffers.Binary;
using Reliable;

namespace Reliable.Tests;

internal static partial class Tests
{
    private static Endpoint MakeSink(out Func<int> processedCount, int maxPacketSize = 8000, int fragmentSize = 500, int maxFragments = 16)
    {
        int processed = 0;
        processedCount = () => processed;
        return new Endpoint(new EndpointConfig
        {
            Name = "sink",
            MaxPacketSize = maxPacketSize,
            FragmentAbove = fragmentSize,
            FragmentSize = fragmentSize,
            MaxFragments = maxFragments,
            TransmitPacket = (id, sequence, packetData) => { },
            ProcessPacket = (id, sequence, packetData) => { processed++; return true; },
        }, 100.0);
    }

    // ------------------------------------------------------------
    // every truncation of a valid header must be rejected cleanly

    private static void TestHostileTruncatedHeaders()
    {
        foreach ((ushort sequence, ushort ack, uint ackBits, string hex) in s_goldenHeaders)
        {
            byte[] golden = FromHex(hex);

            // parser level: every proper prefix is rejected with -1, no exception
            for (int length = 1; length < golden.Length; length++)
            {
                int result = Wire.ReadPacketHeader("hostile", golden.AsSpan(0, length), out _, out _, out _);
                Check(result == -1, $"truncated header ({sequence},{ack},{ackBits:x8}) at {length} bytes must be rejected");
            }

            // endpoint level: dropped and counted, never thrown
            Endpoint sink = MakeSink(out Func<int> processed);
            for (int length = 1; length < golden.Length; length++)
            {
                sink.ReceivePacket(golden.AsSpan(0, length));
            }
            // a truncated header either fails header parse (invalid) or, when the
            // remaining bytes happen to parse as a shorter valid header, is
            // delivered with a short payload — but only lengths >= a valid header
            // can deliver. for these vectors every truncation must be invalid:
            Check(sink.GetCounter(EndpointCounter.NumPacketsInvalid) == (ulong)(golden.Length - 1), $"every truncation of ({sequence},{ack},{ackBits:x8}) counted invalid");
            Check(processed() == 0, "no truncated packet may be processed");
        }
    }

    // ------------------------------------------------------------
    // every fragment rejection rule, one deliberate violation each

    private static void TestHostileFragments()
    {
        // helper: build a valid fragment for a given id/total with an embedded
        // canonical header on fragment 0
        static byte[] BuildFragment(ushort sequence, int fragmentId, int numFragments, int dataBytes, ushort ack, uint ackBits)
        {
            byte[] buffer = new byte[Wire.FragmentHeaderBytes + Wire.MaxPacketHeaderBytes + dataBytes];
            int p = 0;
            buffer[p++] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(p), sequence);
            p += 2;
            buffer[p++] = (byte)fragmentId;
            buffer[p++] = (byte)(numFragments - 1);
            if (fragmentId == 0)
            {
                p += Wire.WritePacketHeader(buffer.AsSpan(p), sequence, ack, ackBits);
            }
            for (int i = 0; i < dataBytes; i++)
            {
                buffer[p++] = (byte)(i + sequence);
            }
            return buffer.AsSpan(0, p).ToArray();
        }

        Endpoint sink;
        Func<int> processed;

        // num_fragments > max_fragments (17 > 16)
        sink = MakeSink(out processed);
        sink.ReceivePacket(BuildFragment(0, 0, 17, 500, 0xFFFF, 0));
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "num_fragments > max_fragments rejected");

        // fragment_id >= num_fragments
        sink = MakeSink(out processed);
        sink.ReceivePacket(BuildFragment(0, 3, 3, 500, 0xFFFF, 0));
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "fragment_id >= num_fragments rejected");

        // prefix byte with bit 0 set but not exactly 1
        sink = MakeSink(out processed);
        byte[] badPrefix = BuildFragment(0, 0, 2, 500, 0xFFFF, 0);
        badPrefix[0] = 3;
        sink.ReceivePacket(badPrefix);
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "fragment prefix != 1 rejected");

        // fragment too small to contain its header
        sink = MakeSink(out processed);
        sink.ReceivePacket(new byte[] { 1, 0, 0, 0 });
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "short fragment rejected");

        // embedded header sequence != fragment sequence
        sink = MakeSink(out processed);
        {
            byte[] fragment = new byte[Wire.FragmentHeaderBytes + Wire.MaxPacketHeaderBytes + 500];
            int p = 0;
            fragment[p++] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(fragment.AsSpan(p), 7);
            p += 2;
            fragment[p++] = 0;
            fragment[p++] = 1; // 2 fragments
            p += Wire.WritePacketHeader(fragment.AsSpan(p), 8, 0xFFFF, 0); // wrong sequence inside
            for (int i = 0; i < 500; i++) fragment[p++] = (byte)i;
            sink.ReceivePacket(fragment.AsSpan(0, p));
        }
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "embedded sequence mismatch rejected");

        // non-canonical embedded header: an ack_bits byte of 0xFF transmitted
        // explicitly. canonical for (5, 5, 0xFFFFFFFF) is [20 05 00 00]; flag
        // bit 1 + trailing ff is the same triple, one byte longer.
        sink = MakeSink(out processed);
        {
            byte[] fragment = new byte[Wire.FragmentHeaderBytes + 5 + 500];
            int p = 0;
            fragment[p++] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(fragment.AsSpan(p), 5);
            p += 2;
            fragment[p++] = 0;
            fragment[p++] = 0; // 1 fragment
            fragment[p++] = 0x22;       // regular prefix, bit 5 (ack diff) + bit 1 (ack_bits byte 0 present)
            fragment[p++] = 0x05;       // sequence low
            fragment[p++] = 0x00;       // sequence high
            fragment[p++] = 0x00;       // ack difference 0
            fragment[p++] = 0xFF;       // ack_bits byte 0 = 0xFF: non-canonical, must be elided
            for (int i = 0; i < 100; i++) fragment[p++] = (byte)i;
            sink.ReceivePacket(fragment.AsSpan(0, p));
        }
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "non-canonical embedded header rejected");

        // middle fragment with the wrong size (100 != fragment_size 500)
        sink = MakeSink(out processed);
        sink.ReceivePacket(BuildFragment(0, 1, 3, 100, 0, 0));
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "undersized middle fragment rejected");

        // any fragment larger than fragment_size (501 > 500)
        sink = MakeSink(out processed);
        sink.ReceivePacket(BuildFragment(0, 2, 3, 501, 0, 0));
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "oversized fragment rejected");

        // fragment count mismatch across fragments of the same packet
        sink = MakeSink(out processed);
        sink.ReceivePacket(BuildFragment(11, 1, 4, 500, 0, 0));
        Check(sink.GetCounter(EndpointCounter.NumFragmentsReceived) == 1, "first fragment accepted");
        sink.ReceivePacket(BuildFragment(11, 1, 3, 500, 0, 0));
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == 1, "fragment count mismatch rejected");

        // duplicate fragment: silently dropped, no counters moved
        sink = MakeSink(out processed);
        byte[] dupFragment = BuildFragment(12, 1, 4, 500, 0, 0);
        sink.ReceivePacket(dupFragment);
        ulong receivedBefore = sink.GetCounter(EndpointCounter.NumFragmentsReceived);
        ulong invalidBefore = sink.GetCounter(EndpointCounter.NumFragmentsInvalid);
        sink.ReceivePacket(dupFragment);
        Check(sink.GetCounter(EndpointCounter.NumFragmentsReceived) == receivedBefore, "duplicate fragment not counted as received");
        Check(sink.GetCounter(EndpointCounter.NumFragmentsInvalid) == invalidBefore, "duplicate fragment not counted as invalid");

        // fragments of an already-delivered packet: silently dropped, no new reassembly
        sink = MakeSink(out processed);
        byte[] part0 = BuildFragment(0, 0, 2, 500, 0xFFFF, 0);
        byte[] part1 = BuildFragment(0, 1, 2, 123, 0xFFFF, 0);
        sink.ReceivePacket(part0);
        sink.ReceivePacket(part1);
        Check(processed() == 1, "two-fragment packet delivered");
        sink.ReceivePacket(part0);
        Check(!sink.FragmentReassemblyExists(0), "no zombie reassembly for a delivered packet");
        Check(processed() == 1, "replayed fragment must not redeliver");

        // datagram larger than max_packet_size + headers: too large to receive
        sink = MakeSink(out processed);
        sink.ReceivePacket(new byte[8000 + Wire.MaxPacketHeaderBytes + Wire.FragmentHeaderBytes + 1]);
        Check(sink.GetCounter(EndpointCounter.NumPacketsTooLargeToReceive) == 1, "oversized datagram rejected");

        // regular packet whose payload exceeds max_packet_size after the header
        sink = MakeSink(out processed);
        {
            byte[] packet = new byte[Wire.MaxPacketHeaderBytes + 8000 + 3];
            int headerBytes = Wire.WritePacketHeader(packet, 0, 0xFFFF, 0); // 8 bytes
            sink.ReceivePacket(packet.AsSpan(0, headerBytes + 8001));
            Check(sink.GetCounter(EndpointCounter.NumPacketsTooLargeToReceive) == 1, "oversized payload rejected");
            Check(processed() == 0, "oversized payload not processed");
        }
    }

    // ------------------------------------------------------------
    // parser fuzz: random bytes through both header parsers, no exceptions ever

    private static void TestHostileParserFuzz()
    {
        ulong rngState = 0xC0FFEE123456789ul;
        ulong NextRng()
        {
            ulong x = rngState;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            rngState = x;
            return unchecked(x * 0x2545F4914F6CDD1Dul);
        }

        int iterations = s_shortMode ? 20000 : 200000;
        byte[] buffer = new byte[64];

        for (int i = 0; i < iterations; i++)
        {
            int length = 1 + (int)(NextRng() % 64);
            for (int j = 0; j < length; j++)
            {
                buffer[j] = (byte)NextRng();
            }

            int headerResult = Wire.ReadPacketHeader("fuzz", buffer.AsSpan(0, length), out _, out _, out _);
            Check(headerResult == -1 || (headerResult >= 3 && headerResult <= Wire.MaxPacketHeaderBytes && headerResult <= length), "packet header parse result in range");

            int fragmentResult = Wire.ReadFragmentHeader("fuzz", buffer.AsSpan(0, length), 256, 1024,
                out int fragmentId, out int numFragments, out int fragmentBytes, out _, out _, out _);
            if (fragmentResult >= 0)
            {
                Check(fragmentResult == Wire.FragmentHeaderBytes, "fragment header consumes exactly 5 bytes");
                Check(fragmentId >= 0 && fragmentId < numFragments, "fragment id in range");
                Check(numFragments >= 1 && numFragments <= 256, "num fragments in range");
                Check(fragmentBytes >= 0 && fragmentBytes <= 1024, "fragment bytes in range");
            }
        }
    }

    // ------------------------------------------------------------
    // a packet the process callback rejects is not acked and may be redelivered

    private static void TestProcessRejectRedelivery()
    {
        bool accept = false;
        int processedCalls = 0;

        Endpoint sink = new Endpoint(new EndpointConfig
        {
            Name = "sink",
            TransmitPacket = (id, sequence, packetData) => { },
            ProcessPacket = (id, sequence, packetData) => { processedCalls++; return accept; },
        }, 100.0);

        byte[] packet = new byte[Wire.MaxPacketHeaderBytes + 8];
        int headerBytes = Wire.WritePacketHeader(packet, 0, 0xFFFF, 0);
        ReadOnlySpan<byte> wire = packet.AsSpan(0, headerBytes + 8);

        // rejected: processed but not recorded
        sink.ReceivePacket(wire);
        Check(processedCalls == 1, "first delivery processed");
        Check(sink.GetCounter(EndpointCounter.NumPacketsDuplicate) == 0, "rejected packet is not a duplicate");

        // redelivered and accepted this time
        accept = true;
        sink.ReceivePacket(wire);
        Check(processedCalls == 2, "redelivery processed after rejection");

        // now it is recorded: a third delivery is a duplicate
        sink.ReceivePacket(wire);
        Check(processedCalls == 2, "accepted packet is not reprocessed");
        Check(sink.GetCounter(EndpointCounter.NumPacketsDuplicate) == 1, "third delivery counted duplicate");
    }

    // ------------------------------------------------------------
    // API misuse: configuration is validated at construction; wire data never throws

    private static void TestConfigValidation()
    {
        static EndpointConfig Valid()
        {
            return new EndpointConfig
            {
                TransmitPacket = (id, sequence, packetData) => { },
                ProcessPacket = (id, sequence, packetData) => true,
            };
        }

        static void MustThrow(Action action, string what)
        {
            try
            {
                action();
            }
            catch (ArgumentException)
            {
                return; // ArgumentNullException is an ArgumentException too
            }
            Check(false, $"{what} must throw ArgumentException");
        }

        static void MustThrowConfig(Action<EndpointConfig> mutate, string what)
        {
            EndpointConfig config = Valid();
            mutate(config);
            MustThrow(() => _ = new Endpoint(config, 0.0), what);
        }

        // a valid default config constructs
        _ = new Endpoint(Valid(), 0.0);

        // the C library's create-time assert list, as construction-time exceptions
        MustThrowConfig(c => c.MaxPacketSize = 0, "MaxPacketSize = 0");
        MustThrowConfig(c => c.MaxPacketSize = -1, "MaxPacketSize < 0");
        MustThrowConfig(c => c.FragmentAbove = 0, "FragmentAbove = 0");
        MustThrowConfig(c => c.MaxFragments = 0, "MaxFragments = 0");
        MustThrowConfig(c => c.MaxFragments = 257, "MaxFragments > 256");
        MustThrowConfig(c => c.FragmentSize = 0, "FragmentSize = 0");
        MustThrowConfig(c => c.AckBufferSize = 0, "AckBufferSize = 0");
        MustThrowConfig(c => c.SentPacketsBufferSize = 0, "SentPacketsBufferSize = 0");
        MustThrowConfig(c => c.ReceivedPacketsBufferSize = 0, "ReceivedPacketsBufferSize = 0");
        MustThrowConfig(c => c.FragmentReassemblyBufferSize = 0, "FragmentReassemblyBufferSize = 0");
        MustThrowConfig(c => c.RttHistorySize = 0, "RttHistorySize = 0");
        MustThrowConfig(c => c.TransmitPacket = null, "TransmitPacket = null");
        MustThrowConfig(c => c.ProcessPacket = null, "ProcessPacket = null");
        MustThrowConfig(c => c.Name = null!, "Name = null");

        // the send-path debug assert of the C library, as a construction-time check:
        // the largest fragmentable packet must fit in MaxFragments fragments
        MustThrowConfig(c => { c.MaxPacketSize = 16 * 1024; c.FragmentAbove = 1024; c.FragmentSize = 1024; c.MaxFragments = 8; }, "MaxFragments cannot cover MaxPacketSize");

        // empty spans are API misuse on both paths (the C library asserts packet_bytes > 0)
        Endpoint endpoint = new Endpoint(Valid(), 0.0);
        MustThrow(() => endpoint.SendPacket(ReadOnlySpan<byte>.Empty), "SendPacket(empty)");
        MustThrow(() => endpoint.ReceivePacket(ReadOnlySpan<byte>.Empty), "ReceivePacket(empty)");

        // oversized send is NOT misuse: dropped and counted, exactly like C
        endpoint.SendPacket(new byte[17 * 1024]);
        Check(endpoint.GetCounter(EndpointCounter.NumPacketsTooLargeToSend) == 1, "oversized send counted, not thrown");
        Check(endpoint.NextPacketSequence == 0, "oversized send consumes no sequence number");
    }

    // ------------------------------------------------------------
    // zero allocation at steady state, the family invariant, measured with the
    // GC allocation counter (the same proof serialize.cs uses)

    private static void TestZeroAllocation()
    {
        TestContext context = new TestContext();

        EndpointConfig senderConfig = DefaultConfig(context, 0, "sender");
        senderConfig.MaxPacketSize = 8000;
        senderConfig.FragmentAbove = 500;
        senderConfig.FragmentSize = 500;

        EndpointConfig receiverConfig = DefaultConfig(context, 1, "receiver");
        receiverConfig.MaxPacketSize = 8000;
        receiverConfig.FragmentAbove = 500;
        receiverConfig.FragmentSize = 500;

        context.Sender = new Endpoint(senderConfig, 100.0);
        context.Receiver = new Endpoint(receiverConfig, 100.0);

        byte[] smallPacket = new byte[64];
        byte[] largePacket = new byte[2200];
        double time = 100.0;

        void Round()
        {
            context.Sender!.SendPacket(smallPacket);      // regular path
            context.Sender!.SendPacket(largePacket);      // fragmented path + reassembly on the receiver
            context.Receiver!.SendPacket(smallPacket);
            context.Sender!.Update(time);
            context.Receiver!.Update(time);
            _ = context.Sender!.GetAcks();
            _ = context.Receiver!.GetAcks();
            context.Sender!.ClearAcks();
            context.Receiver!.ClearAcks();
            time += 0.016;
        }

        // warm up: pool buckets, tiering, first-call setup
        for (int i = 0; i < 64; i++)
        {
            Round();
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 1000; i++)
        {
            Round();
        }
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Check(allocated == 0, $"steady state allocated {allocated} bytes over 1000 rounds");
    }

    // ------------------------------------------------------------
    // port of fuzz_target.c: the fuzz input is a script of operations against a
    // live endpoint pair. deterministic seeds; passing = no exceptions, ever.

    private const int FuzzScriptMaxPacketBytes = 16 * 1024;

    private static void RunFuzzScript(ReadOnlySpan<byte> data)
    {
        double time = 100.0;

        Endpoint client = null!;
        Endpoint server = null!;

        EndpointConfig MakeConfig(ulong id)
        {
            return new EndpointConfig
            {
                Id = id,
                FragmentAbove = 500,   // fragment aggressively so reassembly is exercised by small inputs
                TransmitPacket = (cbId, sequence, packetData) =>
                {
                    if (cbId == 0)
                    {
                        server.ReceivePacket(packetData);
                    }
                    else
                    {
                        client.ReceivePacket(packetData);
                    }
                },
                ProcessPacket = (cbId, sequence, packetData) => true,
            };
        }

        client = new Endpoint(MakeConfig(0), time);
        server = new Endpoint(MakeConfig(1), time);

        // the input is a sequence of operations: [op:1][length:2][payload:length]

        int p = 0;
        int remaining = data.Length;

        while (remaining >= 3)
        {
            int op = data[p] % 4;
            int length = 1 + ((data[p + 1] | (data[p + 2] << 8)) % FuzzScriptMaxPacketBytes);
            p += 3;
            remaining -= 3;

            if (length > remaining)
            {
                length = remaining;
            }

            if (length > 0)
            {
                ReadOnlySpan<byte> packetData = data.Slice(p, length);

                switch (op)
                {
                    case 0:
                        client.SendPacket(packetData);
                        break;
                    case 1:
                        server.SendPacket(packetData);
                        break;
                    case 2:
                        client.ReceivePacket(packetData);
                        break;
                    case 3:
                        server.ReceivePacket(packetData);
                        break;
                }

                p += length;
                remaining -= length;
            }

            time += 0.01;

            client.Update(time);
            server.Update(time);

            client.ClearAcks();
            server.ClearAcks();
        }
    }

    private static void TestFuzzScript()
    {
        ulong rngState = 0xF00DFACE12345ul;
        ulong NextRng()
        {
            ulong x = rngState;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            rngState = x;
            return unchecked(x * 0x2545F4914F6CDD1Dul);
        }

        int scripts = s_shortMode ? 40 : 200;
        byte[] data = new byte[64 * 1024];

        for (int i = 0; i < scripts; i++)
        {
            int size = (int)(NextRng() % (ulong)data.Length);
            for (int j = 0; j < size; j++)
            {
                data[j] = (byte)NextRng();
            }
            RunFuzzScript(data.AsSpan(0, size));
        }
    }
}
