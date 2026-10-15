/*
    Compat.cs — the C# half of the cross-implementation interop gate.

    Its C twin is c/compat.c, built against the real reliable.c. Both emit the
    exact same text for the same mode+seed; scripts/interop.sh diffs them, and any
    byte of difference fails the gate.

    Everything here that involves randomness draws from the shared xorshift64*
    PRNG in the draw order specified in c/compat.c. Keep the two files in
    lockstep: a change to either without the other fails the gate (which is the
    point).
*/

using System;
using System.IO;
using System.Text;
using Reliable;

namespace Reliable.Compat;

internal static class Program
{
    // ------------------------------------------------------------
    // shared deterministic PRNG: xorshift64* (identical in compat.c)

    private static ulong s_rngState;

    private static void RngSeed(ulong seed)
    {
        s_rngState = seed != 0 ? seed : 0x9E3779B97F4A7C15ul;
    }

    private static ulong RngNext()
    {
        ulong x = s_rngState;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s_rngState = x;
        return unchecked(x * 0x2545F4914F6CDD1Dul);
    }

    private static uint RngU32()
    {
        return (uint)(RngNext() >> 32);
    }

    private static int RngInt(int a, int b)
    {
        return a + (int)(RngU32() % (uint)(b - a + 1));
    }

    // ------------------------------------------------------------
    // FNV-1a 64 (identical in compat.c)

    private static ulong Fnv1a64(ReadOnlySpan<byte> data)
    {
        ulong hash = 14695981039346656037ul;
        for (int i = 0; i < data.Length; i++)
        {
            hash ^= data[i];
            hash = unchecked(hash * 1099511628211ul);
        }
        return hash;
    }

    private static TextWriter s_out = Console.Out;

    private static void AppendHex(StringBuilder sb, ReadOnlySpan<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            sb.Append(data[i].ToString("x2"));
        }
    }

    // ------------------------------------------------------------
    // vectors mode

    private static void EmitHeaderVector(ushort sequence, ushort ack, uint ackBits)
    {
        Span<byte> buffer = stackalloc byte[16];
        buffer.Clear();
        int bytes = Wire.WritePacketHeader(buffer, sequence, ack, ackBits);

        // self check: decode and re-encode must round trip exactly
        int readBytes = Wire.ReadPacketHeader("vectors", buffer.Slice(0, bytes), out ushort readSequence, out ushort readAck, out uint readAckBits);
        if (readBytes != bytes || readSequence != sequence || readAck != ack || readAckBits != ackBits)
        {
            s_out.Write($"SELFCHECK-FAILED HDR {sequence} {ack} {ackBits}\n");
            s_out.Flush();
            Environment.Exit(1);
        }

        StringBuilder sb = new StringBuilder(64);
        sb.Append("HDR ").Append(sequence).Append(' ').Append(ack).Append(' ').Append(ackBits).Append(' ');
        AppendHex(sb, buffer.Slice(0, bytes));
        sb.Append('\n');
        s_out.Write(sb.ToString());
    }

    private static int s_vectorsFragCount;

    private static void RunVectors()
    {
        // the elision-rule corners (same values as the C repo's conformance generator)
        ushort[] seqs = { 0, 1, 255, 256, 1000, 32768, 65535, 7 };
        ushort[] acks = { 0, 1, 254, 255, 256, 999, 65535, 32760 };
        uint[] bits = { 0xFFFFFFFFu, 0x00000000u, 0xFFFFFF00u, 0x00FFFFFFu,
                        0xDEADBEEFu, 0xFF00FF00u, 0x000000FFu, 0xFFFF00FFu };

        for (int a = 0; a < 8; a++)
            for (int b = 0; b < 8; b++)
                for (int c = 0; c < 8; c++)
                    EmitHeaderVector(seqs[a], acks[b], bits[c]);

        // 1000 PRNG triples across the whole space
        RngSeed(0x1234567855AA55AAul);
        for (int i = 0; i < 1000; i++)
        {
            ushort sequence = (ushort)RngU32();
            ushort ack = (ushort)RngU32();
            uint ackBits = RngU32();
            EmitHeaderVector(sequence, ack, ackBits);
        }

        // fragment layouts: one endpoint, several payload sizes around the corners
        int[] payloadSizes = { 501, 999, 1000, 1001, 1500, 2200, 4000, 7999, 8000 };

        EndpointConfig config = new EndpointConfig
        {
            Name = "vectors",
            MaxPacketSize = 8000,
            FragmentAbove = 500,
            FragmentSize = 1000,
            MaxFragments = 8,
            TransmitPacket = (id, sequence, packetData) =>
            {
                StringBuilder sb = new StringBuilder(packetData.Length * 2 + 32);
                sb.Append("FRAG ").Append(s_vectorsFragCount++).Append(' ').Append(packetData.Length).Append(' ');
                AppendHex(sb, packetData);
                sb.Append('\n');
                s_out.Write(sb.ToString());
            },
            ProcessPacket = (id, sequence, packetData) => true,
        };

        Endpoint endpoint = new Endpoint(config, 100.0);

        byte[] payload = new byte[8192];
        foreach (int payloadBytes in payloadSizes)
        {
            ushort sequence = endpoint.NextPacketSequence;
            payload[0] = (byte)(sequence & 0xFF);
            payload[1] = (byte)((sequence >> 8) & 0xFF);
            for (int i = 2; i < payloadBytes; i++)
                payload[i] = (byte)((i + sequence) % 256);
            s_out.Write($"FRAGSET {sequence} {payloadBytes}\n");
            s_vectorsFragCount = 0;
            endpoint.SendPacket(payload.AsSpan(0, payloadBytes));
        }
    }

    // ------------------------------------------------------------
    // malformed mode

    // one hostile / boundary input per checklist item 5: zero length, oversize,
    // truncated headers, bad fragment counts. each vector is fed to a fresh
    // endpoint; the line reports what the endpoint did and the eleven counters.
    // the C twin is run_malformed in c/compat.c. identical text.

    private const int MalformedMaxPacket = 100;

    private static readonly string[] CounterNames =
    {
        "sent", "received", "acked", "stale", "invalid",
        "too_large_send", "too_large_receive", "fragments_sent",
        "fragments_received", "fragments_invalid", "duplicate",
    };

    private static ushort s_malformedDeliveredSequence;
    private static int s_malformedDeliveredLength;
    private static bool s_malformedDelivered;

    private static bool MalformedProcess(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)
    {
        s_malformedDelivered = true;
        s_malformedDeliveredSequence = sequence;
        s_malformedDeliveredLength = packetData.Length;
        return true;
    }

    private static void RunMalformed()
    {
        EndpointConfig config = new EndpointConfig
        {
            Name = "malformed",
            MaxPacketSize = MalformedMaxPacket,
            FragmentAbove = 50,
            FragmentSize = 50,
            MaxFragments = 16,
            TransmitPacket = (id, sequence, packetData) => { },
            ProcessPacket = MalformedProcess,
        };

        byte[] oversize = new byte[MalformedMaxPacket + 16];

        (byte[] Data, string Label)[] vectors =
        {
            (Array.Empty<byte>(), "zero-length"),
            (oversize, "oversize"),
            (new byte[] { 0x00 }, "prefix-only"),
            (new byte[] { 0x00, 0x01 }, "seq-truncated"),
            (new byte[] { 0x20, 0x01, 0x02 }, "ack-diff-missing"),
            (new byte[] { 0x01, 0x00, 0x01 }, "fragment-short"),
            (new byte[] { 0x01, 0x00, 0x00, 0x05, 0x02 }, "fragment-id-range"),
            (new byte[] { 0x01, 0x00, 0x00, 0x00, 0xFF }, "fragment-too-many"),
            (new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 }, "fragment-no-header"),
            (new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 }, "valid-minimal"),
        };

        for (int n = 0; n < vectors.Length; n++)
        {
            Endpoint endpoint = new Endpoint(config, 100.0);
            ReadOnlySpan<ulong> counters = endpoint.Counters;

            ulong[] before = new ulong[Endpoint.NumCounters];
            for (int i = 0; i < Endpoint.NumCounters; i++)
                before[i] = counters[i];

            s_malformedDelivered = false;
            s_malformedDeliveredSequence = 0;
            s_malformedDeliveredLength = 0;

            try
            {
                endpoint.ReceivePacket(vectors[n].Data);
            }
            catch (ArgumentException)
            {
                // the port refuses an empty datagram; C counts it (finding, item 5)
            }

            string changed = "none";
            for (int i = 0; i < Endpoint.NumCounters; i++)
            {
                if (counters[i] != before[i])
                {
                    changed = CounterNames[i];
                    break;
                }
            }

            StringBuilder sb = new StringBuilder(128);
            sb.Append(n).Append(' ').Append(s_malformedDelivered ? "accepted" : "refused").Append(' ').Append(changed).Append(' ');
            if (s_malformedDelivered)
                sb.Append(s_malformedDeliveredSequence).Append(' ').Append(s_malformedDeliveredLength);
            else
                sb.Append('-');
            for (int i = 0; i < Endpoint.NumCounters; i++)
                sb.Append(' ').Append(counters[i]);
            sb.Append('\n');
            s_out.Write(sb.ToString());
        }
    }

    // ------------------------------------------------------------
    // empty_packet mode

    // one receiver, six inputs, in order: a zero-length packet, a one-byte
    // packet {0}, a one-byte packet {1}, max_packet_size + 14 zero bytes, one
    // byte more than that, then a valid packet from a sender. each line is
    // <input> <refused|accepted> <process callback ran 0|1> <eleven counters>.
    // counters accumulate on that same receiver. the C twin is run_empty_packet.
    // identical text.

    private static int s_emptyProcessRan;

    private static void RunEmptyPacket()
    {
        EndpointConfig receiverConfig = new EndpointConfig
        {
            Name = "receiver",
            TransmitPacket = (id, sequence, packetData) => { },
            ProcessPacket = (id, sequence, packetData) => { s_emptyProcessRan = 1; return true; },
        };
        int limit = receiverConfig.MaxPacketSize + Wire.MaxPacketHeaderBytes + Wire.FragmentHeaderBytes;
        Endpoint receiver = new Endpoint(receiverConfig, 0.0);

        byte[]? sent = null;
        Endpoint sender = new Endpoint(new EndpointConfig
        {
            Name = "sender",
            TransmitPacket = (id, sequence, packetData) => { sent = packetData.ToArray(); },
            ProcessPacket = (id, sequence, packetData) => true,
        }, 0.0);

        void Feed(string label, ReadOnlySpan<byte> packet)
        {
            s_emptyProcessRan = 0;
            try
            {
                receiver.ReceivePacket(packet);
            }
            catch (ArgumentException)
            {
                // an empty datagram that throws is a refusal that counted nothing
            }

            ReadOnlySpan<ulong> counters = receiver.Counters;
            StringBuilder sb = new StringBuilder(160);
            sb.Append(label).Append(' ').Append(s_emptyProcessRan != 0 ? "accepted" : "refused").Append(' ').Append(s_emptyProcessRan);
            for (int i = 0; i < Endpoint.NumCounters; i++)
                sb.Append(' ').Append(counters[i]);
            sb.Append('\n');
            s_out.Write(sb.ToString());
        }

        Feed("zero-length", ReadOnlySpan<byte>.Empty);
        Feed("byte-0", new byte[] { 0 });
        Feed("byte-1", new byte[] { 1 });

        byte[] zeros = new byte[limit + 1];
        Feed("max-plus-14", zeros.AsSpan(0, limit));
        Feed("max-plus-15", zeros.AsSpan(0, limit + 1));

        sender.SendPacket(new byte[] { 0x11 });
        if (sent == null || sent.Length == 0)
        {
            Console.Error.WriteLine("empty_packet: sender produced no packet");
            s_out.Flush();
            Environment.Exit(1);
        }
        Feed("valid", sent);
    }

    // ------------------------------------------------------------
    // scenario mode

    private const int MaxQueue = 8192;
    private const int ScenarioMaxPacketBytes = 9000;

    private sealed class Link
    {
        public readonly byte[][] Data = new byte[MaxQueue][];
        public readonly int[] Bytes = new int[MaxQueue];
        public int NumPackets;

        public void Queue(ReadOnlySpan<byte> packet)
        {
            if (NumPackets == MaxQueue || packet.Length <= 0)
                return;
            Data[NumPackets] = packet.ToArray();
            Bytes[NumPackets] = packet.Length;
            NumPackets++;
        }

        public void Clear()
        {
            for (int i = 0; i < NumPackets; i++)
                Data[i] = null!;
            NumPackets = 0;
        }
    }

    private static Endpoint s_a = null!;
    private static Endpoint s_b = null!;
    private static readonly Link s_aToB = new Link();
    private static readonly Link s_bToA = new Link();
    private static int s_lossPct;
    private static int s_corruptPct;
    private static int s_duplicatePct;
    private static bool s_inject;
    private static int s_processRejectPct;
    private static int s_warpSends;
    private static bool s_quiet;

    // draw order per flush: fisher-yates (one draw per swap, i from n-1 down to
    // 1), then per packet in post-shuffle order: loss draw; if lost, nothing
    // more; else corrupt draw (+ position and bit draws only when corrupting),
    // then duplicate draw. identical in compat.c.
    private static void LinkFlush(Link link, Endpoint to)
    {
        for (int i = link.NumPackets - 1; i > 0; i--)
        {
            int j = RngInt(0, i);
            (link.Data[i], link.Data[j]) = (link.Data[j], link.Data[i]);
            (link.Bytes[i], link.Bytes[j]) = (link.Bytes[j], link.Bytes[i]);
        }

        for (int i = 0; i < link.NumPackets; i++)
        {
            byte[] data = link.Data[i];
            int bytes = link.Bytes[i];

            if (s_lossPct > 0 && RngInt(0, 99) < s_lossPct)
                continue;

            if (s_corruptPct > 0 && RngInt(0, 99) < s_corruptPct)
            {
                // two sequenced statements, matching compat.c: index draw first,
                // then bit draw
                int corruptIndex = RngInt(0, bytes - 1);
                int corruptBit = RngInt(0, 7);
                data[corruptIndex] ^= (byte)(1 << corruptBit);
            }

            int copies = (s_duplicatePct > 0 && RngInt(0, 99) < s_duplicatePct) ? 2 : 1;
            for (int c = 0; c < copies; c++)
            {
                if (s_hexDumpPayloads)
                    s_out.Write($"R {Fnv1a64(data.AsSpan(0, bytes)):x16} {bytes}\n");
                to.ReceivePacket(data.AsSpan(0, bytes));
            }
        }

        link.Clear();
    }

    private static void ScenarioTransmit(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)
    {
        if (!s_quiet)
            s_out.Write($"T {(id == 0 ? 'A' : 'B')} {sequence} {packetData.Length} {Fnv1a64(packetData):x16}\n");
        if (id == 0)
            s_aToB.Queue(packetData);
        else
            s_bToA.Queue(packetData);
    }

    private static bool s_hexDumpPayloads;

    private static bool ScenarioProcess(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)
    {
        if (s_quiet)
            return true;
        bool accept = true;
        if (s_processRejectPct > 0 && RngInt(0, 99) < s_processRejectPct)
            accept = false;
        StringBuilder sb = new StringBuilder(64);
        sb.Append($"P {(id == 0 ? 'A' : 'B')} {sequence} {packetData.Length} {Fnv1a64(packetData):x16} {(accept ? 1 : 0)}");
        if (s_hexDumpPayloads)
        {
            sb.Append(' ');
            AppendHex(sb, packetData);
        }
        sb.Append('\n');
        s_out.Write(sb.ToString());
        return accept;
    }

    private static uint FloatBits(float value)
    {
        return BitConverter.SingleToUInt32Bits(value);
    }

    private static void PrintEndpointState(string tag, Endpoint endpoint)
    {
        StringBuilder sb = new StringBuilder(160);
        sb.Append("C ").Append(tag);
        ReadOnlySpan<ulong> counters = endpoint.Counters;
        for (int i = 0; i < counters.Length; i++)
            sb.Append(' ').Append(counters[i]);
        sb.Append('\n');
        s_out.Write(sb.ToString());

        s_out.Write($"S {tag} {FloatBits(endpoint.Rtt):x8} {FloatBits(endpoint.RttMin):x8} {FloatBits(endpoint.RttMax):x8} {FloatBits(endpoint.RttAvg):x8} " +
                    $"{FloatBits(endpoint.JitterAvgVsMinRtt):x8} {FloatBits(endpoint.JitterMaxVsMinRtt):x8} {FloatBits(endpoint.JitterStddevVsAvgRtt):x8} " +
                    $"{FloatBits(endpoint.PacketLoss):x8} {FloatBits(endpoint.SentBandwidthKbps):x8} {FloatBits(endpoint.ReceivedBandwidthKbps):x8} {FloatBits(endpoint.AckedBandwidthKbps):x8}\n");
    }

    private static void PrintAcks(string tag, Endpoint endpoint)
    {
        StringBuilder sb = new StringBuilder(64);
        sb.Append("A ").Append(tag);
        ReadOnlySpan<ushort> acks = endpoint.GetAcks();
        for (int i = 0; i < acks.Length; i++)
            sb.Append(' ').Append(acks[i]);
        sb.Append('\n');
        s_out.Write(sb.ToString());
    }

    private static int RunScenario(string profile, ulong seed, int iterations)
    {
        switch (profile)
        {
            case "clean":
                // everything arrives, possibly reordered
                break;
            case "lossy":
                s_lossPct = 10;
                s_duplicatePct = 5;
                s_processRejectPct = 2;
                break;
            case "wrap":
                // lossy link, but first both endpoints are quietly warped to
                // sequence ~64900 so the traced phase crosses the 16 bit wrap
                s_lossPct = 10;
                s_duplicatePct = 5;
                s_processRejectPct = 2;
                s_warpSends = 64900;
                break;
            case "hostile":
                s_lossPct = 10;
                s_corruptPct = 20;
                s_duplicatePct = 5;
                s_inject = true;
                s_processRejectPct = 2;
                break;
            default:
                Console.Error.WriteLine($"unknown profile: {profile}");
                return 2;
        }

        RngSeed(seed);

        double time = 100.0;

        s_a = new Endpoint(new EndpointConfig
        {
            Name = "a",
            Id = 0,
            MaxPacketSize = 8000,
            FragmentAbove = 500,
            FragmentSize = 500,
            MaxFragments = 16,
            TransmitPacket = ScenarioTransmit,
            ProcessPacket = ScenarioProcess,
        }, time);

        s_b = new Endpoint(new EndpointConfig
        {
            Name = "b",
            Id = 1,
            MaxPacketSize = 8000,
            FragmentAbove = 500,
            FragmentSize = 500,
            MaxFragments = 16,
            TransmitPacket = ScenarioTransmit,
            ProcessPacket = ScenarioProcess,
        }, time);

        s_out.Write($"SCENARIO {profile} {seed} {iterations}\n");

        byte[] payload = new byte[ScenarioMaxPacketBytes];

        // warp phase: tiny packets, delivered verbatim in queue order, nothing
        // traced, no PRNG draws, no update. identical in compat.c; the traced
        // phase then starts near the sequence wrap.
        if (s_warpSends > 0)
        {
            s_quiet = true;
            byte[] tiny = new byte[1];
            for (int i = 0; i < s_warpSends; i++)
            {
                s_a.SendPacket(tiny);
                s_b.SendPacket(tiny);
                for (int j = 0; j < s_aToB.NumPackets; j++)
                    s_b.ReceivePacket(s_aToB.Data[j].AsSpan(0, s_aToB.Bytes[j]));
                for (int j = 0; j < s_bToA.NumPackets; j++)
                    s_a.ReceivePacket(s_bToA.Data[j].AsSpan(0, s_bToA.Bytes[j]));
                s_aToB.Clear();
                s_bToA.Clear();
                s_a.ClearAcks();
                s_b.ClearAcks();
            }
            s_quiet = false;
        }

        for (int iteration = 0; iteration < iterations; iteration++)
        {
            // one packet per endpoint per iteration. size class draw, then size draw.
            for (int side = 0; side < 2; side++)
            {
                Endpoint endpoint = side == 0 ? s_a : s_b;
                int sizeClass = RngInt(0, 99);
                int payloadBytes;
                if (sizeClass < 50)
                    payloadBytes = RngInt(1, 400);          // unfragmented
                else if (sizeClass < 95)
                    payloadBytes = RngInt(401, 4000);       // fragmented
                else
                    payloadBytes = RngInt(8001, 9000);      // too large: dropped + counted

                ushort sequence = endpoint.NextPacketSequence;
                payload[0] = (byte)(sequence & 0xFF);
                if (payloadBytes > 1)
                    payload[1] = (byte)((sequence >> 8) & 0xFF);
                for (int i = 2; i < payloadBytes; i++)
                    payload[i] = (byte)((i + sequence) % 256);

                endpoint.SendPacket(payload.AsSpan(0, payloadBytes));
            }

            LinkFlush(s_aToB, s_b);
            LinkFlush(s_bToA, s_a);

            if (s_inject)
            {
                for (int side = 0; side < 2; side++)
                {
                    Endpoint endpoint = side == 0 ? s_a : s_b;
                    int injectBytes = RngInt(1, 2000);
                    for (int i = 0; i < injectBytes; i++)
                        payload[i] = (byte)RngInt(0, 255);
                    endpoint.ReceivePacket(payload.AsSpan(0, injectBytes));
                }
            }

            s_a.Update(time);
            s_b.Update(time);

            PrintAcks("A", s_a);
            PrintAcks("B", s_b);

            s_a.ClearAcks();
            s_b.ClearAcks();

            if ((iteration % 100) == 99)
            {
                PrintEndpointState("A", s_a);
                PrintEndpointState("B", s_b);
            }

            time += 0.016;
        }

        s_out.Write("FINAL\n");
        PrintEndpointState("A", s_a);
        PrintEndpointState("B", s_b);

        return 0;
    }

    // ------------------------------------------------------------
    // fragment_window mode
    //
    // Differential pins for the fragment / received-window fix. A lone fragment
    // must not move the received-packet window; only an accepted packet may. The
    // crafted sequences of the C fix's cases A (512), B (32512) and C (an
    // in-order fragmented packet at 0) are fed, each followed by a genuine
    // sequence 0, both to a cold receiver and to one advanced to 1000, with a
    // lone last fragment carrying zero and one payload byte. One line per input,
    // byte for byte identical to compat.c.

    private static bool s_fwDelivered;
    private static ushort s_fwDeliveredSequence;
    private static int s_fwDeliveredLength;

    private static bool FwProcess(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)
    {
        s_fwDelivered = true;
        s_fwDeliveredSequence = sequence;
        s_fwDeliveredLength = packetData.Length;
        return true;
    }

    private static Endpoint FwEndpoint()
    {
        return new Endpoint(new EndpointConfig
        {
            Name = "fragment_window",
            MaxPacketSize = 8000,
            FragmentAbove = 500,
            FragmentSize = 500,
            MaxFragments = 16,
            TransmitPacket = (id, sequence, packetData) => { },
            ProcessPacket = FwProcess,
        }, 100.0);
    }

    // a lone fragment: prefix 1, sequence LE, fragment id, count-1, then payload.
    // fragment 0 embeds the canonical packet header, exactly like the sender.
    private static int FwBuildFragment(byte[] buffer, ushort sequence, int fragmentId, int numFragments, int payloadBytes)
    {
        int p = 0;
        buffer[p++] = 1;
        buffer[p++] = (byte)(sequence & 0xFF);
        buffer[p++] = (byte)(sequence >> 8);
        buffer[p++] = (byte)fragmentId;
        buffer[p++] = (byte)(numFragments - 1);
        if (fragmentId == 0)
            p += Wire.WritePacketHeader(buffer.AsSpan(p), sequence, 0xFFFF, 0);
        for (int i = 0; i < payloadBytes; i++)
            buffer[p++] = (byte)(i + sequence);
        return p;
    }

    private static int FwGenuineBytes(byte[] buffer)
    {
        int h = Wire.WritePacketHeader(buffer, 0, 0xFFFF, 0);
        buffer[h] = 0;
        return h + 1;
    }

    // advance the receiver to sequence 1000 with genuine in-order packets
    private static void FwAdvance(Endpoint endpoint, int count)
    {
        byte[] packet = new byte[16];
        for (int i = 0; i < count; i++)
        {
            int h = Wire.WritePacketHeader(packet, (ushort)i, 0xFFFF, 0);
            packet[h] = 0;
            endpoint.ReceivePacket(packet.AsSpan(0, h + 1));
        }
    }

    private static void FwReport(string label, ushort sequence, bool refused, Endpoint endpoint)
    {
        StringBuilder sb = new StringBuilder(160);
        sb.Append(label).Append(' ').Append(sequence).Append(' ').Append(refused ? "refused" : "accepted").Append(' ').Append(s_fwDelivered ? 1 : 0);
        ReadOnlySpan<ulong> counters = endpoint.Counters;
        for (int i = 0; i < counters.Length; i++)
            sb.Append(' ').Append(counters[i]);
        sb.Append('\n');
        s_out.Write(sb.ToString());
    }

    private static void FwFragmentThenGenuine(string label, Endpoint endpoint, ushort sequence, int fragmentId, int numFragments, int payloadBytes)
    {
        byte[] fragment = new byte[600];
        int fragmentBytes = FwBuildFragment(fragment, sequence, fragmentId, numFragments, payloadBytes);

        ReadOnlySpan<ulong> counters = endpoint.Counters;
        ulong before = counters[9]; // fragments_invalid

        s_fwDelivered = false;
        s_fwDeliveredSequence = 0;
        s_fwDeliveredLength = 0;

        endpoint.ReceivePacket(fragment.AsSpan(0, fragmentBytes));

        bool refused = counters[9] != before;

        byte[] genuine = new byte[16];
        endpoint.ReceivePacket(genuine.AsSpan(0, FwGenuineBytes(genuine)));

        FwReport(label, sequence, refused, endpoint);
    }

    private static void RunFragmentWindow()
    {
        // case A: in-window lone last fragment, then genuine sequence 0
        {
            Endpoint endpoint = FwEndpoint();
            FwFragmentThenGenuine("A", endpoint, 512, 1, 2, 0);
        }

        // case B: out-of-window lone last fragment, then genuine sequence 0
        {
            Endpoint endpoint = FwEndpoint();
            FwFragmentThenGenuine("B", endpoint, 32512, 1, 2, 0);
        }

        // case C: in-order fragmented packet at sequence 0 (500 + 250 = 1.5 x
        // fragment_size), then a genuine sequence 0
        {
            Endpoint endpoint = FwEndpoint();
            byte[] fragment = new byte[600];
            endpoint.ReceivePacket(fragment.AsSpan(0, FwBuildFragment(fragment, 0, 0, 2, 500)));
            endpoint.ReceivePacket(fragment.AsSpan(0, FwBuildFragment(fragment, 0, 1, 2, 250)));
            byte[] genuine = new byte[16];
            endpoint.ReceivePacket(genuine.AsSpan(0, FwGenuineBytes(genuine)));
            FwReport("C", 0, false, endpoint);
        }

        // scan: every boundary sequence as a lone last fragment with zero and one
        // payload byte, cold and advanced to 1000
        ushort[] sequences =
        {
            0, 1, 255, 256, 511, 512, 513, 32511, 32512, 32513, 32768, 65280, 65535,
        };

        for (int i = 0; i < sequences.Length; i++)
        {
            for (int advanced = 0; advanced < 2; advanced++)
            {
                for (int payload = 0; payload < 2; payload++)
                {
                    Endpoint endpoint = FwEndpoint();
                    if (advanced != 0)
                        FwAdvance(endpoint, 1000);
                    FwFragmentThenGenuine(advanced != 0 ? "adv" + payload : "cold" + payload, endpoint, sequences[i], 1, 2, payload);
                }
            }
        }
    }

    // ------------------------------------------------------------
    // config_refusal mode
    //
    // Differential pins for the config validation carried from the C reference
    // (R3: sequence-buffer sizes are powers of two no larger than 16384; R4: the
    // header-plus-packet bound is computed in 64 bits). One line per input, byte
    // for byte identical to c/compat.c: `<field> <value> <created|refused>`, and
    // for a created config an `ack <n>` line after a one-byte send is acked by a
    // peer through the in-memory callbacks.

    private static Endpoint? s_cfgSender;
    private static Endpoint? s_cfgReceiver;

    private static void CfgTransmit(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)
    {
        if (id == 0)
            s_cfgReceiver!.ReceivePacket(packetData);
        else
            s_cfgSender!.ReceivePacket(packetData);
    }

    private static bool CfgProcess(ulong id, ushort sequence, ReadOnlySpan<byte> packetData) => true;

    private static readonly string[] CfgFieldNames =
    {
        "sent_packets_buffer_size",
        "received_packets_buffer_size",
        "fragment_reassembly_buffer_size",
    };

    private static void CfgSetField(EndpointConfig config, int field, int value)
    {
        if (field == 0)
            config.SentPacketsBufferSize = value;
        else if (field == 1)
            config.ReceivedPacketsBufferSize = value;
        else
            config.FragmentReassemblyBufferSize = value;
    }

    private static void CfgAckTest(int field, int value)
    {
        EndpointConfig senderConfig = new EndpointConfig { Name = "sender", Id = 0, TransmitPacket = CfgTransmit, ProcessPacket = CfgProcess };
        CfgSetField(senderConfig, field, value);
        EndpointConfig receiverConfig = new EndpointConfig { Name = "receiver", Id = 1, TransmitPacket = CfgTransmit, ProcessPacket = CfgProcess };

        s_cfgSender = new Endpoint(senderConfig, 100.0);
        s_cfgReceiver = new Endpoint(receiverConfig, 100.0);

        byte[] packet = new byte[1];

        s_cfgSender.SendPacket(packet);
        s_cfgSender.Update(100.1);
        s_cfgReceiver.Update(100.1);
        s_cfgReceiver.SendPacket(packet);
        s_cfgSender.Update(100.1);

        s_out.Write($"ack {s_cfgSender.GetAcks().Length}\n");
    }

    private static void RunConfigRefusal()
    {
        int[] values = { 0, 1, 2, 3, 100, 255, 256, 257, 16383, 16384, 16385, 32768, 65535, 65536, 65537 };

        for (int field = 0; field < 3; field++)
        {
            foreach (int value in values)
            {
                EndpointConfig config = new EndpointConfig { Name = "cfg", TransmitPacket = CfgTransmit, ProcessPacket = CfgProcess };
                CfgSetField(config, field, value);

                try
                {
                    _ = new Endpoint(config, 0.0);
                    s_out.Write($"{CfgFieldNames[field]} {value} created\n");
                    CfgAckTest(field, value);
                }
                catch (ArgumentException)
                {
                    s_out.Write($"{CfgFieldNames[field]} {value} refused\n");
                }
            }
        }

        // R4: packet_header_size + max_packet_size + 9 + 5 must not exceed INT_MAX.
        // the three edge configs vary only the header and max packet size, so the
        // fragment-cover bound refuses each before any allocation; that refusal is
        // what the differential pins for these inputs.
        (int header, int max)[] r4 =
        {
            (28, int.MaxValue - 14 - 28),
            (28, int.MaxValue - 14 - 28 + 1),
            (9, int.MaxValue - 23),
        };

        foreach ((int header, int max) in r4)
        {
            EndpointConfig config = new EndpointConfig { Name = "cfg", TransmitPacket = CfgTransmit, ProcessPacket = CfgProcess };
            config.PacketHeaderSize = header;
            config.MaxPacketSize = max;

            try
            {
                _ = new Endpoint(config, 0.0);
                s_out.Write($"header_plus_max {header} {max} created\n");
            }
            catch (ArgumentException)
            {
                s_out.Write($"header_plus_max {header} {max} refused\n");
            }
        }
    }

    // ------------------------------------------------------------
    // hardening mode
    //
    // Differential pins for the hardening carried from the C 1.4.x releases:
    // Reset clears every statistic, the rtt minimum is decided by a sample count
    // (so a minimum of 10000 ms or more is reported), and the reassembly buffer
    // is zeroed. One line per step, byte for byte identical to c/compat.c; every
    // float is printed as its raw 32-bit pattern.

    private static Endpoint? s_hwSender;
    private static Endpoint? s_hwReceiver;
    private static bool s_hwDrop;

    private static void HwTransmit(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)
    {
        if (s_hwDrop)
        {
            s_hwDrop = false;
            return;
        }
        if (id == 0)
            s_hwReceiver!.ReceivePacket(packetData);
        else
            s_hwSender!.ReceivePacket(packetData);
    }

    private static bool HwProcess(ulong id, ushort sequence, ReadOnlySpan<byte> packetData) => true;

    private static void HwPair(double time)
    {
        s_hwSender = new Endpoint(new EndpointConfig { Name = "sender", Id = 0, TransmitPacket = HwTransmit, ProcessPacket = HwProcess }, time);
        s_hwReceiver = new Endpoint(new EndpointConfig { Name = "receiver", Id = 1, TransmitPacket = HwTransmit, ProcessPacket = HwProcess }, time);
    }

    private static void PrintHardeningLine(string step, Endpoint endpoint)
    {
        s_out.Write($"{step} rtt {FloatBits(endpoint.Rtt):x8} rtt_min {FloatBits(endpoint.RttMin):x8} rtt_max {FloatBits(endpoint.RttMax):x8} rtt_avg {FloatBits(endpoint.RttAvg):x8} jitter_avg {FloatBits(endpoint.JitterAvgVsMinRtt):x8} jitter_max {FloatBits(endpoint.JitterMaxVsMinRtt):x8} jitter_stddev {FloatBits(endpoint.JitterStddevVsAvgRtt):x8} loss {FloatBits(endpoint.PacketLoss):x8} sent_kbps {FloatBits(endpoint.SentBandwidthKbps):x8} received_kbps {FloatBits(endpoint.ReceivedBandwidthKbps):x8} acked_kbps {FloatBits(endpoint.AckedBandwidthKbps):x8}\n");
    }

    private static void RunHardening()
    {
        double time = 100.0;
        HwPair(time);

        byte[] packet = new byte[64];
        for (int i = 0; i < 200; i++)
        {
            for (int j = 0; j < packet.Length; j++)
                packet[j] = (byte)i;

            s_hwDrop = (i % 10 == 0);
            s_hwSender!.SendPacket(packet.AsSpan(0, 8 + (i % 40)));

            time += 0.016;
            s_hwSender.Update(time);
            s_hwReceiver!.Update(time);

            s_hwDrop = (i % 15 == 0);
            s_hwReceiver.SendPacket(packet.AsSpan(0, 8 + ((i * 7) % 40)));

            time += 0.016;
            s_hwSender.Update(time);
            s_hwReceiver.Update(time);

            s_hwSender.ClearAcks();
            s_hwReceiver.ClearAcks();
        }

        PrintHardeningLine("before_reset", s_hwSender!);

        s_hwSender!.Reset();
        s_hwReceiver!.Reset();
        PrintHardeningLine("after_reset", s_hwSender!);

        // the rtt minimum is decided by a sample count, not a sentinel: samples of
        // 10000, 12000 and 20000 ms must report a minimum of 10000, not 0
        time = 100.0;
        HwPair(time);

        byte[] tiny = new byte[8];

        s_hwSender!.SendPacket(tiny);
        time += 10.0;
        s_hwSender.Update(time);
        s_hwReceiver!.Update(time);
        s_hwReceiver.SendPacket(tiny);
        s_hwSender.Update(time);
        s_hwSender.ClearAcks();
        s_hwReceiver.ClearAcks();

        s_hwSender.SendPacket(tiny);
        time += 12.0;
        s_hwSender.Update(time);
        s_hwReceiver.Update(time);
        s_hwReceiver.SendPacket(tiny);
        s_hwSender.Update(time);
        s_hwSender.ClearAcks();
        s_hwReceiver.ClearAcks();

        s_hwSender.SendPacket(tiny);
        time += 20.0;
        s_hwSender.Update(time);
        s_hwReceiver.Update(time);
        s_hwReceiver.SendPacket(tiny);
        s_hwSender.Update(time);
        s_hwSender.ClearAcks();
        s_hwReceiver.ClearAcks();

        PrintHardeningLine("large_rtt", s_hwSender);

        // a fresh endpoint before any sample reports zero everywhere
        HwPair(0.0);
        PrintHardeningLine("fresh", s_hwSender!);
    }

    // ------------------------------------------------------------
    // byte_budget mode
    //
    // Differential pins for the unfinished-reassembly byte budget. A first
    // fragment that would push the live reassembly bytes past the configured
    // budget is refused (counted NUM_FRAGMENTS_INVALID); 0 = unbounded. Each
    // crafted fragment prints one line: step, refused|accepted, the outstanding
    // reassembly bytes, then the eleven counters. byte for byte identical to
    // compat.c.

    private static Endpoint BbEndpoint(int budget)
    {
        return new Endpoint(new EndpointConfig
        {
            Name = "byte_budget",
            MaxPacketSize = 16384,
            FragmentAbove = 500,
            FragmentSize = 1024,
            MaxFragments = 16,
            FragmentReassemblyByteBudget = budget,
            TransmitPacket = (id, sequence, packetData) => { },
            ProcessPacket = (id, sequence, packetData) => true,
        }, 100.0);
    }

    // a fragment: prefix 1, sequence LE, fragment id, count-1, then 0x5A payload.
    // fragment 0 embeds the canonical packet header, exactly like the sender.
    private static int BbBuildFragment(byte[] buffer, ushort sequence, int fragmentId, int numFragments, int payloadBytes)
    {
        int p = 0;
        buffer[p++] = 1;
        buffer[p++] = (byte)(sequence & 0xFF);
        buffer[p++] = (byte)(sequence >> 8);
        buffer[p++] = (byte)fragmentId;
        buffer[p++] = (byte)(numFragments - 1);
        if (fragmentId == 0)
            p += Wire.WritePacketHeader(buffer.AsSpan(p), sequence, 0xFFFF, 0);
        for (int i = 0; i < payloadBytes; i++)
            buffer[p++] = 0x5A;
        return p;
    }

    private static void BbReport(string step, bool refused, Endpoint endpoint)
    {
        StringBuilder sb = new StringBuilder(160);
        sb.Append(step).Append(' ').Append(refused ? "refused" : "accepted").Append(' ').Append(endpoint.OutstandingReassemblyBytes);
        ReadOnlySpan<ulong> counters = endpoint.Counters;
        for (int i = 0; i < counters.Length; i++)
            sb.Append(' ').Append(counters[i]);
        sb.Append('\n');
        s_out.Write(sb.ToString());
    }

    private static void BbRunBudget(int budget, string label)
    {
        Endpoint endpoint = BbEndpoint(budget);
        byte[] fragment = new byte[2048];

        for (int seq = 0; seq < 64; seq++)
        {
            int fragmentBytes = BbBuildFragment(fragment, (ushort)seq, 15, 16, 1024);
            ulong invalidBefore = endpoint.Counters[9];
            endpoint.ReceivePacket(fragment.AsSpan(0, fragmentBytes));
            BbReport(label + "-" + seq, endpoint.Counters[9] != invalidBefore, endpoint);
        }

        byte[] genuine = new byte[16];
        int h = Wire.WritePacketHeader(genuine, 0, 0xFFFF, 0);
        genuine[h] = 0;
        endpoint.ReceivePacket(genuine.AsSpan(0, h + 1));
        BbReport(label + "-genuine", false, endpoint);
    }

    private static void RunByteBudget()
    {
        // 64 crafted last fragments at 64 KB, then the same unbounded (0)
        BbRunBudget(64 * 1024, "b64k");
        BbRunBudget(0, "b0");

        // a complete fragmented packet (1024 + 512 = 1.5 x fragment_size) within the budget
        {
            Endpoint endpoint = BbEndpoint(64 * 1024);
            byte[] fragment = new byte[2048];

            int n0 = BbBuildFragment(fragment, 0, 0, 2, 1024);
            ulong invalidBefore = endpoint.Counters[9];
            endpoint.ReceivePacket(fragment.AsSpan(0, n0));
            BbReport("complete-0", endpoint.Counters[9] != invalidBefore, endpoint);

            int n1 = BbBuildFragment(fragment, 0, 1, 2, 512);
            endpoint.ReceivePacket(fragment.AsSpan(0, n1));
            BbReport("complete-1", false, endpoint);
        }
    }

    private static int Main(string[] args)
    {
        // buffer stdout: the scenario traces are hundreds of thousands of lines
        using StreamWriter buffered = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false), 1 << 20);
        s_out = buffered;

        // debugging aid for gate mismatches: dump full payload hex in P lines
        s_hexDumpPayloads = Environment.GetEnvironmentVariable("RELIABLE_COMPAT_HEX") != null;

        int result;
        if (args.Length >= 1 && args[0] == "vectors")
        {
            RunVectors();
            result = 0;
        }
        else if (args.Length >= 1 && args[0] == "malformed")
        {
            RunMalformed();
            result = 0;
        }
        else if (args.Length >= 1 && args[0] == "fragment_window")
        {
            RunFragmentWindow();
            result = 0;
        }
        else if (args.Length >= 1 && args[0] == "empty_packet")
        {
            RunEmptyPacket();
            result = 0;
        }
        else if (args.Length >= 1 && args[0] == "config_refusal")
        {
            RunConfigRefusal();
            result = 0;
        }
        else if (args.Length >= 1 && args[0] == "hardening")
        {
            RunHardening();
            result = 0;
        }
        else if (args.Length >= 1 && args[0] == "byte_budget")
        {
            RunByteBudget();
            result = 0;
        }
        else if (args.Length >= 4 && args[0] == "scenario")
        {
            result = RunScenario(args[1], ulong.Parse(args[2]), int.Parse(args[3]));
        }
        else
        {
            Console.Error.WriteLine("usage: Compat vectors | Compat malformed | Compat fragment_window | Compat empty_packet | Compat config_refusal | Compat hardening | Compat byte_budget | Compat scenario <clean|lossy|hostile|wrap> <seed> <iterations>");
            result = 2;
        }

        buffered.Flush();
        return result;
    }
}
