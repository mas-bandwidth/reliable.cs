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
        else if (args.Length >= 4 && args[0] == "scenario")
        {
            result = RunScenario(args[1], ulong.Parse(args[2]), int.Parse(args[3]));
        }
        else
        {
            Console.Error.WriteLine("usage: Compat vectors | Compat scenario <clean|lossy|hostile|wrap> <seed> <iterations>");
            result = 2;
        }

        buffered.Flush();
        return result;
    }
}
