/*
    Soak.cs

    Port of the C repo's fuzz.c: two endpoints exchanging real traffic (mostly
    large enough to fragment) across a simulated link with loss, reordering,
    duplication and single-bit corruption, plus fully random packets injected
    straight into receive. Deterministic seeds instead of time(NULL), and
    invariants checked as it runs:

      - nothing ever throws, no matter what the link does
      - every reported ack is a sequence this endpoint actually sent
      - on the corruption-free leg, delivered payload bytes match what was sent
      - on the corruption-free leg, a sequence is delivered at most once inside
        the active receive window (link duplicates are absorbed)
      - outstanding pooled reassembly buffers never exceed the reassembly window
      - a corruption-free soak crosses the 16 bit sequence wrap (65535 -> 0)
      - a final Reset returns every pooled buffer

    (The cross-implementation differential soak — C and C# in lockstep — lives in
    compat/ and scripts/interop.sh; this is the C#-only robustness soak.)
*/

using System;
using Reliable;

namespace Reliable.Tests;

internal static partial class Tests
{
    private const int SoakMaxPacketBytes = 16 * 1024;
    private const int SoakMaxQueue = 8192;
    private const int SoakSequenceSpace = 65536;
    private const int SoakReceiveWindow = 256;

    private sealed class SoakLink
    {
        public readonly byte[][] Data = new byte[SoakMaxQueue][];
        public readonly int[] Bytes = new int[SoakMaxQueue];
        public int NumPackets;
    }

    private sealed class SoakRng
    {
        private ulong _state;

        public SoakRng(ulong seed)
        {
            _state = seed != 0 ? seed : 0x9E3779B97F4A7C15ul;
        }

        public ulong Next()
        {
            ulong x = _state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            _state = x;
            return unchecked(x * 0x2545F4914F6CDD1Dul);
        }

        public int Int(int a, int b)
        {
            return a + (int)((uint)(Next() >> 32) % (uint)(b - a + 1));
        }
    }

    private sealed class SoakDeliveryTracker
    {
        private readonly bool[] _delivered = new bool[SoakSequenceSpace];
        private ushort _highest;
        private bool _started;

        public long DeliveredCount { get; private set; }

        public void Processed(ushort sequence, string endpoint, ulong seed, int iteration)
        {
            if (!_started)
            {
                _started = true;
                _highest = sequence;
            }
            else if (Seq.GreaterThan(sequence, _highest))
            {
                int advance = (ushort)(sequence - _highest);
                for (int i = 0; i < advance; ++i)
                {
                    _delivered[(ushort)(sequence - SoakReceiveWindow - i)] = false;
                }
                _highest = sequence;
            }

            Check(!_delivered[sequence],
                $"{endpoint} delivered sequence {sequence} more than once inside the receive window (seed {seed}, iteration {iteration})");

            _delivered[sequence] = true;
            DeliveredCount++;
        }
    }

    private static int SoakCleanPayloadSize(ushort sequence)
    {
        if ((sequence & 255) == 0)
        {
            return SoakMaxPacketBytes;
        }
        return 3 + (int)(((uint)sequence * 977u) % 512u);
    }

    private static void SoakFillPayload(Span<byte> payload, ulong senderId, ushort sequence)
    {
        payload[0] = (byte)(0xA0 | (int)senderId);
        payload[1] = (byte)(sequence & 0xFF);
        payload[2] = (byte)(sequence >> 8);
        for (int i = 3; i < payload.Length; ++i)
        {
            payload[i] = (byte)((i * 31 + sequence * 7 + (int)senderId * 131) & 0xFF);
        }
    }

    private static void SoakValidatePayload(ReadOnlySpan<byte> payload, ulong senderId, ushort sequence, string endpoint, ulong seed, int iteration)
    {
        int expectedBytes = SoakCleanPayloadSize(sequence);
        Check(payload.Length == expectedBytes,
            $"{endpoint} delivered a payload of {payload.Length} bytes, expected {expectedBytes} (seed {seed}, iteration {iteration}, sequence {sequence})");
        Check(payload.Length >= 3,
            $"{endpoint} delivered a payload shorter than its header (seed {seed}, iteration {iteration}, sequence {sequence})");
        Check(payload[0] == (byte)(0xA0 | (int)senderId),
            $"{endpoint} delivered payload from the wrong sender (seed {seed}, iteration {iteration}, sequence {sequence})");
        Check(payload[1] == (byte)(sequence & 0xFF) && payload[2] == (byte)(sequence >> 8),
            $"{endpoint} delivered payload for the wrong sequence (seed {seed}, iteration {iteration}, sequence {sequence})");
        for (int i = 3; i < payload.Length; ++i)
        {
            Check(payload[i] == (byte)((i * 31 + sequence * 7 + (int)senderId * 131) & 0xFF),
                $"{endpoint} delivered corrupted payload byte {i} (seed {seed}, iteration {iteration}, sequence {sequence})");
        }
    }

    private static void SoakOneSeed(ulong seed, int iterations)
    {
        SoakRng rng = new SoakRng(seed);

        SoakLink clientToServer = new SoakLink();
        SoakLink serverToClient = new SoakLink();

        Endpoint client = null!;
        Endpoint server = null!;

        // sequences each endpoint has actually sent, for the ack invariant.
        // iteration counts stay far below 65536, so sequences never wrap here.
        bool[] clientSent = new bool[65536];
        bool[] serverSent = new bool[65536];

        EndpointConfig MakeConfig(ulong id, string name)
        {
            return new EndpointConfig
            {
                Name = name,
                Id = id,
                TransmitPacket = (cbId, sequence, packetData) =>
                {
                    SoakLink link = cbId == 0 ? clientToServer : serverToClient;
                    if (link.NumPackets == SoakMaxQueue || packetData.Length <= 0)
                    {
                        return;
                    }
                    link.Data[link.NumPackets] = packetData.ToArray();
                    link.Bytes[link.NumPackets] = packetData.Length;
                    link.NumPackets++;
                },
                ProcessPacket = (cbId, sequence, packetData) => true,
            };
        }

        client = new Endpoint(MakeConfig(0, "client"), 100.0);
        server = new Endpoint(MakeConfig(1, "server"), 100.0);

        void Flush(SoakLink link, Endpoint to)
        {
            // fisher-yates shuffle for reordering
            for (int i = link.NumPackets - 1; i > 0; --i)
            {
                int j = rng.Int(0, i);
                (link.Data[i], link.Data[j]) = (link.Data[j], link.Data[i]);
                (link.Bytes[i], link.Bytes[j]) = (link.Bytes[j], link.Bytes[i]);
            }

            for (int i = 0; i < link.NumPackets; ++i)
            {
                byte[] data = link.Data[i];
                int bytes = link.Bytes[i];

                if (rng.Int(0, 99) < 10)                            // 10% packet loss
                {
                    continue;
                }

                if (rng.Int(0, 99) < 20)                            // 20% single-bit corruption
                {
                    data[rng.Int(0, bytes - 1)] ^= (byte)(1 << rng.Int(0, 7));
                }

                int copies = rng.Int(0, 99) < 5 ? 2 : 1;            // 5% duplication
                for (int c = 0; c < copies; ++c)
                {
                    to.ReceivePacket(data.AsSpan(0, bytes));
                }
            }

            for (int i = 0; i < link.NumPackets; ++i)
            {
                link.Data[i] = null!;
            }
            link.NumPackets = 0;
        }

        byte[] packetData = new byte[SoakMaxPacketBytes];
        double time = 100.0;
        const double deltaTime = 0.1;

        for (int iteration = 0; iteration < iterations; ++iteration)
        {
            // real traffic in both directions (most large enough to fragment)
            {
                clientSent[client.NextPacketSequence] = true;
                int bytes = rng.Int(1, SoakMaxPacketBytes);
                for (int i = 0; i < bytes; ++i)
                {
                    packetData[i] = (byte)rng.Next();
                }
                client.SendPacket(packetData.AsSpan(0, bytes));
            }
            {
                serverSent[server.NextPacketSequence] = true;
                int bytes = rng.Int(1, SoakMaxPacketBytes);
                for (int i = 0; i < bytes; ++i)
                {
                    packetData[i] = (byte)rng.Next();
                }
                server.SendPacket(packetData.AsSpan(0, bytes));
            }

            // deliver queued traffic across the lossy / reordering / corrupting link
            Flush(clientToServer, server);
            Flush(serverToClient, client);

            // inject fully random packets straight into receive (the classic fuzz path)
            {
                int bytes = rng.Int(1, SoakMaxPacketBytes);
                for (int i = 0; i < bytes; ++i)
                {
                    packetData[i] = (byte)rng.Next();
                }
                client.ReceivePacket(packetData.AsSpan(0, bytes));
                server.ReceivePacket(packetData.AsSpan(0, bytes));
            }

            client.Update(time);
            server.Update(time);

            // invariant: every reported ack is a sequence this endpoint sent
            foreach (ushort ack in client.GetAcks())
            {
                Check(clientSent[ack], $"client acked {ack} which was never sent (seed {seed}, iteration {iteration})");
            }
            foreach (ushort ack in server.GetAcks())
            {
                Check(serverSent[ack], $"server acked {ack} which was never sent (seed {seed}, iteration {iteration})");
            }

            client.ClearAcks();
            server.ClearAcks();

            // invariant: pooled reassembly buffers are bounded by the window
            Check(client.OutstandingReassemblyBuffers >= 0 && client.OutstandingReassemblyBuffers <= 64,
                $"client outstanding reassembly buffers out of range (seed {seed}, iteration {iteration})");
            Check(server.OutstandingReassemblyBuffers >= 0 && server.OutstandingReassemblyBuffers <= 64,
                $"server outstanding reassembly buffers out of range (seed {seed}, iteration {iteration})");

            time += deltaTime;
        }

        // invariant: reset returns every pooled buffer
        client.Reset();
        server.Reset();
        Check(client.OutstandingReassemblyBuffers == 0, $"client leaked reassembly buffers (seed {seed})");
        Check(server.OutstandingReassemblyBuffers == 0, $"server leaked reassembly buffers (seed {seed})");
    }

    private static void SoakCleanOneSeed(ulong seed, int iterations, bool expectSequenceWrap = false)
    {
        SoakRng rng = new SoakRng(seed);

        SoakLink clientToServer = new SoakLink();
        SoakLink serverToClient = new SoakLink();

        Endpoint client = null!;
        Endpoint server = null!;

        // sequences each endpoint has actually sent, for the ack invariant. the
        // wrap leg reuses sequence numbers, so an entry stays true once sent.
        bool[] clientSent = new bool[SoakSequenceSpace];
        bool[] serverSent = new bool[SoakSequenceSpace];

        SoakDeliveryTracker clientDelivered = new SoakDeliveryTracker();
        SoakDeliveryTracker serverDelivered = new SoakDeliveryTracker();

        int currentIteration = 0;

        EndpointConfig MakeConfig(ulong id, string name)
        {
            return new EndpointConfig
            {
                Name = name,
                Id = id,
                ReceivedPacketsBufferSize = SoakReceiveWindow,
                TransmitPacket = (cbId, sequence, packetData) =>
                {
                    SoakLink link = cbId == 0 ? clientToServer : serverToClient;
                    if (link.NumPackets == SoakMaxQueue || packetData.Length <= 0)
                    {
                        return;
                    }
                    link.Data[link.NumPackets] = packetData.ToArray();
                    link.Bytes[link.NumPackets] = packetData.Length;
                    link.NumPackets++;
                },
                ProcessPacket = (cbId, sequence, packetData) =>
                {
                    ulong senderId = cbId == 0 ? 1ul : 0ul;
                    string endpoint = cbId == 0 ? "client" : "server";
                    SoakValidatePayload(packetData, senderId, sequence, endpoint, seed, currentIteration);
                    SoakDeliveryTracker tracker = cbId == 0 ? clientDelivered : serverDelivered;
                    tracker.Processed(sequence, endpoint, seed, currentIteration);
                    return true;
                },
            };
        }

        client = new Endpoint(MakeConfig(0, "client"), 100.0);
        server = new Endpoint(MakeConfig(1, "server"), 100.0);

        void Flush(SoakLink link, Endpoint to)
        {
            // fisher-yates shuffle for reordering
            for (int i = link.NumPackets - 1; i > 0; --i)
            {
                int j = rng.Int(0, i);
                (link.Data[i], link.Data[j]) = (link.Data[j], link.Data[i]);
                (link.Bytes[i], link.Bytes[j]) = (link.Bytes[j], link.Bytes[i]);
            }

            for (int i = 0; i < link.NumPackets; ++i)
            {
                byte[] data = link.Data[i];
                int bytes = link.Bytes[i];

                int copies = rng.Int(0, 99) < 5 ? 2 : 1;            // 5% duplication, no loss or corruption
                for (int c = 0; c < copies; ++c)
                {
                    to.ReceivePacket(data.AsSpan(0, bytes));
                }
            }

            for (int i = 0; i < link.NumPackets; ++i)
            {
                link.Data[i] = null!;
            }
            link.NumPackets = 0;
        }

        byte[] packetData = new byte[SoakMaxPacketBytes];
        double time = 100.0;
        const double deltaTime = 0.1;
        const int batch = 16;

        for (int iteration = 0; iteration < iterations; )
        {
            int chunk = Math.Min(batch, iterations - iteration);

            for (int n = 0; n < chunk; ++n)
            {
                currentIteration = iteration + n;

                {
                    ushort sequence = client.NextPacketSequence;
                    clientSent[sequence] = true;
                    int bytes = SoakCleanPayloadSize(sequence);
                    SoakFillPayload(packetData.AsSpan(0, bytes), 0, sequence);
                    client.SendPacket(packetData.AsSpan(0, bytes));
                }
                {
                    ushort sequence = server.NextPacketSequence;
                    serverSent[sequence] = true;
                    int bytes = SoakCleanPayloadSize(sequence);
                    SoakFillPayload(packetData.AsSpan(0, bytes), 1, sequence);
                    server.SendPacket(packetData.AsSpan(0, bytes));
                }
            }

            Flush(clientToServer, server);
            Flush(serverToClient, client);

            client.Update(time);
            server.Update(time);

            // invariant: every reported ack is a sequence this endpoint sent
            foreach (ushort ack in client.GetAcks())
            {
                Check(clientSent[ack], $"client acked {ack} which was never sent (seed {seed}, iteration {currentIteration})");
            }
            foreach (ushort ack in server.GetAcks())
            {
                Check(serverSent[ack], $"server acked {ack} which was never sent (seed {seed}, iteration {currentIteration})");
            }

            client.ClearAcks();
            server.ClearAcks();

            // invariant: pooled reassembly buffers are bounded by the window
            Check(client.OutstandingReassemblyBuffers >= 0 && client.OutstandingReassemblyBuffers <= 64,
                $"client outstanding reassembly buffers out of range (seed {seed}, iteration {currentIteration})");
            Check(server.OutstandingReassemblyBuffers >= 0 && server.OutstandingReassemblyBuffers <= 64,
                $"server outstanding reassembly buffers out of range (seed {seed}, iteration {currentIteration})");

            time += deltaTime;
            iteration += chunk;
        }

        Check(clientDelivered.DeliveredCount == iterations,
            $"client delivered {clientDelivered.DeliveredCount} packets, expected {iterations} (seed {seed})");
        Check(serverDelivered.DeliveredCount == iterations,
            $"server delivered {serverDelivered.DeliveredCount} packets, expected {iterations} (seed {seed})");

        // on the wrap leg, assert the run actually crossed 16 bit sequence space
        // instead of silently finishing short of the boundary
        if (expectSequenceWrap)
        {
            Check(clientDelivered.DeliveredCount > SoakSequenceSpace,
                $"client delivered only {clientDelivered.DeliveredCount} packets, did not cross the sequence wrap (seed {seed})");
            Check(serverDelivered.DeliveredCount > SoakSequenceSpace,
                $"server delivered only {serverDelivered.DeliveredCount} packets, did not cross the sequence wrap (seed {seed})");
        }

        // invariant: reset returns every pooled buffer
        client.Reset();
        server.Reset();
        Check(client.OutstandingReassemblyBuffers == 0, $"client leaked reassembly buffers (seed {seed})");
        Check(server.OutstandingReassemblyBuffers == 0, $"server leaked reassembly buffers (seed {seed})");
    }

    private static void TestSoak()
    {
        int iterations = s_shortMode ? 500 : 2500;
        SoakOneSeed(7, iterations);
        SoakOneSeed(42, iterations);
        SoakOneSeed(20260807, iterations);
        SoakCleanOneSeed(11, iterations);
    }

    private static void TestSoakSequenceWrap()
    {
        int iterations = SoakSequenceSpace + (s_shortMode ? 64 : 1024);
        SoakCleanOneSeed(65537, iterations, expectSequenceWrap: true);
    }
}
