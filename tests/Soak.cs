/*
    Soak.cs

    Port of the C repo's fuzz.c: two endpoints exchanging real traffic (mostly
    large enough to fragment) across a simulated link with loss, reordering,
    duplication and single-bit corruption, plus fully random packets injected
    straight into receive. Deterministic seeds instead of time(NULL), and
    invariants checked as it runs:

      - nothing ever throws, no matter what the link does
      - every reported ack is a sequence this endpoint actually sent
      - outstanding pooled reassembly buffers never exceed the reassembly window
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

    private static void TestSoak()
    {
        int iterations = s_shortMode ? 500 : 2500;
        SoakOneSeed(7, iterations);
        SoakOneSeed(42, iterations);
        SoakOneSeed(20260807, iterations);
    }
}
