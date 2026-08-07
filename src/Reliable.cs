/*
    Reliable.cs

    C# port of the reliable C library (mas-bandwidth/reliable): packet
    acknowledgement, fragmentation/reassembly, and rtt/jitter/packet loss/bandwidth
    estimation over an unreliable datagram transport. It does not retransmit: it
    tells you which packets arrived; what you do about the ones that did not is
    your business.

    The wire format is byte-identical to the C library (see STANDARD.md, vendored
    verbatim from the C repo) and the protocol state machines match it observable-
    behavior-for-observable-behavior — proven by the interop gate in compat/, which
    runs this code head-to-head against the real reliable.c.

    The API is what a careful C# expert would write, not a transliteration:
    Span<byte> everywhere a C pointer+length was, delegates that close over state
    instead of void* contexts, construction-time config validation instead of
    debug-only asserts, and the GC instead of caller-supplied allocators. Family
    values (shared with serialize.cs): zero third-party dependencies; malicious
    packet data never throws — hostile input fails into counters and is dropped,
    exactly like the C library; exceptions are reserved for API misuse; no unsafe
    code; zero allocation at steady state everywhere the C library is zero-alloc
    (new fragment reassemblies rent from ArrayPool, the one place C mallocs).

    Threading contract (same as C): endpoints are not thread safe — one endpoint
    per thread, or protect each endpoint with your own lock. The log level and
    writer are process-wide.

    Copyright © 2026 Más Bandwidth LLC. Licensed under AGPL-3.0 (see LICENSE);
    intended to move to MBSL when ready. The reference C implementation is
    BSD-3-Clause, © 2017-2026 Más Bandwidth LLC.
*/

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;

namespace Reliable;

// ------------------------------------------------------------------
// callbacks
// ------------------------------------------------------------------

/// <summary>
/// Called to send a packet. <paramref name="packetData"/> is a view over the
/// endpoint's internal scratch buffer: copy it if you keep it, and do not send
/// packets on the <em>same</em> endpoint from inside the callback (the scratch
/// buffer is in use). Sending on a different endpoint is fine.
/// </summary>
/// <param name="id">The endpoint id, so shared callbacks can tell endpoints apart.</param>
/// <param name="sequence">The sequence number of the packet being transmitted.</param>
/// <param name="packetData">The wire bytes to hand to your transport.</param>
public delegate void TransmitPacketCallback(ulong id, ushort sequence, ReadOnlySpan<byte> packetData);

/// <summary>
/// Called when a packet is received. Return <c>true</c> to accept and ack the
/// packet; <c>false</c> to reject it — rejected packets are not acked and may be
/// processed again if they arrive again.
/// </summary>
/// <param name="id">The endpoint id, so shared callbacks can tell endpoints apart.</param>
/// <param name="sequence">The sequence number of the received packet.</param>
/// <param name="packetData">The packet payload. Valid only for the duration of the call: copy it if you keep it.</param>
public delegate bool ProcessPacketCallback(ulong id, ushort sequence, ReadOnlySpan<byte> packetData);

// ------------------------------------------------------------------
// logging
// ------------------------------------------------------------------

/// <summary>Log verbosity, mirroring RELIABLE_LOG_LEVEL_*.</summary>
public enum ReliableLogLevel
{
    /// <summary>No log output (the default).</summary>
    None = 0,
    /// <summary>Errors only.</summary>
    Error = 1,
    /// <summary>Errors and informational messages.</summary>
    Info = 2,
    /// <summary>Everything, including per-packet debug output.</summary>
    Debug = 3,
}

/// <summary>
/// Process-wide log configuration, mirroring reliable_log_level /
/// reliable_set_printf_function. With <see cref="Level"/> at its default of
/// <see cref="ReliableLogLevel.None"/> logging costs nothing and allocates
/// nothing: messages are only formatted after the level check passes.
/// </summary>
public static class ReliableLog
{
    private static readonly Action<string> s_console = Console.Write;

    /// <summary>The process-wide log level. Default: <see cref="ReliableLogLevel.None"/>.</summary>
    public static ReliableLogLevel Level;

    /// <summary>Where log output goes. Null (the default) writes to the console.</summary>
    public static Action<string>? Writer;

    internal static bool ErrorEnabled => Level >= ReliableLogLevel.Error;

    internal static bool DebugEnabled => Level >= ReliableLogLevel.Debug;

    internal static void Write(string message)
    {
        (Writer ?? s_console)(message);
    }
}

// ------------------------------------------------------------------
// counters
// ------------------------------------------------------------------

/// <summary>
/// Endpoint counters, mirroring RELIABLE_ENDPOINT_COUNTER_* index for index.
/// </summary>
public enum EndpointCounter
{
    /// <summary>Packets sent (a fragmented packet counts once).</summary>
    NumPacketsSent = 0,
    /// <summary>Regular packets whose header was read off the wire (counted before stale/duplicate rejection).</summary>
    NumPacketsReceived = 1,
    /// <summary>Sent packets acked by the far end.</summary>
    NumPacketsAcked = 2,
    /// <summary>Received packets rejected as outside (behind) the receive window.</summary>
    NumPacketsStale = 3,
    /// <summary>Received packets rejected as unparseable.</summary>
    NumPacketsInvalid = 4,
    /// <summary>Sends dropped because the packet exceeded <see cref="EndpointConfig.MaxPacketSize"/>.</summary>
    NumPacketsTooLargeToSend = 5,
    /// <summary>Receives dropped because the packet exceeded <see cref="EndpointConfig.MaxPacketSize"/>.</summary>
    NumPacketsTooLargeToReceive = 6,
    /// <summary>Fragments transmitted.</summary>
    NumFragmentsSent = 7,
    /// <summary>Fragments received (counted after processing, including the fragment that completes a packet).</summary>
    NumFragmentsReceived = 8,
    /// <summary>Fragments rejected (unparseable header, count mismatch, or stale reassembly).</summary>
    NumFragmentsInvalid = 9,
    /// <summary>Received packets rejected as duplicates of already-accepted packets.</summary>
    NumPacketsDuplicate = 10,
}

// ------------------------------------------------------------------
// config
// ------------------------------------------------------------------

/// <summary>
/// Endpoint configuration, mirroring reliable_config_t. The defaults are the C
/// library's reliable_default_config: sensible for a client/server game
/// exchanging packets at 60HZ. The endpoint copies the configuration at
/// construction; later changes to a config object have no effect.
/// </summary>
public sealed class EndpointConfig
{
    /// <summary>Name of the endpoint, used in log output.</summary>
    public string Name = "endpoint";

    /// <summary>Id of the endpoint, passed to callbacks so shared callbacks can tell endpoints apart.</summary>
    public ulong Id;

    /// <summary>Maximum packet size that can be sent or received (bytes).</summary>
    public int MaxPacketSize = 16 * 1024;

    /// <summary>Packets larger than this many bytes are sent as fragments.</summary>
    public int FragmentAbove = 1024;

    /// <summary>Maximum number of fragments per-packet. 256 max. Must cover MaxPacketSize / FragmentSize.</summary>
    public int MaxFragments = 16;

    /// <summary>Size of each fragment (bytes).</summary>
    public int FragmentSize = 1024;

    /// <summary>Maximum number of acks buffered between calls to <see cref="Endpoint.ClearAcks"/>.</summary>
    public int AckBufferSize = 256;

    /// <summary>Number of sent packets tracked for acks, packet loss and bandwidth stats.</summary>
    public int SentPacketsBufferSize = 256;

    /// <summary>Number of received packets tracked. Also the window for stale and duplicate packet rejection.</summary>
    public int ReceivedPacketsBufferSize = 256;

    /// <summary>Number of packets that can be under reassembly from fragments at the same time.</summary>
    public int FragmentReassemblyBufferSize = 64;

    /// <summary>Exponential smoothing factor for the rtt moving average.</summary>
    public float RttSmoothingFactor = 0.0025f;

    /// <summary>Number of rtt samples kept for min/max/avg rtt and jitter.</summary>
    public int RttHistorySize = 512;

    /// <summary>Exponential smoothing factor for packet loss.</summary>
    public float PacketLossSmoothingFactor = 0.1f;

    /// <summary>Exponential smoothing factor for bandwidth.</summary>
    public float BandwidthSmoothingFactor = 0.1f;

    /// <summary>Assumed network header overhead per-packet, used only for bandwidth stats. 28 = IPv4 + UDP.</summary>
    public int PacketHeaderSize = 28;

    /// <summary>Called to send a packet. Required.</summary>
    public TransmitPacketCallback? TransmitPacket;

    /// <summary>Called when a packet is received. Required.</summary>
    public ProcessPacketCallback? ProcessPacket;
}

// ------------------------------------------------------------------
// sequence arithmetic
// ------------------------------------------------------------------

internal static class Seq
{
    // reliable_sequence_greater_than: 16 bit wrapping comparison. every sequence
    // comparison in the library goes through this; never compare as plain ints.
    internal static bool GreaterThan(ushort s1, ushort s2)
    {
        return ((s1 > s2) && (s1 - s2 <= 32768)) ||
               ((s1 < s2) && (s2 - s1 > 32768));
    }

    internal static bool LessThan(ushort s1, ushort s2)
    {
        return GreaterThan(s2, s1);
    }
}

// ------------------------------------------------------------------
// sequence buffer
// ------------------------------------------------------------------

/*
    reliable_sequence_buffer_t: a rolling ring of entries indexed by 16 bit
    sequence number, entry i occupied iff entrySequence[i % n] == i. 0xFFFFFFFF
    (never a valid 16 bit sequence) marks an empty slot. The C stores entries as
    raw bytes with a stride; here the entry type is a struct type parameter.

    Cleanup callbacks receive the slot index (the C passes the entry pointer);
    only the fragment reassembly buffer uses them, to return pooled buffers.
*/
internal sealed class SequenceBuffer<T> where T : struct
{
    internal const uint EmptySentinel = 0xFFFFFFFF;

    private readonly uint[] _entrySequence;
    private readonly T[] _entries;

    internal ushort Sequence;

    internal SequenceBuffer(int numEntries)
    {
        Debug.Assert(numEntries > 0);
        _entrySequence = new uint[numEntries];
        _entries = new T[numEntries];
        Array.Fill(_entrySequence, EmptySentinel);
    }

    internal int NumEntries => _entrySequence.Length;

    internal ref T EntryAt(int index) => ref _entries[index];

    internal void Reset()
    {
        Sequence = 0;
        Array.Fill(_entrySequence, EmptySentinel);
    }

    // reliable_sequence_buffer_remove_entries. note the C iterates with the
    // *unwrapped* int sequence (finish += 65536) and indexes with its modulo;
    // ported verbatim, including calling cleanup on every slot in range whether
    // occupied or not (the cleanup itself no-ops on empty slots).
    internal void RemoveEntries(int startSequence, int finishSequence, Action<int>? cleanup)
    {
        if (finishSequence < startSequence)
        {
            finishSequence += 65536;
        }
        if (finishSequence - startSequence < NumEntries)
        {
            for (int sequence = startSequence; sequence <= finishSequence; ++sequence)
            {
                cleanup?.Invoke(sequence % NumEntries);
                _entrySequence[sequence % NumEntries] = EmptySentinel;
            }
        }
        else
        {
            for (int i = 0; i < NumEntries; ++i)
            {
                cleanup?.Invoke(i);
                _entrySequence[i] = EmptySentinel;
            }
        }
    }

    // reliable_sequence_buffer_test_insert: false = would be rejected as stale.
    internal bool TestInsert(ushort sequence)
    {
        return !Seq.LessThan(sequence, (ushort)(Sequence - (ushort)NumEntries));
    }

    // reliable_sequence_buffer_insert: returns the slot index, or -1 if stale.
    internal int Insert(ushort sequence)
    {
        if (Seq.LessThan(sequence, (ushort)(Sequence - (ushort)NumEntries)))
        {
            return -1;
        }
        if (Seq.GreaterThan((ushort)(sequence + 1), Sequence))
        {
            RemoveEntries(Sequence, sequence, null);
            Sequence = (ushort)(sequence + 1);
        }
        int index = sequence % NumEntries;
        _entrySequence[index] = sequence;
        return index;
    }

    // reliable_sequence_buffer_advance
    internal void Advance(ushort sequence)
    {
        if (Seq.GreaterThan((ushort)(sequence + 1), Sequence))
        {
            RemoveEntries(Sequence, sequence, null);
            Sequence = (ushort)(sequence + 1);
        }
    }

    // reliable_sequence_buffer_insert_with_cleanup. note the branch order differs
    // from Insert (advance checked first, stale second) — that is the C.
    internal int InsertWithCleanup(ushort sequence, Action<int> cleanup)
    {
        if (Seq.GreaterThan((ushort)(sequence + 1), Sequence))
        {
            RemoveEntries(Sequence, sequence, cleanup);
            Sequence = (ushort)(sequence + 1);
        }
        else if (Seq.LessThan(sequence, (ushort)(Sequence - (ushort)NumEntries)))
        {
            return -1;
        }
        int index = sequence % NumEntries;
        if (_entrySequence[index] != EmptySentinel)
        {
            cleanup(index);
        }
        _entrySequence[index] = sequence;
        return index;
    }

    // reliable_sequence_buffer_advance_with_cleanup
    internal void AdvanceWithCleanup(ushort sequence, Action<int> cleanup)
    {
        if (Seq.GreaterThan((ushort)(sequence + 1), Sequence))
        {
            RemoveEntries(Sequence, sequence, cleanup);
            Sequence = (ushort)(sequence + 1);
        }
    }

    // reliable_sequence_buffer_remove
    internal void Remove(ushort sequence)
    {
        _entrySequence[sequence % NumEntries] = EmptySentinel;
    }

    // reliable_sequence_buffer_remove_with_cleanup
    internal void RemoveWithCleanup(ushort sequence, Action<int> cleanup)
    {
        int index = sequence % NumEntries;
        if (_entrySequence[index] != EmptySentinel)
        {
            _entrySequence[index] = EmptySentinel;
            cleanup(index);
        }
    }

    internal bool Available(ushort sequence)
    {
        return _entrySequence[sequence % NumEntries] == EmptySentinel;
    }

    internal bool Exists(ushort sequence)
    {
        return _entrySequence[sequence % NumEntries] == sequence;
    }

    // reliable_sequence_buffer_find: slot index, or -1 if that sequence is not present.
    internal int Find(ushort sequence)
    {
        int index = sequence % NumEntries;
        return _entrySequence[index] == sequence ? index : -1;
    }

    // reliable_sequence_buffer_at_index: true = slot occupied (by any sequence).
    internal bool OccupiedAtIndex(int index)
    {
        return _entrySequence[index] != EmptySentinel;
    }

    // reliable_sequence_buffer_generate_ack_bits
    internal void GenerateAckBits(out ushort ack, out uint ackBits)
    {
        ack = (ushort)(Sequence - 1);
        ackBits = 0;
        uint mask = 1;
        for (int i = 0; i < 32; ++i)
        {
            ushort sequence = (ushort)(ack - (ushort)i);
            if (Exists(sequence))
            {
                ackBits |= mask;
            }
            mask <<= 1;
        }
    }
}

// ------------------------------------------------------------------
// wire codecs
// ------------------------------------------------------------------

/*
    The packet header and fragment header codecs, byte-identical to
    reliable_write_packet_header / reliable_read_packet_header /
    reliable_read_fragment_header. All multi-byte integers little-endian,
    explicitly (no endian detection: BinaryPrimitives is LE by construction here).

    Read functions return the number of bytes consumed, or -1 to reject —
    rejection is the only failure mode; nothing on this path throws, no matter
    how hostile the bytes.
*/
internal static class Wire
{
    internal const int MaxPacketHeaderBytes = 9;   // RELIABLE_MAX_PACKET_HEADER_BYTES
    internal const int FragmentHeaderBytes = 5;    // RELIABLE_FRAGMENT_HEADER_BYTES

    internal static int WritePacketHeader(Span<byte> packetData, ushort sequence, ushort ack, uint ackBits)
    {
        int p = 0;

        byte prefixByte = 0;

        if ((ackBits & 0x000000FFu) != 0x000000FFu)
        {
            prefixByte |= 1 << 1;
        }

        if ((ackBits & 0x0000FF00u) != 0x0000FF00u)
        {
            prefixByte |= 1 << 2;
        }

        if ((ackBits & 0x00FF0000u) != 0x00FF0000u)
        {
            prefixByte |= 1 << 3;
        }

        if ((ackBits & 0xFF000000u) != 0xFF000000u)
        {
            prefixByte |= 1 << 4;
        }

        int sequenceDifference = sequence - ack;
        if (sequenceDifference < 0)
        {
            sequenceDifference += 65536;
        }
        if (sequenceDifference <= 255)
        {
            prefixByte |= 1 << 5;
        }

        packetData[p++] = prefixByte;

        BinaryPrimitives.WriteUInt16LittleEndian(packetData.Slice(p), sequence);
        p += 2;

        if (sequenceDifference <= 255)
        {
            packetData[p++] = (byte)sequenceDifference;
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(packetData.Slice(p), ack);
            p += 2;
        }

        if ((ackBits & 0x000000FFu) != 0x000000FFu)
        {
            packetData[p++] = (byte)(ackBits & 0x000000FFu);
        }

        if ((ackBits & 0x0000FF00u) != 0x0000FF00u)
        {
            packetData[p++] = (byte)((ackBits & 0x0000FF00u) >> 8);
        }

        if ((ackBits & 0x00FF0000u) != 0x00FF0000u)
        {
            packetData[p++] = (byte)((ackBits & 0x00FF0000u) >> 16);
        }

        if ((ackBits & 0xFF000000u) != 0xFF000000u)
        {
            packetData[p++] = (byte)((ackBits & 0xFF000000u) >> 24);
        }

        Debug.Assert(p <= MaxPacketHeaderBytes);

        return p;
    }

    internal static int ReadPacketHeader(string name, ReadOnlySpan<byte> packetData, out ushort sequence, out ushort ack, out uint ackBits)
    {
        sequence = 0;
        ack = 0;
        ackBits = 0;

        int packetBytes = packetData.Length;

        if (packetBytes < 3)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] packet too small for packet header (1)\n");
            return -1;
        }

        int p = 0;

        byte prefixByte = packetData[p++];

        if ((prefixByte & 1) != 0)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] prefix byte does not indicate a regular packet\n");
            return -1;
        }

        sequence = BinaryPrimitives.ReadUInt16LittleEndian(packetData.Slice(p));
        p += 2;

        if ((prefixByte & (1 << 5)) != 0)
        {
            if (packetBytes < 3 + 1)
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] packet too small for packet header (2)\n");
                return -1;
            }
            byte sequenceDifference = packetData[p++];
            ack = (ushort)(sequence - sequenceDifference);
        }
        else
        {
            if (packetBytes < 3 + 2)
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] packet too small for packet header (3)\n");
                return -1;
            }
            ack = BinaryPrimitives.ReadUInt16LittleEndian(packetData.Slice(p));
            p += 2;
        }

        int expectedBytes = 0;
        for (int i = 1; i <= 4; ++i)
        {
            if ((prefixByte & (1 << i)) != 0)
            {
                expectedBytes++;
            }
        }
        if (packetBytes < p + expectedBytes)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] packet too small for packet header (4)\n");
            return -1;
        }

        ackBits = 0xFFFFFFFF;

        if ((prefixByte & (1 << 1)) != 0)
        {
            ackBits &= 0xFFFFFF00;
            ackBits |= packetData[p++];
        }

        if ((prefixByte & (1 << 2)) != 0)
        {
            ackBits &= 0xFFFF00FF;
            ackBits |= (uint)packetData[p++] << 8;
        }

        if ((prefixByte & (1 << 3)) != 0)
        {
            ackBits &= 0xFF00FFFF;
            ackBits |= (uint)packetData[p++] << 16;
        }

        if ((prefixByte & (1 << 4)) != 0)
        {
            ackBits &= 0x00FFFFFF;
            ackBits |= (uint)packetData[p++] << 24;
        }

        return p;
    }

    internal static int ReadFragmentHeader(
        string name,
        ReadOnlySpan<byte> packetData,
        int maxFragments,
        int fragmentSize,
        out int fragmentId,
        out int numFragments,
        out int fragmentBytes,
        out ushort sequence,
        out ushort ack,
        out uint ackBits)
    {
        fragmentId = 0;
        numFragments = 0;
        fragmentBytes = 0;
        sequence = 0;
        ack = 0;
        ackBits = 0;

        int packetBytes = packetData.Length;

        if (packetBytes < FragmentHeaderBytes)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] packet is too small to read fragment header\n");
            return -1;
        }

        int p = 0;

        byte prefixByte = packetData[p++];
        if (prefixByte != 1)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] prefix byte is not a fragment\n");
            return -1;
        }

        sequence = BinaryPrimitives.ReadUInt16LittleEndian(packetData.Slice(p));
        p += 2;
        fragmentId = packetData[p++];
        numFragments = packetData[p++] + 1;

        if (numFragments > maxFragments)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] num fragments {numFragments} outside of range of max fragments {maxFragments}\n");
            return -1;
        }

        if (fragmentId >= numFragments)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] fragment id {fragmentId} outside of range of num fragments {numFragments}\n");
            return -1;
        }

        fragmentBytes = packetBytes - FragmentHeaderBytes;

        if (fragmentId == 0)
        {
            int packetHeaderBytes = ReadPacketHeader(
                name,
                packetData.Slice(FragmentHeaderBytes),
                out ushort packetSequence,
                out ushort packetAck,
                out uint packetAckBits);

            if (packetHeaderBytes < 0)
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] bad packet header in fragment\n");
                return -1;
            }

            if (packetSequence != sequence)
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] bad packet sequence in fragment. expected {sequence}, got {packetSequence}\n");
                return -1;
            }

            // the packet header is re-encoded canonically during reassembly, so a
            // non-canonical header would shift where the fragment payload lands.
            // reject it here instead.

            Span<byte> canonicalHeader = stackalloc byte[MaxPacketHeaderBytes];
            int canonicalHeaderBytes = WritePacketHeader(canonicalHeader, packetSequence, packetAck, packetAckBits);
            if (canonicalHeaderBytes != packetHeaderBytes ||
                !canonicalHeader.Slice(0, canonicalHeaderBytes).SequenceEqual(packetData.Slice(FragmentHeaderBytes, canonicalHeaderBytes)))
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] non-canonical packet header in fragment\n");
                return -1;
            }

            fragmentBytes = packetBytes - packetHeaderBytes - FragmentHeaderBytes;
            ack = packetAck;
            ackBits = packetAckBits;
        }

        if (fragmentBytes > fragmentSize)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] fragment bytes {fragmentBytes} > fragment size {fragmentSize}\n");
            return -1;
        }

        if (fragmentId != numFragments - 1 && fragmentBytes != fragmentSize)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{name}] fragment {fragmentId} is {fragmentBytes} bytes, which is not the expected fragment size {fragmentSize}\n");
            return -1;
        }

        return p;
    }
}

// ------------------------------------------------------------------
// endpoint
// ------------------------------------------------------------------

/// <summary>
/// A reliability endpoint, mirroring reliable_endpoint_t. One endpoint per
/// connection: a client has one, a server has one per client slot. Feed
/// <see cref="ReceivePacket"/> every datagram from your socket; call
/// <see cref="SendPacket"/> to send; call <see cref="Update"/> once per frame
/// with the current time; read <see cref="GetAcks"/> and call
/// <see cref="ClearAcks"/> once per frame. Endpoints are not thread safe.
/// </summary>
public sealed class Endpoint
{
    private const int NumCountersInternal = 11;

    internal struct SentPacketData
    {
        public double Time;
        public uint PacketBytes;   // reliable_sent_packet_data_t packs this into 31 bits + a 1 bit
        public bool Acked;         // acked flag; the packing has no wire relevance so plain fields here
    }

    internal struct ReceivedPacketData
    {
        public double Time;
        public uint PacketBytes;
    }

    // 256 received-fragment flags without a per-entry array: the C's
    // uint8_t fragment_received[256] as four inline bit words.
    private struct FragmentReceivedBits
    {
        private ulong _b0, _b1, _b2, _b3;

        public readonly bool Get(int index)
        {
            ulong word = (index >> 6) switch { 0 => _b0, 1 => _b1, 2 => _b2, _ => _b3 };
            return (word & (1ul << (index & 63))) != 0;
        }

        public void Set(int index)
        {
            ulong bit = 1ul << (index & 63);
            switch (index >> 6)
            {
                case 0: _b0 |= bit; break;
                case 1: _b1 |= bit; break;
                case 2: _b2 |= bit; break;
                default: _b3 |= bit; break;
            }
        }

        public void Clear()
        {
            _b0 = 0; _b1 = 0; _b2 = 0; _b3 = 0;
        }
    }

    private struct FragmentReassemblyData
    {
        public int NumFragmentsReceived;
        public int NumFragmentsTotal;
        public byte[]? PacketData;      // rented from ArrayPool; null = no reassembly in this slot
        public int PacketBytes;
        public int PacketHeaderBytes;
        public FragmentReceivedBits FragmentReceived;
    }

    // config, defensively copied at construction (the C copies the struct)
    private readonly string _name;
    private readonly ulong _id;
    private readonly int _maxPacketSize;
    private readonly int _fragmentAbove;
    private readonly int _maxFragments;
    private readonly int _fragmentSize;
    private readonly int _ackBufferSize;
    private readonly int _sentPacketsBufferSize;
    private readonly int _receivedPacketsBufferSize;
    private readonly int _fragmentReassemblyBufferSize;
    private readonly float _rttSmoothingFactor;
    private readonly int _rttHistorySize;
    private readonly float _packetLossSmoothingFactor;
    private readonly float _bandwidthSmoothingFactor;
    private readonly int _packetHeaderSize;
    private readonly TransmitPacketCallback _transmitPacket;
    private readonly ProcessPacketCallback _processPacket;

    private double _time;
    private float _rtt;
    private float _rttMin;
    private float _rttMax;
    private float _rttAvg;
    private float _jitterAvgVsMinRtt;
    private float _jitterMaxVsMinRtt;
    private float _jitterStddevVsAvgRtt;
    private float _packetLoss;
    private float _sentBandwidthKbps;
    private float _receivedBandwidthKbps;
    private float _ackedBandwidthKbps;
    private int _numAcks;
    private readonly ushort[] _acks;
    private ushort _sequence;
    private readonly float[] _rttHistoryBuffer;
    private readonly byte[] _transmitBuffer;
    private readonly SequenceBuffer<SentPacketData> _sentPackets;
    private readonly SequenceBuffer<ReceivedPacketData> _receivedPackets;
    private readonly SequenceBuffer<FragmentReassemblyData> _fragmentReassembly;
    private readonly ulong[] _counters = new ulong[NumCountersInternal];
    private readonly Action<int> _reassemblyCleanup;

    // observability hook for tests, mirroring the C suite's tracking allocator:
    // rented reassembly buffers not yet returned. must be zero when idle.
    internal int OutstandingReassemblyBuffers;

    /// <summary>
    /// Creates an endpoint. The configuration is validated here — the C library's
    /// debug-only asserts are construction-time exceptions in C# — and copied, so
    /// later changes to <paramref name="config"/> have no effect.
    /// </summary>
    /// <param name="config">The endpoint configuration.</param>
    /// <param name="time">The current time in seconds.</param>
    /// <exception cref="ArgumentNullException">A required field is null.</exception>
    /// <exception cref="ArgumentException">A configuration value is out of range.</exception>
    public Endpoint(EndpointConfig config, double time)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (config.Name == null) throw new ArgumentException("config.Name must not be null", nameof(config));
        if (config.MaxPacketSize <= 0) throw new ArgumentException("config.MaxPacketSize must be positive", nameof(config));
        if (config.FragmentAbove <= 0) throw new ArgumentException("config.FragmentAbove must be positive", nameof(config));
        if (config.MaxFragments <= 0 || config.MaxFragments > 256) throw new ArgumentException("config.MaxFragments must be in [1,256]", nameof(config));
        if (config.FragmentSize <= 0) throw new ArgumentException("config.FragmentSize must be positive", nameof(config));
        if (config.AckBufferSize <= 0) throw new ArgumentException("config.AckBufferSize must be positive", nameof(config));
        if (config.SentPacketsBufferSize <= 0) throw new ArgumentException("config.SentPacketsBufferSize must be positive", nameof(config));
        if (config.ReceivedPacketsBufferSize <= 0) throw new ArgumentException("config.ReceivedPacketsBufferSize must be positive", nameof(config));
        if (config.FragmentReassemblyBufferSize <= 0) throw new ArgumentException("config.FragmentReassemblyBufferSize must be positive", nameof(config));
        if (config.RttHistorySize <= 0) throw new ArgumentException("config.RttHistorySize must be positive", nameof(config));
        if (config.TransmitPacket == null) throw new ArgumentNullException(nameof(config), "config.TransmitPacket is required");
        if (config.ProcessPacket == null) throw new ArgumentNullException(nameof(config), "config.ProcessPacket is required");

        // the C library debug-asserts num_fragments <= max_fragments on the send
        // path; the construction-time equivalent is that the largest fragmentable
        // packet must fit in MaxFragments fragments
        if (config.MaxPacketSize > config.FragmentAbove)
        {
            long worstCaseFragments = ((long)config.MaxPacketSize + config.FragmentSize - 1) / config.FragmentSize;
            if (worstCaseFragments > config.MaxFragments)
            {
                throw new ArgumentException(
                    $"config.MaxFragments ({config.MaxFragments}) cannot cover MaxPacketSize ({config.MaxPacketSize}) at FragmentSize ({config.FragmentSize}): worst case is {worstCaseFragments} fragments",
                    nameof(config));
            }
        }

        _name = config.Name;
        _id = config.Id;
        _maxPacketSize = config.MaxPacketSize;
        _fragmentAbove = config.FragmentAbove;
        _maxFragments = config.MaxFragments;
        _fragmentSize = config.FragmentSize;
        _ackBufferSize = config.AckBufferSize;
        _sentPacketsBufferSize = config.SentPacketsBufferSize;
        _receivedPacketsBufferSize = config.ReceivedPacketsBufferSize;
        _fragmentReassemblyBufferSize = config.FragmentReassemblyBufferSize;
        _rttSmoothingFactor = config.RttSmoothingFactor;
        _rttHistorySize = config.RttHistorySize;
        _packetLossSmoothingFactor = config.PacketLossSmoothingFactor;
        _bandwidthSmoothingFactor = config.BandwidthSmoothingFactor;
        _packetHeaderSize = config.PacketHeaderSize;
        _transmitPacket = config.TransmitPacket;
        _processPacket = config.ProcessPacket;

        _time = time;

        _acks = new ushort[_ackBufferSize];
        _sentPackets = new SequenceBuffer<SentPacketData>(_sentPacketsBufferSize);
        _receivedPackets = new SequenceBuffer<ReceivedPacketData>(_receivedPacketsBufferSize);
        _fragmentReassembly = new SequenceBuffer<FragmentReassemblyData>(_fragmentReassemblyBufferSize);
        _rttHistoryBuffer = new float[_rttHistorySize];

        // scratch buffer for outgoing packets, so the send path doesn't allocate.
        // sized for whichever is larger: a regular packet or a fragment
        int transmitBufferSize = _maxPacketSize + Wire.MaxPacketHeaderBytes;
        int fragmentTransmitBufferSize = Wire.FragmentHeaderBytes + Wire.MaxPacketHeaderBytes + _fragmentSize;
        if (fragmentTransmitBufferSize > transmitBufferSize)
        {
            transmitBufferSize = fragmentTransmitBufferSize;
        }
        _transmitBuffer = new byte[transmitBufferSize];

        Array.Fill(_rttHistoryBuffer, -1.0f);

        _reassemblyCleanup = CleanupReassemblySlot;
    }

    // reliable_fragment_reassembly_data_cleanup: return the pooled buffer, if any.
    // called on every slot in a cleanup sweep, occupied or not; empty slots no-op.
    private void CleanupReassemblySlot(int index)
    {
        ref FragmentReassemblyData reassembly = ref _fragmentReassembly.EntryAt(index);
        if (reassembly.PacketData != null)
        {
            ArrayPool<byte>.Shared.Return(reassembly.PacketData);
            reassembly.PacketData = null;
            OutstandingReassemblyBuffers--;
        }
    }

    /// <summary>
    /// The sequence number the next sent packet will have. Use it to map acked
    /// sequence numbers back to the contents of packets you sent.
    /// </summary>
    public ushort NextPacketSequence => _sequence;

    /// <summary>
    /// Sends a packet. The packet is handed to the transmit callback, split into
    /// fragments first if larger than <see cref="EndpointConfig.FragmentAbove"/>.
    /// Packets larger than <see cref="EndpointConfig.MaxPacketSize"/> are dropped
    /// and counted in <see cref="EndpointCounter.NumPacketsTooLargeToSend"/>.
    /// </summary>
    /// <param name="packetData">The packet payload. Must not be empty.</param>
    /// <exception cref="ArgumentException">The payload is empty.</exception>
    public void SendPacket(ReadOnlySpan<byte> packetData)
    {
        if (packetData.IsEmpty)
        {
            throw new ArgumentException("packet data must not be empty", nameof(packetData));
        }

        int packetBytes = packetData.Length;

        if (packetBytes > _maxPacketSize)
        {
            if (ReliableLog.ErrorEnabled) ReliableLog.Write($"[{_name}] packet too large to send. packet is {packetBytes} bytes, maximum is {_maxPacketSize}\n");
            _counters[(int)EndpointCounter.NumPacketsTooLargeToSend]++;
            return;
        }

        ushort sequence = _sequence++;

        _receivedPackets.GenerateAckBits(out ushort ack, out uint ackBits);

        if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] sending packet {sequence}\n");

        int sentPacketIndex = _sentPackets.Insert(sequence);

        Debug.Assert(sentPacketIndex >= 0);

        ref SentPacketData sentPacketData = ref _sentPackets.EntryAt(sentPacketIndex);
        sentPacketData.Time = _time;
        sentPacketData.PacketBytes = (uint)(_packetHeaderSize + packetBytes);
        sentPacketData.Acked = false;

        if (packetBytes <= _fragmentAbove)
        {
            // regular packet

            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] sending packet {sequence} without fragmentation\n");

            int packetHeaderBytes = Wire.WritePacketHeader(_transmitBuffer, sequence, ack, ackBits);

            packetData.CopyTo(_transmitBuffer.AsSpan(packetHeaderBytes));

            _transmitPacket(_id, sequence, _transmitBuffer.AsSpan(0, packetHeaderBytes + packetBytes));
        }
        else
        {
            // fragmented packet

            Span<byte> packetHeader = stackalloc byte[Wire.MaxPacketHeaderBytes];
            packetHeader.Clear();

            int packetHeaderBytes = Wire.WritePacketHeader(packetHeader, sequence, ack, ackBits);

            int numFragments = (packetBytes / _fragmentSize) + ((packetBytes % _fragmentSize) != 0 ? 1 : 0);

            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] sending packet {sequence} as {numFragments} fragments\n");

            Debug.Assert(numFragments >= 1);
            Debug.Assert(numFragments <= _maxFragments);

            int q = 0;

            for (int fragmentId = 0; fragmentId < numFragments; ++fragmentId)
            {
                Span<byte> fragment = _transmitBuffer;
                int p = 0;

                fragment[p++] = 1;
                BinaryPrimitives.WriteUInt16LittleEndian(fragment.Slice(p), sequence);
                p += 2;
                fragment[p++] = (byte)fragmentId;
                fragment[p++] = (byte)(numFragments - 1);

                if (fragmentId == 0)
                {
                    packetHeader.Slice(0, packetHeaderBytes).CopyTo(fragment.Slice(p));
                    p += packetHeaderBytes;
                }

                int bytesToCopy = _fragmentSize;
                if (q + bytesToCopy > packetBytes)
                {
                    bytesToCopy = packetBytes - q;
                }

                packetData.Slice(q, bytesToCopy).CopyTo(fragment.Slice(p));

                p += bytesToCopy;
                q += bytesToCopy;

                _transmitPacket(_id, sequence, fragment.Slice(0, p));

                _counters[(int)EndpointCounter.NumFragmentsSent]++;
            }
        }

        _counters[(int)EndpointCounter.NumPacketsSent]++;
    }

    /// <summary>
    /// Call this for each packet received from your socket. Valid packets are
    /// passed to the process callback; stale, duplicate and malformed packets are
    /// dropped and counted. Hostile input never throws.
    /// </summary>
    /// <param name="packetData">The received datagram. Must not be empty.</param>
    /// <exception cref="ArgumentException">The datagram is empty.</exception>
    public void ReceivePacket(ReadOnlySpan<byte> packetData)
    {
        if (packetData.IsEmpty)
        {
            throw new ArgumentException("packet data must not be empty", nameof(packetData));
        }

        int packetBytes = packetData.Length;

        if (packetBytes > _maxPacketSize + Wire.MaxPacketHeaderBytes + Wire.FragmentHeaderBytes)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] packet too large to receive. packet is at least {packetBytes - (Wire.MaxPacketHeaderBytes + Wire.FragmentHeaderBytes)} bytes, maximum is {_maxPacketSize}\n");
            _counters[(int)EndpointCounter.NumPacketsTooLargeToReceive]++;
            return;
        }

        byte prefixByte = packetData[0];

        if ((prefixByte & 1) == 0)
        {
            // regular packet

            _counters[(int)EndpointCounter.NumPacketsReceived]++;

            int packetHeaderBytes = Wire.ReadPacketHeader(_name, packetData, out ushort sequence, out ushort ack, out uint ackBits);
            if (packetHeaderBytes < 0)
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] ignoring invalid packet. could not read packet header\n");
                _counters[(int)EndpointCounter.NumPacketsInvalid]++;
                return;
            }

            Debug.Assert(packetHeaderBytes <= packetBytes);

            int packetPayloadBytes = packetBytes - packetHeaderBytes;

            if (packetPayloadBytes > _maxPacketSize)
            {
                if (ReliableLog.ErrorEnabled) ReliableLog.Write($"[{_name}] packet too large to receive. packet is at {packetPayloadBytes} bytes, maximum is {_maxPacketSize}\n");
                _counters[(int)EndpointCounter.NumPacketsTooLargeToReceive]++;
                return;
            }

            if (!_receivedPackets.TestInsert(sequence))
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] ignoring stale packet {sequence}\n");
                _counters[(int)EndpointCounter.NumPacketsStale]++;
                return;
            }

            if (_receivedPackets.Exists(sequence))
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] ignoring duplicate packet {sequence}\n");
                _counters[(int)EndpointCounter.NumPacketsDuplicate]++;
                return;
            }

            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] processing packet {sequence}\n");

            if (_processPacket(_id, sequence, packetData.Slice(packetHeaderBytes)))
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] process packet {sequence} successful\n");

                int receivedPacketIndex = _receivedPackets.Insert(sequence);

                _fragmentReassembly.AdvanceWithCleanup(sequence, _reassemblyCleanup);

                Debug.Assert(receivedPacketIndex >= 0);

                ref ReceivedPacketData receivedPacketData = ref _receivedPackets.EntryAt(receivedPacketIndex);
                receivedPacketData.Time = _time;
                receivedPacketData.PacketBytes = (uint)(_packetHeaderSize + packetBytes);

                for (int i = 0; i < 32; ++i)
                {
                    if ((ackBits & 1) != 0)
                    {
                        ushort ackSequence = (ushort)(ack - (ushort)i);

                        int sentPacketIndex = _sentPackets.Find(ackSequence);

                        if (sentPacketIndex >= 0)
                        {
                            ref SentPacketData sentPacketData = ref _sentPackets.EntryAt(sentPacketIndex);

                            if (!sentPacketData.Acked)
                            {
                                if (_numAcks < _ackBufferSize)
                                {
                                    if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] acked packet {ackSequence}\n");
                                    _acks[_numAcks++] = ackSequence;
                                    _counters[(int)EndpointCounter.NumPacketsAcked]++;
                                    sentPacketData.Acked = true;

                                    float rtt = (float)(_time - sentPacketData.Time) * 1000.0f;

                                    Debug.Assert(rtt >= 0.0);

                                    int index = ackSequence % _rttHistorySize;

                                    _rttHistoryBuffer[index] = rtt;

                                    if ((_rtt == 0.0f && rtt > 0.0f) || Math.Abs(_rtt - rtt) < 0.00001)
                                    {
                                        _rtt = rtt;
                                    }
                                    else
                                    {
                                        _rtt += (rtt - _rtt) * _rttSmoothingFactor;
                                    }
                                }
                                else
                                {
                                    if (ReliableLog.ErrorEnabled) ReliableLog.Write($"[{_name}] ack buffer is full. dropped ack for packet {ackSequence}. make sure you call ClearAcks\n");
                                }
                            }
                        }
                    }
                    ackBits >>= 1;
                }
            }
            else
            {
                if (ReliableLog.ErrorEnabled) ReliableLog.Write($"[{_name}] process packet failed\n");
            }
        }
        else
        {
            // fragment packet

            int fragmentHeaderBytes = Wire.ReadFragmentHeader(
                _name,
                packetData,
                _maxFragments,
                _fragmentSize,
                out int fragmentId,
                out int numFragments,
                out int fragmentBytes,
                out ushort sequence,
                out ushort ack,
                out uint ackBits);

            if (fragmentHeaderBytes < 0)
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] ignoring invalid fragment. could not read fragment header\n");
                _counters[(int)EndpointCounter.NumFragmentsInvalid]++;
                return;
            }

            if (_receivedPackets.Exists(sequence))
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] ignoring fragment {fragmentId} of packet {sequence}. packet already received\n");
                return;
            }

            int reassemblyIndex = _fragmentReassembly.Find(sequence);

            if (reassemblyIndex < 0)
            {
                reassemblyIndex = _fragmentReassembly.InsertWithCleanup(sequence, _reassemblyCleanup);

                if (reassemblyIndex < 0)
                {
                    if (ReliableLog.ErrorEnabled) ReliableLog.Write($"[{_name}] ignoring invalid fragment. could not insert in reassembly buffer (stale)\n");
                    _counters[(int)EndpointCounter.NumFragmentsInvalid]++;
                    return;
                }

                _receivedPackets.Advance(sequence);

                int packetBufferSize = Wire.MaxPacketHeaderBytes + numFragments * _fragmentSize;

                ref FragmentReassemblyData newReassembly = ref _fragmentReassembly.EntryAt(reassemblyIndex);
                newReassembly.NumFragmentsReceived = 0;
                newReassembly.NumFragmentsTotal = numFragments;
                newReassembly.PacketData = ArrayPool<byte>.Shared.Rent(packetBufferSize);
                newReassembly.PacketBytes = 0;
                newReassembly.PacketHeaderBytes = 0;
                newReassembly.FragmentReceived.Clear();
                OutstandingReassemblyBuffers++;
            }

            ref FragmentReassemblyData reassembly = ref _fragmentReassembly.EntryAt(reassemblyIndex);

            if (numFragments != reassembly.NumFragmentsTotal)
            {
                if (ReliableLog.ErrorEnabled) ReliableLog.Write($"[{_name}] ignoring invalid fragment. fragment count mismatch. expected {reassembly.NumFragmentsTotal}, got {numFragments}\n");
                _counters[(int)EndpointCounter.NumFragmentsInvalid]++;
                return;
            }

            if (reassembly.FragmentReceived.Get(fragmentId))
            {
                if (ReliableLog.ErrorEnabled) ReliableLog.Write($"[{_name}] ignoring fragment {fragmentId} of packet {sequence}. fragment already received\n");
                return;
            }

            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] received fragment {fragmentId} of packet {sequence} ({reassembly.NumFragmentsReceived + 1}/{numFragments})\n");

            reassembly.NumFragmentsReceived++;
            reassembly.FragmentReceived.Set(fragmentId);

            StoreFragmentData(ref reassembly, sequence, ack, ackBits, fragmentId, _fragmentSize, packetData.Slice(fragmentHeaderBytes));

            if (reassembly.NumFragmentsReceived == reassembly.NumFragmentsTotal)
            {
                if (ReliableLog.DebugEnabled) ReliableLog.Write($"[{_name}] completed reassembly of packet {sequence}\n");

                // deliver the reassembled packet through the regular path. safe to
                // recurse: the reassembly buffer's own sequence is already past this
                // sequence, so the recursion cannot clean this slot's buffer out
                // from under us (same invariant the C relies on)
                byte[] reassembledPacket = reassembly.PacketData!;
                int start = Wire.MaxPacketHeaderBytes - reassembly.PacketHeaderBytes;
                int length = reassembly.PacketHeaderBytes + reassembly.PacketBytes;

                ReceivePacket(reassembledPacket.AsSpan(start, length));

                _fragmentReassembly.RemoveWithCleanup(sequence, _reassemblyCleanup);
            }

            _counters[(int)EndpointCounter.NumFragmentsReceived]++;
        }
    }

    // reliable_store_fragment_data
    private static void StoreFragmentData(
        ref FragmentReassemblyData reassembly,
        ushort sequence,
        ushort ack,
        uint ackBits,
        int fragmentId,
        int fragmentSize,
        ReadOnlySpan<byte> fragmentData)
    {
        byte[] packetData = reassembly.PacketData!;
        int fragmentBytes = fragmentData.Length;

        if (fragmentId == 0)
        {
            Span<byte> packetHeader = stackalloc byte[Wire.MaxPacketHeaderBytes];
            packetHeader.Clear();

            reassembly.PacketHeaderBytes = Wire.WritePacketHeader(packetHeader, sequence, ack, ackBits);

            packetHeader.Slice(0, reassembly.PacketHeaderBytes)
                .CopyTo(packetData.AsSpan(Wire.MaxPacketHeaderBytes - reassembly.PacketHeaderBytes));

            fragmentData = fragmentData.Slice(reassembly.PacketHeaderBytes);
            fragmentBytes -= reassembly.PacketHeaderBytes;
        }

        if (fragmentId == reassembly.NumFragmentsTotal - 1)
        {
            reassembly.PacketBytes = (reassembly.NumFragmentsTotal - 1) * fragmentSize + fragmentBytes;
        }

        int offset = Wire.MaxPacketHeaderBytes + fragmentId * fragmentSize;
        int endOffset = offset + fragmentBytes;
        int maxSize = Wire.MaxPacketHeaderBytes + reassembly.NumFragmentsTotal * fragmentSize;

        if (fragmentBytes < 0 || endOffset > maxSize)
        {
            if (ReliableLog.DebugEnabled) ReliableLog.Write($"[reliable] invalid fragment size {fragmentBytes} (would write past {endOffset}/{maxSize})\n");
            return;
        }

        fragmentData.CopyTo(packetData.AsSpan(offset));
    }

    /// <summary>
    /// The sequence numbers of sent packets acked since the last
    /// <see cref="ClearAcks"/>. The span is a view over internal state: it is
    /// invalidated by <see cref="ClearAcks"/>, <see cref="Reset"/> and by
    /// receiving more packets.
    /// </summary>
    public ReadOnlySpan<ushort> GetAcks()
    {
        return _acks.AsSpan(0, _numAcks);
    }

    /// <summary>
    /// Clears the ack array. Call this once per-frame after processing acks. If
    /// you don't, the ack buffer fills up and new acks are dropped.
    /// </summary>
    public void ClearAcks()
    {
        _numAcks = 0;
    }

    /// <summary>
    /// Resets the endpoint to its initial state: acks, counters, sequence number
    /// and all tracking buffers are cleared, and in-progress fragment
    /// reassemblies are released. (Like the C library, smoothed stats and the rtt
    /// history are not cleared.)
    /// </summary>
    public void Reset()
    {
        _numAcks = 0;
        _sequence = 0;

        Array.Clear(_acks);
        Array.Clear(_counters);

        for (int i = 0; i < _fragmentReassemblyBufferSize; ++i)
        {
            if (_fragmentReassembly.OccupiedAtIndex(i))
            {
                CleanupReassemblySlot(i);
            }
        }

        _sentPackets.Reset();
        _receivedPackets.Reset();
        _fragmentReassembly.Reset();
    }

    /// <summary>
    /// Updates rtt, jitter, packet loss and bandwidth stats. Call once per-frame
    /// with the current time in seconds.
    /// </summary>
    public void Update(double time)
    {
        _time = time;

        // calculate min and max rtt
        {
            float minRtt = 10000.0f;
            float maxRtt = 0.0f;
            float sumRtt = 0.0f;
            int count = 0;
            for (int i = 0; i < _rttHistorySize; i++)
            {
                float rtt = _rttHistoryBuffer[i];
                if (rtt >= 0.0f)
                {
                    if (rtt < minRtt)
                    {
                        minRtt = rtt;
                    }
                    if (rtt > maxRtt)
                    {
                        maxRtt = rtt;
                    }
                    sumRtt += rtt;
                    count++;
                }
            }
            if (minRtt == 10000.0f)
            {
                minRtt = 0.0f;
            }
            _rttMin = minRtt;
            _rttMax = maxRtt;
            if (count > 0)
            {
                _rttAvg = sumRtt / count;
            }
            else
            {
                _rttAvg = 0.0f;
            }
        }

        // calculate average jitter vs. min rtt
        {
            float sum = 0.0f;
            int count = 0;
            for (int i = 0; i < _rttHistorySize; i++)
            {
                if (_rttHistoryBuffer[i] >= 0.0f)
                {
                    sum += _rttHistoryBuffer[i] - _rttMin;
                    count++;
                }
            }
            if (count > 0)
            {
                _jitterAvgVsMinRtt = sum / count;
            }
            else
            {
                _jitterAvgVsMinRtt = 0.0f;
            }
        }

        // calculate max jitter vs. min rtt
        {
            float max = 0.0f;
            for (int i = 0; i < _rttHistorySize; i++)
            {
                if (_rttHistoryBuffer[i] >= 0.0f)
                {
                    float difference = _rttHistoryBuffer[i] - _rttMin;
                    if (difference > max)
                    {
                        max = difference;
                    }
                }
            }
            _jitterMaxVsMinRtt = max;
        }

        // calculate stddev jitter vs. avg rtt
        {
            float sum = 0.0f;
            int count = 0;
            for (int i = 0; i < _rttHistorySize; i++)
            {
                if (_rttHistoryBuffer[i] >= 0.0f)
                {
                    float deviation = _rttHistoryBuffer[i] - _rttAvg;
                    sum += deviation * deviation;
                    count++;
                }
            }
            if (count > 0)
            {
                _jitterStddevVsAvgRtt = (float)Math.Pow(sum / count, 0.5);
            }
            else
            {
                _jitterStddevVsAvgRtt = 0.0f;
            }
        }

        // calculate packet loss
        {
            uint baseSequence = unchecked((uint)(_sentPackets.Sequence - _sentPacketsBufferSize + 1 + 0xFFFF));
            int numSent = 0;
            int numDropped = 0;
            int numSamples = _sentPacketsBufferSize / 2;
            for (int i = 0; i < numSamples; ++i)
            {
                ushort sequence = unchecked((ushort)(baseSequence + (uint)i));
                int sentPacketIndex = _sentPackets.Find(sequence);
                if (sentPacketIndex >= 0)
                {
                    numSent++;
                    if (!_sentPackets.EntryAt(sentPacketIndex).Acked)
                    {
                        numDropped++;
                    }
                }
            }
            if (numSent > 0)
            {
                float packetLoss = ((float)numDropped) / ((float)numSent) * 100.0f;
                if (Math.Abs(_packetLoss - packetLoss) > 0.00001)
                {
                    _packetLoss += (packetLoss - _packetLoss) * _packetLossSmoothingFactor;
                }
                else
                {
                    _packetLoss = packetLoss;
                }
            }
            else
            {
                _packetLoss = 0.0f;
            }
        }

        // calculate sent bandwidth
        {
            uint baseSequence = unchecked((uint)(_sentPackets.Sequence - _sentPacketsBufferSize + 1 + 0xFFFF));
            int bytesSent = 0;
            double startTime = double.MaxValue;
            double finishTime = 0.0;
            int numSamples = _sentPacketsBufferSize / 2;
            for (int i = 0; i < numSamples; ++i)
            {
                ushort sequence = unchecked((ushort)(baseSequence + (uint)i));
                int sentPacketIndex = _sentPackets.Find(sequence);
                if (sentPacketIndex < 0)
                {
                    continue;
                }
                ref SentPacketData sentPacketData = ref _sentPackets.EntryAt(sentPacketIndex);
                bytesSent += (int)sentPacketData.PacketBytes;
                if (sentPacketData.Time < startTime)
                {
                    startTime = sentPacketData.Time;
                }
                if (sentPacketData.Time > finishTime)
                {
                    finishTime = sentPacketData.Time;
                }
            }
            if (startTime != double.MaxValue && finishTime > startTime)
            {
                float sentBandwidthKbps = (float)(bytesSent / (finishTime - startTime) * 8.0 / 1000.0);
                if (Math.Abs(_sentBandwidthKbps - sentBandwidthKbps) > 0.00001)
                {
                    _sentBandwidthKbps += (sentBandwidthKbps - _sentBandwidthKbps) * _bandwidthSmoothingFactor;
                }
                else
                {
                    _sentBandwidthKbps = sentBandwidthKbps;
                }
            }
        }

        // calculate received bandwidth
        {
            uint baseSequence = unchecked((uint)(_receivedPackets.Sequence - _receivedPacketsBufferSize + 1 + 0xFFFF));
            int bytesReceived = 0;
            double startTime = double.MaxValue;
            double finishTime = 0.0;
            int numSamples = _receivedPacketsBufferSize / 2;
            for (int i = 0; i < numSamples; ++i)
            {
                ushort sequence = unchecked((ushort)(baseSequence + (uint)i));
                int receivedPacketIndex = _receivedPackets.Find(sequence);
                if (receivedPacketIndex < 0)
                {
                    continue;
                }
                ref ReceivedPacketData receivedPacketData = ref _receivedPackets.EntryAt(receivedPacketIndex);
                bytesReceived += (int)receivedPacketData.PacketBytes;
                if (receivedPacketData.Time < startTime)
                {
                    startTime = receivedPacketData.Time;
                }
                if (receivedPacketData.Time > finishTime)
                {
                    finishTime = receivedPacketData.Time;
                }
            }
            if (startTime != double.MaxValue && finishTime > startTime)
            {
                float receivedBandwidthKbps = (float)(bytesReceived / (finishTime - startTime) * 8.0 / 1000.0);
                if (Math.Abs(_receivedBandwidthKbps - receivedBandwidthKbps) > 0.00001)
                {
                    _receivedBandwidthKbps += (receivedBandwidthKbps - _receivedBandwidthKbps) * _bandwidthSmoothingFactor;
                }
                else
                {
                    _receivedBandwidthKbps = receivedBandwidthKbps;
                }
            }
        }

        // calculate acked bandwidth
        {
            uint baseSequence = unchecked((uint)(_sentPackets.Sequence - _sentPacketsBufferSize + 1 + 0xFFFF));
            int bytesSent = 0;
            double startTime = double.MaxValue;
            double finishTime = 0.0;
            int numSamples = _sentPacketsBufferSize / 2;
            for (int i = 0; i < numSamples; ++i)
            {
                ushort sequence = unchecked((ushort)(baseSequence + (uint)i));
                int sentPacketIndex = _sentPackets.Find(sequence);
                if (sentPacketIndex < 0)
                {
                    continue;
                }
                ref SentPacketData sentPacketData = ref _sentPackets.EntryAt(sentPacketIndex);
                if (!sentPacketData.Acked)
                {
                    continue;
                }
                bytesSent += (int)sentPacketData.PacketBytes;
                if (sentPacketData.Time < startTime)
                {
                    startTime = sentPacketData.Time;
                }
                if (sentPacketData.Time > finishTime)
                {
                    finishTime = sentPacketData.Time;
                }
            }
            if (startTime != double.MaxValue && finishTime > startTime)
            {
                float ackedBandwidthKbps = (float)(bytesSent / (finishTime - startTime) * 8.0 / 1000.0);
                if (Math.Abs(_ackedBandwidthKbps - ackedBandwidthKbps) > 0.00001)
                {
                    _ackedBandwidthKbps += (ackedBandwidthKbps - _ackedBandwidthKbps) * _bandwidthSmoothingFactor;
                }
                else
                {
                    _ackedBandwidthKbps = ackedBandwidthKbps;
                }
            }
        }
    }

    /// <summary>Exponentially smoothed moving average rtt, in milliseconds.</summary>
    public float Rtt => _rtt;

    /// <summary>Minimum rtt over the rtt history window, in milliseconds.</summary>
    public float RttMin => _rttMin;

    /// <summary>Maximum rtt over the rtt history window, in milliseconds.</summary>
    public float RttMax => _rttMax;

    /// <summary>Average rtt over the rtt history window, in milliseconds.</summary>
    public float RttAvg => _rttAvg;

    /// <summary>Average jitter relative to minimum rtt, in milliseconds.</summary>
    public float JitterAvgVsMinRtt => _jitterAvgVsMinRtt;

    /// <summary>Maximum jitter relative to minimum rtt, in milliseconds.</summary>
    public float JitterMaxVsMinRtt => _jitterMaxVsMinRtt;

    /// <summary>Standard deviation of jitter relative to average rtt, in milliseconds.</summary>
    public float JitterStddevVsAvgRtt => _jitterStddevVsAvgRtt;

    /// <summary>Smoothed packet loss, as a percentage.</summary>
    public float PacketLoss => _packetLoss;

    /// <summary>Smoothed sent bandwidth, in kilobits per second.</summary>
    public float SentBandwidthKbps => _sentBandwidthKbps;

    /// <summary>Smoothed received bandwidth, in kilobits per second.</summary>
    public float ReceivedBandwidthKbps => _receivedBandwidthKbps;

    /// <summary>Smoothed acked bandwidth, in kilobits per second.</summary>
    public float AckedBandwidthKbps => _ackedBandwidthKbps;

    /// <summary>The number of counters in <see cref="Counters"/>.</summary>
    public const int NumCounters = NumCountersInternal;

    /// <summary>The endpoint counters, indexed by <see cref="EndpointCounter"/>.</summary>
    public ReadOnlySpan<ulong> Counters => _counters;

    /// <summary>Reads a single counter.</summary>
    public ulong GetCounter(EndpointCounter counter) => _counters[(int)counter];

    // internal access for the mirrored C test suite (the C tests reach into
    // endpoint->fragment_reassembly and friends)
    internal SequenceBuffer<SentPacketData> SentPackets => _sentPackets;
    internal SequenceBuffer<ReceivedPacketData> ReceivedPackets => _receivedPackets;
    internal bool FragmentReassemblyExists(ushort sequence) => _fragmentReassembly.Exists(sequence);
}
