# Red-team brief: reliable.cs

You are attacking the C# port of mas-bandwidth/reliable. This document tells you
what the port claims and how to run it. It deliberately contains no design
rationale — come in cold and try to break the claims.

Reference implementation: `mas-bandwidth/reliable` at tag `v1.4.0` (clone it
next to this repo as `../reliable`). Normative wire spec: `STANDARD.md`
(vendored verbatim from the C repo). Where this port and the C library disagree
on wire bytes or observable protocol behavior, the port is wrong, with the
API-shape exceptions listed in README ("Where the C# API deliberately differs").

## The public API surface

Namespace `Reliable`, assembly `src/Reliable.csproj` (net8.0 + net10.0):

- `sealed class Endpoint`
  - `Endpoint(EndpointConfig config, double time)`
  - `ushort NextPacketSequence`
  - `void SendPacket(ReadOnlySpan<byte> packetData)`
  - `void ReceivePacket(ReadOnlySpan<byte> packetData)`
  - `ReadOnlySpan<ushort> GetAcks()` / `void ClearAcks()`
  - `void Reset()`
  - `void Update(double time)`
  - stats properties: `Rtt`, `RttMin`, `RttMax`, `RttAvg`, `JitterAvgVsMinRtt`,
    `JitterMaxVsMinRtt`, `JitterStddevVsAvgRtt`, `PacketLoss`,
    `SentBandwidthKbps`, `ReceivedBandwidthKbps`, `AckedBandwidthKbps`
  - `ReadOnlySpan<ulong> Counters`, `ulong GetCounter(EndpointCounter)`,
    `const int NumCounters`
- `sealed class EndpointConfig` — all fields public, defaults =
  `reliable_default_config`
- `enum EndpointCounter` (11 values, same indices as `RELIABLE_ENDPOINT_COUNTER_*`)
- `delegate void TransmitPacketCallback(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)`
- `delegate bool ProcessPacketCallback(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)`
- `static class ReliableLog` (`Level`, `Writer`), `enum ReliableLogLevel`

Internal machinery (`SequenceBuffer<T>`, `Wire`, endpoint internals) is visible
to the `Reliable.Tests` and `Reliable.Compat` assemblies via InternalsVisibleTo.

## The claims to falsify

Wire:

1. `Wire.WritePacketHeader` output is byte-identical to
   `reliable_write_packet_header` for every `(sequence, ack, ack_bits)` triple.
2. Fragment emission (count, sizes, headers, embedded header placement) is
   byte-identical to the C library for every payload size and config.
3. Header and fragment parsing accepts exactly what the C parser accepts and
   rejects exactly what it rejects, including the canonical-encoding rule for
   headers embedded in fragment 0.

Behavior:

4. For any sequence of `SendPacket` / `ReceivePacket` / `Update` / `ClearAcks`
   calls with any byte inputs, the observable behavior (transmitted bytes,
   delivered packets and their payload bytes, ack lists, all 11 counters, and
   the smoothed stats bit for bit) is identical to the C library driven with the
   same sequence.
5. `ReceivePacket` never throws, whatever the bytes — malformed, truncated,
   corrupted, oversized, replayed, forged fragments, anything. Failures land in
   counters and the packet is dropped.
6. Exceptions occur only for API misuse: invalid config at construction, empty
   spans on send/receive.
7. Steady state allocates zero GC bytes: `SendPacket` (both shapes),
   `ReceivePacket` (regular packets and fragments of an existing reassembly),
   `Update`, `GetAcks`, `ClearAcks`, with logging at its default level. Only a
   brand-new fragment reassembly rents (from `ArrayPool<byte>.Shared`), and
   every rented buffer is returned on delivery, eviction, and `Reset()`
   (`Endpoint.OutstandingReassemblyBuffers`, internal, tracks the balance).
8. Sequence arithmetic wraps at 16 bits everywhere; behavior across the 65535→0
   boundary matches the C library, including stale/duplicate windows and
   reassembly eviction.
9. Reported acks are exactly the C library's: only sequences actually sent, at
   most once each, ack-buffer overflow drops with later recovery.
10. `Reset()` matches `reliable_endpoint_reset`: sequence, acks, counters and
    tracking buffers cleared, in-flight reassemblies released; smoothed stats
    and rtt history deliberately not cleared.

## How to run everything

```sh
# unit + hostile + soak suite (both TFMs; "short" for a quicker pass)
dotnet run -c Release --project tests/Tests.csproj -f net10.0
DOTNET_ROLL_FORWARD=LatestMajor dotnet run -c Release --project tests/Tests.csproj -f net8.0

# the interop gate against the real C library (defaults to ../reliable)
scripts/interop.sh ../reliable

# individual gate modes, for targeted attacks — both sides must emit
# byte-identical stdout for the same arguments:
cc -O2 -ffp-contract=off -I ../reliable -o /tmp/compat-c compat/c/compat.c ../reliable/reliable.c -lm
/tmp/compat-c vectors
/tmp/compat-c scenario hostile <seed> <iterations>
dotnet run -c Release --project compat/Compat.csproj -- vectors
dotnet run -c Release --project compat/Compat.csproj -- scenario hostile <seed> <iterations>

# RELIABLE_COMPAT_HEX=1 makes both halves dump full payload hex in P (process)
# lines and add R (receive) lines — for localizing any divergence you find
```

`-ffp-contract=off` on the C build is load-bearing for the bit-exact stats
comparison; see README.

The scenario profiles (`clean`, `lossy`, `hostile`, `wrap` — the last crosses
the 16-bit sequence wrap) and their exact PRNG draw
order are specified in comments in `compat/c/compat.c` / `compat/Compat.cs`.
New profiles, seeds, and iteration counts are yours to add — a divergence found
with any seed is a finding.

## Scope notes

- The C library's own scope rules apply: no authentication/anti-spoofing (that
  is netcode's layer), fragmentation amplifies loss by design, continuous
  bidirectional exchange is assumed, endpoints are not thread safe. Breaking
  those is not a finding against the port; diverging from the C library's
  handling of them is.
- The C library's release builds trust the caller on configuration; this port
  validates config at construction instead. A config the C library debug-asserts
  on should throw here — a config accepted here but assert-rejected by the C
  library (or vice versa) is a finding.
- Anything the port's own documentation (README, XML docs) promises that the
  code does not deliver is a finding.
