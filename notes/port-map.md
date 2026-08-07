# Port map: reliable (C) → reliable.cs

Survey of the whole C library (`mas-bandwidth/reliable` @ v1.4.0, reliable.h 248
lines + reliable.c 3064 lines including embedded tests), and the C# shape of every
piece. The wire and the protocol semantics are the C library's, byte-exact where
the wire is concerned; the API is what a careful C# expert would write.

## Public API surface (reliable.h) → C#

| C | C# | Notes |
|---|---|---|
| `reliable_init` / `reliable_term` | — (dropped) | Both are no-ops in C. Nothing to initialize in C#. |
| `struct reliable_config_t` | `sealed class EndpointConfig` | Field-for-field, idiomatic names, defaults inline (see below). |
| `reliable_default_config` | `new EndpointConfig()` | Field initializers carry the exact C defaults. |
| `reliable_endpoint_create` | `new Endpoint(config, time)` | Config is defensively copied at construction (C copies the struct). Validation: see "assert doctrine". |
| `reliable_endpoint_destroy` | — (GC) | No unmanaged resources. Reassembly buffers are pooled; abandoned rentals are ordinary garbage. No IDisposable: nothing to dispose deterministically. |
| `reliable_endpoint_next_packet_sequence` | `Endpoint.NextPacketSequence` (ushort property) | |
| `reliable_endpoint_send_packet` | `Endpoint.SendPacket(ReadOnlySpan<byte>)` | Length > max → counter + drop (same as C). Empty span throws (C asserts `packet_bytes > 0`). Negative length is unrepresentable in C#. |
| `reliable_endpoint_receive_packet` | `Endpoint.ReceivePacket(ReadOnlySpan<byte>)` | Never throws on wire data, no matter how hostile. Empty span throws (C asserts). |
| `reliable_endpoint_free_packet` | — (dropped) | C-allocator API; meaningless under GC. |
| `reliable_endpoint_get_acks` | `Endpoint.GetAcks()` → `ReadOnlySpan<ushort>` | Span over the internal ack array, valid until `ClearAcks`/`Reset`. |
| `reliable_endpoint_clear_acks` | `Endpoint.ClearAcks()` | |
| `reliable_endpoint_reset` | `Endpoint.Reset()` | Clears acks, counters, sequence, all three buffers; returns in-flight reassembly buffers to the pool. |
| `reliable_endpoint_update` | `Endpoint.Update(double time)` | Same stats math, same op order (see "stats math"). |
| `reliable_endpoint_rtt` (+ min/max/avg) | `Rtt`, `RttMin`, `RttMax`, `RttAvg` properties | |
| `reliable_endpoint_jitter_*` | `JitterAvgVsMinRtt`, `JitterMaxVsMinRtt`, `JitterStddevVsAvgRtt` | |
| `reliable_endpoint_packet_loss` | `PacketLoss` | Percent, as in C. |
| `reliable_endpoint_bandwidth` | `SentBandwidthKbps`, `ReceivedBandwidthKbps`, `AckedBandwidthKbps` | Three out-params → three properties. |
| `reliable_endpoint_counters` | `Endpoint.GetCounter(EndpointCounter)` + `Counters` span | `EndpointCounter` enum replaces the `RELIABLE_ENDPOINT_COUNTER_*` defines, same order/indices. |
| `reliable_log_level`, `reliable_set_printf_function` | `ReliableLog.Level`, `ReliableLog.Writer` | Process-wide, like C. Formatting only happens when the level passes, so logging off = zero cost, zero alloc. |
| `reliable_set_assert_function`, `reliable_assert` | `Debug.Assert` | See assert doctrine. |
| `reliable_copy_string` | — (dropped) | C string helper. |
| transmit callback `(ctx,id,seq,data,bytes)` | `delegate void TransmitPacketCallback(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)` | `void* context` dropped: C# delegates close over state. The span is the endpoint's scratch buffer — copy it if you keep it, and do not send on the same endpoint from inside the callback (same contract as C v1.3.0+). |
| process callback returning int | `delegate bool ProcessPacketCallback(ulong id, ushort sequence, ReadOnlySpan<byte> packetData)` | `true` = accept + ack; `false` = reject (not acked, may be redelivered). ReadOnly: C hands out a mutable pointer, C# does not — copy to mutate. |

## Internal machinery (not in reliable.h, external linkage only) → C#

| C | C# |
|---|---|
| `reliable_sequence_buffer_t` + 13 functions | `internal sealed class SequenceBuffer<T> where T : struct` — `T[]` entries + `uint[]` entrySequence, `0xFFFFFFFF` = empty. Cleanup-function variants become an `Action<int>`-style per-slot cleanup hook where needed (fragment reassembly only). `InternalsVisibleTo` for tests. |
| `reliable_write_uint8/16/32/64`, read twins | `BinaryPrimitives` little-endian + a thin internal `Wire` cursor. Explicit LE (no endian detection, no `test_endian`). |
| `reliable_write_packet_header` | `internal static Wire.WritePacketHeader(Span<byte>, ushort seq, ushort ack, uint ackBits) → int` |
| `reliable_read_packet_header` | `Wire.ReadPacketHeader(ReadOnlySpan<byte>, out seq, out ack, out ackBits) → int` (−1 on reject) |
| `reliable_read_fragment_header` | `Wire.ReadFragmentHeader(...) → int` (−1 on reject), same 6 rejection rules |
| `reliable_fragment_reassembly_data_t` | internal struct in the reassembly sequence buffer; `packet_data` is a pooled `byte[]` (`ArrayPool<byte>.Shared`), returned on delivery / eviction / reset. |
| `reliable_sent_packet_data_t` (bitfield: acked:1, packet_bytes:31) | internal struct `{ double Time; uint PacketBytesAndAcked; }` — packed the same way to keep the same 31-bit size arithmetic. |
| `reliable_received_packet_data_t` | internal struct `{ double Time; uint PacketBytes; }` |

## Wire-relevant invariants (must be byte-exact / behavior-exact)

1. **Sequence arithmetic**: 16-bit wrapping. `greater(s1,s2) = (s1>s2 && s1-s2<=32768) || (s1<s2 && s2-s1>32768)`. Every comparison goes through this; never plain int compare.
2. **Packet header** (4–9 bytes): prefix byte — bit0=0 regular; bits1–4 set = that ack_bits byte is PRESENT (absent means 0xFF); bit5 set = ack sent as one-byte `(sequence-ack) mod 65536` difference (≤255), else 16-bit ack. Then LE sequence, ack (1 or 2 bytes), then only the non-0xFF ack_bits bytes, low byte first.
3. **Canonical encoding is mandatory**: one legal encoding per (seq, ack, ack_bits). Enforced on the wire for headers embedded in fragment 0: reassembly re-encodes and rejects on any byte mismatch (length or content).
4. **Fragment header** (exactly 5 bytes): prefix byte == 1 exactly (not just bit0), LE sequence, fragment_id (u8), num_fragments−1 (u8). Fragment 0 alone carries the embedded packet header immediately after. All fragments except the last carry exactly `fragment_size` bytes; the last carries the remainder.
5. **Fragment rejection rules** (read_fragment_header): too short (<5); prefix != 1; num_fragments > max_fragments; fragment_id >= num_fragments; fragment 0: unreadable embedded header, embedded sequence != fragment sequence, non-canonical embedded header; fragment_bytes > fragment_size; non-last fragment with fragment_bytes != fragment_size.
6. **Receive ordering, regular packet**: size gate (`> max_packet_size + 9 + 5` → too-large counter) → packets_received++ → header parse (fail → invalid counter) → payload size gate (`> max_packet_size` → too-large counter) → stale test (`less(seq, buffer.sequence - buffer_size)` → stale counter) → duplicate test (exists → duplicate counter) → process callback → only if accepted: insert into received, advance fragment_reassembly with cleanup (kills any zombie reassembly at that sequence), then walk 32 ack bits.
7. **Ack walk**: for each set bit i, ack_sequence = ack − i; find in sent_packets; if found and not yet acked: only if ack array has room → record ack, acked=1, counter++, rtt sample + smoothing. **If the ack buffer is full the packet stays un-acked** so a later packet can report it (recovery-after-clear semantics).
8. **Fragment receive ordering**: header parse (fail → fragments_invalid) → already-received sequence? silent drop → find reassembly; if absent: insert (stale → fragments_invalid), **advance received_packets window to the fragment's sequence**, allocate `9 + num_fragments*fragment_size`, init; then fragment-count mismatch → fragments_invalid; duplicate fragment → silent drop; store (fragment 0 re-encodes header canonically at buffer offset `9 − header_bytes`); on last fragment received: recursive `ReceivePacket` on `[9−header_bytes, 9+packet_bytes)`, then remove+cleanup. fragments_received++ happens at the very end, after possible delivery.
9. **Send path**: too-large check **before** sequence++ (a too-large send consumes no sequence number). Ack bits generated from received_packets. Sent-packet entry: time, `packet_header_size + packet_bytes` (the config's assumed UDP/IP overhead), acked=0. Non-fragmented: header + memcpy into the persistent transmit buffer, one transmit call. Fragmented: `num_fragments = ceil(bytes / fragment_size)`, per fragment: 5-byte header, fragment 0 += packet header, then payload slice; fragments_sent++ per fragment; one transmit call per fragment. packets_sent++ once at the end.
10. **Sequence buffer insert**: reject if `less(seq, buffer.sequence − num_entries)` (stale); if `greater(seq+1, buffer.sequence)` remove entries `[buffer.sequence, seq]` (with +65536 unwrap; if range ≥ num_entries, clear all) and set `buffer.sequence = seq+1`. Entry index = `seq % num_entries` — note C indexes with the **int** sequence (which can exceed 65535 inside remove_entries after the +65536 unwrap); the modulo results coincide only because the unwrap loop clears by raw index. Replicate the C loop exactly.
11. **generate_ack_bits**: ack = buffer.sequence − 1 (wrapping); bit i set iff `exists(ack − i)` for i in 0..31.
12. **Stats math**: rtt sample = `(float)(time − send_time) * 1000f`; history ring indexed `ack_sequence % rtt_history_size`; smoothing `if (rtt==0 && sample>0) || |rtt−sample| < 0.00001 → rtt=sample else rtt += (sample−rtt)*factor`. Update(): min/max/avg over history (≥0 entries only; min sentinel 10000 → 0); jitter avg/max vs min rtt; stddev = pow(sum/count, 0.5) vs avg rtt; packet loss & the three bandwidths sample `buffer_size/2` entries starting at `(uint)(buffer.sequence − buffer_size + 1 + 0xFFFF)`, smoothing with the |Δ| > 0.00001 branch shape. Keep the op order and float/double promotions identical (differential gate compares these).
13. **Counters**: 11, exact meanings and increment points as in §6–§9. PACKETS_RECEIVED counts header-valid regular packets **before** stale/duplicate checks (and increments even for packets later dropped as stale/dup); fragments do not touch it until reassembly delivers the packet recursively.

## Assert doctrine (from the C repo's CLAUDE.md, mapped to C#)

C: write-side / caller-supplied inputs are assert-only (compiled out in release —
"release builds trust the caller" is the maintainer's design contract); read-side /
wire inputs are always runtime-checked. C# has no compile-out-in-release assert
convention visible to library consumers, and the serialize.cs family doctrine is:
trusted parameters are validated as **API misuse** (throws `ArgumentException` /
`ArgumentOutOfRangeException`), wire data **never throws** — it fails into counters
and drops, exactly like C.

- `EndpointConfig` validation → constructor throws (the C debug asserts' list:
  MaxPacketSize > 0, FragmentAbove > 0, 0 < MaxFragments ≤ 256, FragmentSize > 0,
  buffer sizes > 0, RttHistorySize > 0, callbacks non-null). Once, at construction —
  zero steady-state cost, and it removes the `max_fragments > 256` release-mode UB
  hazard without adding per-packet checks the C design forbids.
- `SendPacket`/`ReceivePacket` with an empty span → `ArgumentException` (C: assert).
- Everything the C library runtime-checks on the receive path is runtime-checked
  here, identically.
- Internal invariants (e.g. sent-buffer insert cannot fail on the send path) →
  `Debug.Assert`.

## Allocation discipline (what must be zero-alloc, measured by GC counters)

C is zero-alloc at steady state everywhere except new fragment reassemblies.
C# mirrors: `SendPacket` (both shapes), `ReceivePacket` (regular packets, and
fragments of an existing reassembly), `Update`, `GetAcks`, `ClearAcks` allocate
nothing (with logging off). New reassemblies rent from `ArrayPool<byte>.Shared`
(returned on delivery/eviction/reset); the reassembly sequence-buffer entries are
structs in a pre-allocated array. Tests measure with
`GC.GetAllocatedBytesForCurrentThread()` like serialize.cs's batch tests, and
tests mirror C's tracking allocator with an internal outstanding-rental counter.

## Test inventory (C suite → C#)

| C test | C# | Notes |
|---|---|---|
| test_endian | — | Irrelevant: explicit LE primitives (same call the serialize.cs port made). |
| test_sequence_buffer | test_sequence_buffer | Internal type, via InternalsVisibleTo. |
| test_generate_ack_bits | test_generate_ack_bits | |
| test_packet_header | test_packet_header | The four corner cases + golden bytes pinned from the C library. |
| test_acks | test_acks | |
| test_acks_packet_loss | test_acks_packet_loss | |
| test_duplicate_packets | test_duplicate_packets | Including the fragment-after-delivery zombie check. |
| test_stale_packets | test_stale_packets | |
| test_ack_buffer_overflow | test_ack_buffer_overflow | Drop + recovery-after-clear. |
| test_packets | test_packets | fragment_above=500 exchange with payload validation. |
| test_large_packets | test_large_packets | max-size packet exactly at the boundary. |
| test_sequence_buffer_rollover | test_sequence_buffer_rollover | 32768+ sends across the wrap. |
| test_fragment_cleanup | test_fragment_cleanup | Tracking allocator → outstanding-rental counter == 0. |
| test_rtt | test_rtt | |
| test_endpoint_reset | test_endpoint_reset | Includes in-flight reassembly freed, no double-free analog. |
| — | test_golden_headers | C#-only: header vectors pinned from the C library (write bytes + read-back). |
| — | test_hostile_* | C#-only: every rejection rule in §5–§6 hit deliberately, counters checked, no exceptions. |
| — | test_zero_allocation | C#-only: GC-counter steady-state proof. |
| — | test_soak (seeded) | C#-only: fuzz.c's lossy/reordering/corrupting/duplicating link, deterministic seeds, invariant checks. |
| fuzz.c, fuzz_target.c | tests soak + hostile script harness | fuzz_target.c's op-script harness mirrored as a seeded hostile test; no persisted corpus exists in the C repo to reuse (OSS-Fuzz corpus lives with Google, not in-repo). |

## Subtle-behavior register (places the C library will bite a careless port)

- `sequence + 1` before `greater(...)` in insert/advance is **uint16** arithmetic — wraps.
- `test_insert` uses `buffer.sequence − (ushort)num_entries` — the cast on num_entries matters when buffer sizes exceed 65535 (uint16 truncation of the size before the subtract).
- `remove_entries` unwraps finish < start by +65536 and then indexes `sequence % num_entries` with the **unwrapped int** — fine because % of the unwrapped value only coincides with the wrapped value when num_entries divides 65536, and C does it anyway: copy the C loop verbatim, don't "fix" it. If the span ≥ num_entries the whole buffer is cleared instead.
- ack==0xFFFF initial state: generate_ack_bits on a fresh buffer yields ack=0xFFFF, ack_bits=0 (sequence 0 − 1 wraps). The very first packet each side sends carries that.
- PACKETS_RECEIVED increments before validity/stale/dup checks (a flood of duplicates moves it).
- A regular packet whose process callback returns false is **not** inserted into received_packets — a retransmit is redelivered. Duplicates are only duplicates once accepted.
- Fragments for a sequence already in received_packets are dropped **silently** (no invalid counter, no received counter).
- A fragment whose reassembly slot insert fails (stale) is fragments_invalid — but its arrival already advanced nothing (advance of received_packets happens only after a successful reassembly insert).
- The reassembly buffer eviction (insert_with_cleanup over an occupied slot) returns the evicted packet's pooled buffer — loss amplification by design; don't "fix".
- num_fragments in store is trusted from the **first** fragment that created the reassembly; later fragments must match exactly.
- fragment_received[256] cannot be overrun because fragment_id is a wire uint8 (≤255) — but num_fragments comes from config-checked wire (≤ max_fragments ≤ 256 via ctor validation).
- The transmit buffer is sized `max(max_packet_size + 9, 5 + 9 + fragment_size)`.
- Sent/received `packet_bytes` recorded for bandwidth include `config.PacketHeaderSize` (assumed IP+UDP overhead), and on receive it is `PacketHeaderSize + packet_bytes` (the **whole datagram** incl. reliable header), while on send it is `PacketHeaderSize + packet_bytes` (payload only, **excluding** the reliable header). Asymmetric in C; keep it.
- Sent-packet entry `packet_bytes` is a 31-bit bitfield in C — value truncation at 2^31 is unreachable (max_packet_size is int-range but sane configs are far below); keep a plain uint plus the acked bit packed to preserve the arithmetic.
- rtt smoothing has the `rtt == 0.0f && rtt_sample > 0.0f` snap branch and the `< 0.00001` equality snap; packet loss & bandwidth use `> 0.00001` on the *other* side (asymmetric: snap-vs-smooth condition order differs between rtt and loss/bandwidth). Copy each verbatim.
- Update() reads `sent_packets->sequence` etc. directly — the buffer's own monotonic sequence, not the endpoint's.
- Receive of a reassembled packet is **recursive** into ReceivePacket — the reassembled buffer must remain valid during the recursion; the pooled array is returned only after the recursive call returns.

## Interop / differential harness plan (the spine)

- `compat/c/compat.c` — small C driver against the real reliable.c (clone pinned
  v1.4.0 in CI, `../reliable` locally): modes `vectors` (header + fragment wire
  sweeps as hex lines — superset of the C repo's tools/conformance/gen_vectors.c),
  `scenario <seed> <iters> <profile>` (endpoint pair over a deterministic
  scripted link — shared xorshift64* PRNG, loss/reorder/duplication/corruption
  decisions in identical draw order — emitting a trace of every transmit (FNV-1a),
  every processed packet, per-iteration acks, final counters and stats bits).
- `compat/Compat.cs` — the same modes implemented on the C# endpoint, emitting the
  identical trace format.
- `scripts/interop.sh` — builds the C driver, runs both sides across the modes and
  seeds, diffs the outputs. Byte identity of traces is the gate. Clean-link,
  lossy, and hostile (corrupting) profiles; a long-run soak profile is the same
  machinery with more iterations.
- Golden pins: a subset of the `vectors` output is frozen into Tests.cs so the C#
  suite alone (no C build) still pins the wire.
