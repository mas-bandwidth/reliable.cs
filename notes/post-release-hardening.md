# Post-release hardening — reliable.cs

From the 2026-08-07 red/blue security review (parsing/reassembly, sequence/ack +
resource-exhaustion, and fidelity lenses). Verdict was **READY** — zero surviving
findings; config validation is stricter than the C's debug asserts. Post-release:

1. **`Reliable.cs:1210` int vs size_t.** `packetBufferSize` is computed as a C# int
   where the C uses size_t. Not attacker-reachable (numFragments capped at 256,
   FragmentSize is host config; overflow needs FragmentSize > ~8MB, which
   construction-time validation and OOM already stop). A checked/long computation or
   an explicit guard removes the last divergence from the reference.

2. **Interop gate proven live in CI** — the `C wire + behavior compatibility` job runs
   the C driver against the C# twin with byte-identical stdout required. Keep green.

## Hardening carried from the C 1.4.x releases

The C library hardened three things after the initial port, and this port carries all
three (C commits on `sprint/reliable-audit-fixes`; the interop differential pins each —
`compat` mode `hardening`, gated by `scripts/interop.sh`):

1. **Reset clears every statistic.** `reliable_endpoint_reset` (C 1.4.2) zeroes rtt,
   rtt_min, rtt_max, rtt_avg, the three jitters, packet loss and the three bandwidths,
   and refills the rtt history with -1. `Endpoint.Reset()` matches: every getter goes
   back to its create-time value, so a recompute after reset does not resurrect stale
   samples.

2. **The rtt minimum is decided by a sample count, not a sentinel.** The old
   `min_rtt == 10000.0f` empty marker reported 0 for a link slow enough to reach it.
   `Endpoint.Update` now tracks the number of valid samples, so a minimum of 10000 ms
   or more is reported (differential step `large_rtt` pins rtt_min == 10000.0f).

3. **The reassembly buffer is zeroed on rent.** C 1.4.5 (PR 66) memsets the rented
   reassembly buffer after it is allocated, as an invariant so a future logic error
   leaks zeros, not stale bytes, into a delivered packet. The port zeroes the requested
   length with `Array.Clear` before the first fragment is stored.

## Decisions recorded here (asked for by the port cards)

- **Bandwidth sums are widened to `long`.** The C reference accumulates the sent /
  received / acked byte sums in `int64_t` (`reliable.c` 1729, 1769, 1811); the first
  port used `int`. With the carried config bound `packet_header_size + max_packet_size
  + 9 + 5 <= INT_MAX` a single recorded packet can approach 2^31 bytes, and the sample
  window (buffer size / 2, up to 8192 entries) can overflow `int`. `Endpoint.Update`
  now accumulates the three byte sums in `long` for exact parity.
- **`SentPacketData.PacketBytes` stays a full `uint`.** The C packs the acked bit and a
  31-bit `packet_bytes` field (`reliable.c` 508-513). With the carried bound the
  recorded `packet_header_size + packet_bytes` never reaches 2^31, so the C's 31-bit
  packing never truncates and a plain `uint` is behaviorally identical; the packing has
  no wire relevance. Documented in `notes/port-map.md`.

