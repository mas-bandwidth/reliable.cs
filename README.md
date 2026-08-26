# reliable.cs

**Status: released** — v1.0.0, the first release. Wire and behavior compatibility with the C reference is proven in CI on every push (the "C wire + behavior compatibility" gate).

C# port of the [reliable](https://github.com/mas-bandwidth/reliable) C library:
packet acknowledgement, fragmentation/reassembly, and rtt/jitter/packet loss/
bandwidth estimation over an unreliable datagram transport (UDP). It does not
retransmit: it tells you which packets arrived; what you do about the ones that
did not is your business.

The wire format is byte-identical to the C library — STANDARD.md is vendored
verbatim from the C repo — and the protocol state machines match it observable
behavior for observable behavior. That is proven, not asserted: golden wire
vectors are pinned from the real C library into the test suite, and the interop
gate in `compat/` runs this code head-to-head against the real `reliable.c` —
same scripted scenarios, same shared PRNG, every transmitted byte, every
delivered packet, every ack, every counter and every stat compared bit for bit,
through clean, lossy, hostile (corrupting) and sequence-wrap link profiles
including 5000-iteration differential soaks.

Family values (shared with serialize.cs): zero third-party dependencies,
including test frameworks; hostile wire data never throws — malformed, stale,
duplicate and truncated packets fail into counters and are dropped, exactly like
the C library; exceptions are reserved for API misuse; no unsafe code; zero
allocation at steady state everywhere the C library is zero-alloc (new fragment
reassemblies rent from `ArrayPool`, the one place the C library mallocs).

## Layout

- `src/Reliable.cs` — the whole library, one file (mirrors the C single
  translation unit): `Endpoint`, `EndpointConfig`, `EndpointCounter`, the
  transmit/process callback delegates, `ReliableLog`, plus the internal
  sequence buffer and wire codecs.
- `tests/` — console test runner, no test framework: prints each test name,
  exit code is the verdict. The C suite ported test for test, plus golden wire
  pins generated from the C library, hostile-input tests for every rejection
  rule, a zero-allocation proof, the C repo's fuzz_target.c script harness, and
  a seeded adversarial soak.
- `compat/` — the cross-implementation interop harness: `Compat.csproj` (C#
  half) and `c/compat.c` (C half, built against the real `reliable.c`).
- `scripts/interop.sh` — the interop gate as one runnable command.
- `STANDARD.md` — the wire format spec, vendored verbatim from the C repo
  (CI diffs it against upstream and fails on drift).
- `notes/` — the port map (every C construct → its C# shape, the invariant
  register) and the red-team brief.

## Build and test

```sh
dotnet build src/Reliable.csproj                          # builds net8.0 + net10.0
dotnet run --project tests/Tests.csproj -f net10.0        # add "short" for a quicker pass
dotnet run --project tests/Tests.csproj -f net8.0         # the LTS leg (needs the .NET 8
                                                          # runtime, or DOTNET_ROLL_FORWARD=LatestMajor)
dotnet run --project tests/Tests.csproj -f net10.0 -- golden   # run only tests matching a substring
```

## Interop gate (head-to-head vs the C library)

```sh
scripts/interop.sh path/to/reliable     # defaults to ../reliable
```

Builds `compat/c/compat.c` against the real `reliable.c`, then runs both halves
across wire-vector and scripted-scenario modes and diffs the outputs; any byte
of difference fails. Two requirements the script enforces and CI pins:

- `-ffp-contract=off` on the C build is required, not optional: C# always
  evaluates float expressions strictly, and default clang/gcc on ARM64 contract
  the stats smoothing (`a + b*c`) into fused multiply-adds that drift by 1 ulp
  and fail the bit-exact stats comparison. (The same rule as the serialize.cs
  interop gate.)
- CI pins the C clone to a release tag (`v1.4.0`); bump deliberately, in its
  own commit.

## Using it

```csharp
using Reliable;

var endpoint = new Endpoint(new EndpointConfig
{
    Name = "client",
    TransmitPacket = (id, sequence, packetData) => socket.Send(packetData),
    ProcessPacket = (id, sequence, packetData) => { HandleGamePacket(packetData); return true; },
}, time);

// per frame:
endpoint.SendPacket(payload);                  // fragments automatically above FragmentAbove
endpoint.ReceivePacket(datagram);              // for every datagram off the socket
endpoint.Update(time);
foreach (ushort acked in endpoint.GetAcks()) { /* that packet arrived */ }
endpoint.ClearAcks();
```

The defaults in `EndpointConfig` are the C library's `reliable_default_config`:
sensible for a client/server game exchanging packets at 60HZ. One endpoint per
connection: a client has one, a server has one per client slot.

## Caveats (the C library's, unchanged)

- **The transmit callback must not send packets on the same endpoint** — it is
  called synchronously while the endpoint's transmit scratch buffer is in use.
  Sending from the process callback is fine, as is sending on other endpoints.
- **Acks are dropped once the ack buffer fills** — call `ClearAcks()` once per
  frame. A dropped ack can still be reported by a later packet while it remains
  within the 32-packet ack window.
- **Not thread safe.** Endpoints have no locking, and the log level/writer are
  process-wide. One endpoint per thread, or protect each endpoint with your own
  lock.
- **No authentication, no encryption.** reliable assumes an authenticated,
  encrypted transport beneath it — that is netcode's job (its sister library).
- **Fragmentation amplifies loss by design**: one lost fragment loses the whole
  packet. Callers needing large reliable blocks should build block transfer
  above this rather than sending very large packets.
- **Continuous bidirectional exchange is assumed** (~60HZ both ways): acks
  piggyback on outgoing packets, and there are no keepalives because there are
  never lulls. The rtt/jitter/loss stats are fresh under the same assumption.

## Where the C# API deliberately differs

The wire and the semantics are the C library's; the surface is what a careful
C# programmer would expect. The differences, all recorded in
`notes/port-map.md`:

- `Span<byte>` replaces pointer+length; delegates close over your state, so
  there is no `void* context`; the GC replaces the custom allocator hooks.
- The C library's debug-only configuration asserts are construction-time
  `ArgumentException`s here — validated once, at `new Endpoint(...)`, never
  per packet. That includes the send path's fragment-count assert, checked at
  construction as "MaxFragments must cover MaxPacketSize".
- Empty payloads throw (the C library asserts `packet_bytes > 0`); oversized
  payloads are dropped and counted, exactly like C.
- `ProcessPacket` receives a read-only span (the C callback gets a mutable
  pointer); copy if you need to mutate.
- No `Dispose`: the endpoint owns no unmanaged resources. `Reset()` matches
  `reliable_endpoint_reset` (and like it, does not clear smoothed stats).

## License

This library is licensed AGPL-3.0 (see [LICENSE](LICENSE)).
The reference C implementation is BSD-3-Clause.
