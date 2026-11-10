# reliable.cs status

The C# port is released. `src/Reliable.cs` implements packet headers,
fragmentation and reassembly, acknowledgements, sequence buffers, counters,
statistics, reset, and logging. The library targets net8.0 and net10.0 and
has no third-party package dependencies.

## Verification in this repository

- `dotnet run --project tests/Tests.csproj -c Release -f net10.0` runs the
  unit, hostile-input, and seeded soak tests. The net8.0 target is also in
  the CI test matrix.
- `scripts/interop.sh` compares the C# port with the C reference using wire
  vectors and deterministic clean, lossy, hostile, wrap, and soak scenarios.
  The CI workflow checks out the C reference at v1.4.5 for this gate and
  checks `STANDARD.md` against the upstream specification.
- `TestSequenceBufferRollover` sends 32769 packets and stops before the
  65535→0 sequence wrap. `TestSequenceWrap` sends 65540 packets and crosses
  that wrap; the interop `wrap` profile also exercises it.
- Endpoint construction validates configuration, including sequence-buffer
  sizes and finite smoothing factors in [0,1]. The C# API differences from
  the reference are described in the README and `notes/port-map.md`.

## Scope

The library is licensed under AGPL-3.0. It has no example project or
netstandard2.1/Unity target. New fragment reassemblies rent pooled buffers;
the steady-state allocation check covers the paths named in the test suite.
`notes/post-release-hardening.md` records the remaining large-size arithmetic
review. Historical test results and CI runs should be read from their own
logs rather than treated as a status of the current head.
