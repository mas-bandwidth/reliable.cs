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
