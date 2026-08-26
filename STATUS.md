# STATUS — blue phase, end of session 2026-08-07

Where the port stands, exactly. Written for a cold reader.

## Done and verified (all pushed, all green locally; CI green as of run 1)

- **The library** (`src/Reliable.cs`): complete port of reliable.c v1.4.0 —
  packet headers, fragments/reassembly, acks, sequence buffers, counters, rtt/
  jitter/loss/bandwidth stats, reset, logging. Builds net8.0 + net10.0,
  warnings-as-errors, no unsafe, zero dependencies.
- **Interop gate** (`compat/` + `scripts/interop.sh`): C driver against the real
  reliable.c vs the C# twin, shared xorshift64* PRNG, byte-identical stdout
  required. PASSING locally against both `../reliable` HEAD and an exact v1.4.0
  checkout: wire vectors (1551 lines), scenario clean/lossy/hostile (300/500/500
  iters), wrap (2000 iters crossing 65535→0), two 5000-iteration soaks (42k/44k
  trace lines). Stats compared as float BIT PATTERNS — bit-exact.
  `RELIABLE_COMPAT_HEX=1` on both halves dumps payload hex for debugging.
- **Tests** (`tests/`): 24 green on net10.0 and net8.0 — the C suite test for
  test, golden header+fragment pins generated from C v1.4.0, hostile tests for
  every rejection rule, 200k-case parser fuzz, config validation, zero-alloc
  proof (GC counters, 1000 rounds, 0 bytes), fuzz_target.c script harness port,
  3-seed adversarial soak with invariants.
- **CI** (`.github/workflows/ci.yml`): ubuntu+macos test matrix, interop gate
  vs pinned v1.4.0, STANDARD.md spec-sync. Run 1 (commit 97bf22f) completed
  SUCCESS on GitHub; later pushes (notes/wrap profile) had not been checked
  before session end — verify at github.com/mas-bandwidth/reliable.cs/actions.
- **Notes**: `notes/port-map.md` (every C construct → C# shape, wire invariants,
  subtle-behavior register), `notes/red-team-brief.md` (the red team's entry
  point: surfaces, claims to falsify, how to run — no blue rationale).

## Two harness-side findings during gate bring-up (both fixed, neither a library bug)

1. clang FMA contraction drifted smoothed stats by 1 ulp → `-ffp-contract=off`
   is mandatory on the C build (enforced by interop.sh, documented in README).
2. C unspecified evaluation order in `data[rng()] ^= 1 << rng()` desynced the
   corruption draws vs C#'s left-to-right → sequenced explicitly in both halves.

## Judgment calls (details in notes/port-map.md and README "Where the C# API deliberately differs")

- C's debug-only config asserts → construction-time ArgumentException (incl.
  MaxFragments-must-cover-MaxPacketSize, which in C is a send-path assert).
- Empty send/receive spans throw (C asserts); oversized are counted+dropped like C.
- No void* context (closures), no custom allocators (GC + ArrayPool for
  reassembly buffers), no Dispose (nothing unmanaged), ProcessPacket span is
  read-only (C's pointer is mutable).
- `reliable_init/term`, `free_packet`, `copy_string` dropped (meaningless in C#).

## Honest gaps / what's next

- **Red team has not run.** `notes/red-team-brief.md` is their entry point.
  Blue is NOT self-declaring done — Rowan's gate decides.
- No example project (C repo has example.c/stats.c); README carries a usage
  snippet only.
- No netstandard2.1/Unity target (same open deliverable as serialize.cs).
- No performance benchmarks beyond the zero-alloc proof (the schema bench
  harness lives outside this repo, per family practice).
- The C fuzzer's OSS-Fuzz corpus is not in the C repo, so nothing to reuse;
  hostile coverage here is the seeded harnesses + differential soaks.
- CI status of the final two commits (notes + wrap profile) unverified at
  session end — check Actions before trusting main.
- Licensing: AGPL-3.0 now, per Glenn; move to MBSL when ready (README notes it).
