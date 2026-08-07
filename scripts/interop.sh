#!/bin/sh
# The cross-implementation interop gate, runnable as one command. Exit code is
# the verdict.
#
#   scripts/interop.sh [path-to-c-reliable-clone]
#
# Builds the C half of the compat harness against the real reliable.c, then runs
# both halves across the wire-vector mode and the scripted scenario profiles
# (clean, lossy, hostile — the hostile long run is the differential soak), and
# diffs the outputs. Any byte of difference fails the gate.
#
# CI pins the C clone to a release tag (see .github/workflows/ci.yml) and runs
# this with CC=clang; locally the default compiler is fine and the clone may
# track HEAD.

set -e

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
C_RELIABLE="${1:-../reliable}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# -ffp-contract=off is REQUIRED on the C build: C# always evaluates float
# expressions strictly, and default clang/gcc on ARM64 contract the stats
# smoothing (a + b*c) and jitter accumulation into fused multiply-adds, which
# drift by 1 ulp and fail the bit-exact stats comparison. Strict IEEE evaluation
# is the normative behavior (same rule as the serialize.cs interop gate).
echo "== building C compat harness against $C_RELIABLE"
"$CC" -O2 -ffp-contract=off -Wall -Wextra -I "$C_RELIABLE" -o "$WORK/compat-c" compat/c/compat.c "$C_RELIABLE/reliable.c" -lm

echo "== building C# compat harness"
dotnet build -c Release compat/Compat.csproj --nologo -v q

run_cs() {
    dotnet run -c Release --project compat/Compat.csproj --no-build -- "$@"
}

gate() {
    name="$1"; shift
    echo "== $name"
    "$WORK/compat-c" "$@" > "$WORK/c.out"
    run_cs "$@" > "$WORK/cs.out"
    if ! cmp -s "$WORK/c.out" "$WORK/cs.out"; then
        echo "MISMATCH in $name:"
        diff "$WORK/c.out" "$WORK/cs.out" | head -20
        exit 1
    fi
    wc -l < "$WORK/c.out" | awk '{print "   identical ("$1" trace lines)"}'
}

gate "wire vectors"                    vectors
gate "scenario clean    (seed 1)"      scenario clean 1 300
gate "scenario lossy    (seed 2)"      scenario lossy 2 500
gate "scenario hostile  (seed 3)"      scenario hostile 3 500
gate "scenario wrap     (seed 6)"      scenario wrap 6 2000
gate "differential soak (seed 4)"      scenario hostile 4 5000
gate "differential soak (seed 5)"      scenario lossy 5 5000

echo "INTEROP GATE PASSED"
