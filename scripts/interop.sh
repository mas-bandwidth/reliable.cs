#!/bin/sh
# The cross-implementation interop gate, runnable as one command. Exit code is
# the verdict.
#
#   scripts/interop.sh [path-to-c-reliable-clone]
#
# Builds the C half of the compat harness against the real reliable.c, then runs
# both halves across the wire-vector mode, the empty-packet refusal, and the
# scripted scenario profiles (clean, lossy, hostile — the hostile long run is
# the differential soak), and diffs the outputs. Any byte of difference fails
# the gate.
#
# CI pins the C clone to a release tag (see .github/workflows/ci.yml) and runs
# this with CC=clang; locally the default compiler is fine and the clone may
# track HEAD.

set -e

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
C_RELIABLE="${1:-../reliable}"
FP_CONTRACT="${FP_CONTRACT:--ffp-contract=off}"
[ -n "$FP_CONTRACT" ] || { echo "error: FP_CONTRACT must name a strict-float flag (default -ffp-contract=off)" >&2; exit 1; }

# Hermetic when no C reference is reachable: the differential leg needs a real
# checkout of mas-bandwidth/reliable, named by the argument (or the ../reliable
# default). Without one, skip loudly and succeed so local/unit runs are not
# blocked; CI always passes the pinned checkout.
if [ ! -f "$C_RELIABLE/reliable.c" ]; then
    echo "SKIP: no C reference checkout at $C_RELIABLE" >&2
    echo "SKIP: pass one explicitly: scripts/interop.sh <path-to-reliable>" >&2
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# -ffp-contract=off is REQUIRED on the C build: C# always evaluates float
# expressions strictly, and default clang/gcc on ARM64 contract the stats
# smoothing (a + b*c) and jitter accumulation into fused multiply-adds, which
# drift by 1 ulp and fail the bit-exact stats comparison. Strict IEEE evaluation
# is the normative behavior (same rule as the serialize.cs interop gate).
echo "== building C compat harness against $C_RELIABLE"
echo "== C compiler: $CC ($(command -v "$CC")) $("$CC" --version | head -1) $FP_CONTRACT"
# Since 1.4.2 the header codecs are static. The harness calls them, so this
# build copy gives those two functions external linkage and changes nothing else.
sed \
    -e 's/^static int reliable_write_packet_header/int reliable_write_packet_header/' \
    -e 's/^static int reliable_read_packet_header/int reliable_read_packet_header/' \
    "$C_RELIABLE/reliable.c" > "$WORK/reliable.c"
"$CC" -O2 "$FP_CONTRACT" -Wall -Wextra -I "$C_RELIABLE" -o "$WORK/compat-c" compat/c/compat.c "$WORK/reliable.c" -lm

echo "== building C# compat harness"
# -m:1 -nr:false: build in this process only. MSBuild worker nodes hang in
# sandboxed environments where the runtime's shared-memory directory
# (/tmp/.dotnet/shm) is not writable and is redirected out from under it, and
# a hung node fails the gate after the node-connection timeout with no error;
# a single-node build is slower but immune, and the gate is not build-bound.
dotnet build -c Release compat/Compat.csproj --nologo -v q -m:1 -nr:false

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

gate "empty packet on one receiver"    empty_packet
gate "wire vectors"                    vectors
gate "malformed inputs"                malformed
gate "fragment window"                 fragment_window
gate "config refusal"                  config_refusal
gate "1.4.x hardening"                 hardening
gate "scenario clean    (seed 1)"      scenario clean 1 300
gate "scenario lossy    (seed 2)"      scenario lossy 2 500
gate "scenario hostile  (seed 3)"      scenario hostile 3 500
gate "scenario wrap     (seed 6)"      scenario wrap 6 2000
gate "differential soak (seed 4)"      scenario hostile 4 5000
gate "differential soak (seed 5)"      scenario lossy 5 5000

echo "INTEROP GATE PASSED"
