#!/usr/bin/env bash
# Line coverage via kcov (in the dev shell): the unit-test binary plus a
# simulator sweep, merged — the simulator reaches error paths and race
# interleavings unit tests cannot.
#
# Gotcha: Zig 0.16's default Debug backend (self-hosted, x86_64) emits DWARF
# whose line tables kcov 43 cannot read (0 lines found). Build with -fllvm.
#
#   scripts/coverage.sh [output-dir]     # default zig-out/coverage
#
# The merged HTML report lands in <output-dir>/merged/kcov-merged/index.html;
# cobertura.xml next to it is what CI uploads to Coveralls.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/zig-out/coverage}
SIM_SEEDS=${SIM_SEEDS:-150}

cd "$ROOT"
rm -rf "$OUT"
mkdir -p "$OUT" zig-out/bin

echo "== build (LLVM backend, for kcov-readable DWARF) =="
# The zoxy module links the vendored OpenSSL; `zig build` installs the archive
# (zig-out/lib/libopenssl.a) so this bypass-the-build-graph test compile can
# link it by path. The simulator never links OpenSSL.
zig build
zig test src/root.zig --test-no-exec -fllvm -femit-bin=zig-out/bin/coverage_tests \
    -lc zig-out/lib/libopenssl.a
zig build-exe src/sim.zig -ODebug -fllvm -femit-bin=zig-out/bin/coverage_sim

echo "== unit tests under kcov =="
kcov --include-path="$ROOT/src" "$OUT/tests" zig-out/bin/coverage_tests
echo "== simulator (seeds 0..$SIM_SEEDS) under kcov =="
kcov --include-path="$ROOT/src" "$OUT/sim" zig-out/bin/coverage_sim 0 "$SIM_SEEDS"
kcov --merge "$OUT/merged" "$OUT/tests" "$OUT/sim"

# kcov writes an absolute <source> root; Coveralls resolves file paths by
# joining source + filename and then fetching them from GitHub, so the root
# must be repo-relative ("src") or every file shows "source not available".
sed -i "s|<source>$ROOT/src/*</source>|<source>src</source>|" \
    "$OUT/merged/kcov-merged/cobertura.xml"

JSON="$OUT/merged/kcov-merged/coverage.json"
TOTAL=$(grep -o '"percent_covered": "[0-9.]*"' "$JSON" | tail -1 | grep -o '[0-9.]*')
echo
echo "coverage: ${TOTAL}% (report: $OUT/merged/kcov-merged/index.html)"
