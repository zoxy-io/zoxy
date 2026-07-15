#!/usr/bin/env bash
# Pinned Tier-0 profiler (DESIGN.md §9): drive a fixed zrk load through a
# real zoxy against a loopback nginx origin, sample ONLY the zoxy pid with
# perf, and fold the result into a flamegraph. zoxy is pinned to one core so
# the hardware PMU and LBR call-graph stay on a single core type — on a hybrid
# Intel part an unpinned process migrates between the cpu_core and cpu_atom
# PMUs and samples read as zero. Invoked by `zig build profile`, which passes
# the ReleaseFast zoxy and the zrk load generator it built.
#
#   $1  path to the zoxy binary        $2  path to the zrk binary
# Env knobs: ZOXY_CPU, SECONDS_LOAD, RATE, CONNECTIONS, FREQ.
set -uo pipefail

ZOXY_BIN=${1:?usage: profile.sh <zoxy-bin> <zrk-bin>}
ZRK_BIN=${2:?usage: profile.sh <zoxy-bin> <zrk-bin>}

for tool in perf flamegraph.pl stackcollapse-perf.pl nginx taskset; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "profile: '$tool' not found — run inside the dev shell (devenv shell)." >&2
        exit 1
    }
done

NPROC=$(nproc)
# Prefer the last P-core on hybrid Intel (cpu_core lists them); else last cpu.
PCORES=$(cat /sys/devices/cpu_core/cpus 2>/dev/null || echo "0-$((NPROC - 1))")
ZOXY_CPU=${ZOXY_CPU:-$(echo "$PCORES" | tr ',' '\n' | tail -1 | awk -F- '{print $NF}')}
# Everything else runs off zoxy's core so the load generator never steals it.
OTHERS=$(seq 0 $((NPROC - 1)) | grep -vwx "$ZOXY_CPU" | paste -sd, -)
OTHERS=${OTHERS:-$ZOXY_CPU}

SECONDS_LOAD=${SECONDS_LOAD:-30}
RATE=${RATE:-100000}
CONNECTIONS=${CONNECTIONS:-64}
FREQ=${FREQ:-4000}
ORIGIN_PORT=${ORIGIN_PORT:-19190}
ZOXY_PORT=${ZOXY_PORT:-18190}

OUT=".zig-cache/zoxy-profile"
rm -rf "$OUT"; mkdir -p "$OUT/logs"

cat > "$OUT/nginx.conf" <<EOF
daemon off;
worker_processes 1;
pid nginx.pid;
error_log logs/error.log crit;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$ORIGIN_PORT;
        location / { return 200 "zoxy-profile-origin\n"; }
    }
}
EOF

cat > "$OUT/zoxy.json" <<EOF
{ "listeners":[{"bind":"127.0.0.1:$ZOXY_PORT","cluster":"origin"}],
  "clusters":{"origin":{"endpoints":["127.0.0.1:$ORIGIN_PORT"]}},
  "timeouts":{"connect_ms":5000,"idle_ms":60000,"drain_deadline_ms":5000} }
EOF

cleanup() { kill "${ZOXY_PID:-}" "${NGINX_PID:-}" 2>/dev/null; }
trap cleanup EXIT

taskset -c "$OTHERS"   nginx -p "$OUT" -c nginx.conf & NGINX_PID=$!
sleep 1
taskset -c "$ZOXY_CPU" "$ZOXY_BIN" "$OUT/zoxy.json" & ZOXY_PID=$!
sleep 1
echo "profile: zoxy pid=$ZOXY_PID pinned to cpu $ZOXY_CPU; origin+load on cpus $OTHERS"

# Warm up and prove the path serves before spending a measured run on it.
warm=$(taskset -c "$OTHERS" "$ZRK_BIN" -c 16 -R 20000 -d 3s --plain "http://127.0.0.1:$ZOXY_PORT/" 2>&1)
echo "$warm" | grep -q "Requests/sec: 0.00" && { echo "profile: path served 0 req/s — aborting"; echo "$warm"; exit 1; }

echo "profile: measuring ${SECONDS_LOAD}s at ${RATE} req/s over ${CONNECTIONS} connections"
# cycles:u + LBR: hardware call-graph from the branch MSRs, no frame pointers
# or DWARF CFI needed. Records only the zoxy pid, for the load's duration.
perf record -p "$ZOXY_PID" -e cycles:u -F "$FREQ" --call-graph lbr \
    -o "$OUT/zoxy.perf.data" -- sleep "$SECONDS_LOAD" & PERF_PID=$!
taskset -c "$OTHERS" "$ZRK_BIN" -t 4 -c "$CONNECTIONS" -R "$RATE" -d "${SECONDS_LOAD}s" \
    --plain "http://127.0.0.1:$ZOXY_PORT/" 2>&1 | tail -4
wait "$PERF_PID"

perf script -i "$OUT/zoxy.perf.data" 2>/dev/null | stackcollapse-perf.pl > "$OUT/zoxy.folded" 2>/dev/null
flamegraph.pl --title "zoxy L4 relay under load (cycles:u, LBR call-graph)" \
    "$OUT/zoxy.folded" > "$OUT/zoxy-flamegraph.svg" 2>/dev/null

echo
echo "profile: flamegraph -> $OUT/zoxy-flamegraph.svg"
echo "profile: top self-time symbols"
perf report -i "$OUT/zoxy.perf.data" --stdio --no-children -g none 2>/dev/null \
    | awk '/^ *[0-9]+\.[0-9]+%/ {print}' | head -12
