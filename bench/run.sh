#!/usr/bin/env bash
# End-to-end benchmark: load generator -> zoxy -> nginx origin, on loopback.
#
#   bench/run.sh [-d duration] [-c connections] [-t threads]
#
# Three saturating runs over the same connection set, so the proxy hop cost is
# directly visible:
#   baseline A: generator -> nginx, keep-alive — the honest comparison since
#               Phase 1: zoxy speaks keep-alive on both sides (downstream
#               reuse + upstream pool)
#   baseline B: generator -> nginx, "Connection: close" — the Phase-0
#               connection model, kept to show the handshake tax
#   proxied:    generator -> zoxy -> nginx (keep-alive end to end)
#
# The generator is h2load (nghttp2's load tool): closed-loop, forced to
# HTTP/1.1 (--h1) since zoxy is H1-only until the H2 phase lands. It drives
# each connection flat out for the duration and reports throughput plus a
# time-for-request distribution and an errored/failed count — the error
# counters catch protocol bugs that throughput numbers alone hide. h2load
# ships in the dev shell; used from PATH when present, else fetched via
# `nix shell`.
#
# READ THE NUMBERS RIGHT — this is `-m1`, one request in flight per connection,
# so it is a *latency* test: req/s = connections / mean-latency. Inserting a
# proxy adds a hop, so on loopback (no network RTT to hide behind) the proxied
# req/s is lower *by construction* — that gap is the hop latency, not a zoxy
# throughput ceiling. What matters is the `time for request:` distribution, the
# small direct-vs-proxied mean gap, and the "zoxy CPU" line: if zoxy has spare
# cores, the loop is latency-bound and the req/s gap is not saturation. Each
# role is pinned to a DISJOINT set of cores so the proxied run never steals
# cores from the generator/origin — without that, `nproc` zoxy workers + nginx
# + h2load contend for the same cores and the hop looks far worse than it is.
# In production (RTT 0.1-100ms) an ~10us loopback hop is invisible; to measure
# zoxy's *throughput* ceiling instead, drive it until its own cores saturate
# (much higher `-c`, or add real RTT).
#
# nginx is used from PATH when installed, otherwise fetched with `nix shell`.
# Ports are offset from the dev defaults so a running dev instance survives.
set -euo pipefail

DURATION=10s
CONNECTIONS=64
THREADS=""
while getopts "d:c:t:h" opt; do
    case $opt in
        d) DURATION=$OPTARG ;;
        c) CONNECTIONS=$OPTARG ;;
        t) THREADS=$OPTARG ;;
        *) sed -n '2,24p' "$0"; exit 2 ;;
    esac
done
DURATION_S=${DURATION//[^0-9]/}   # "10s" -> "10"; the CPU sampler needs seconds

ORIGIN_PORT=19000
PROXY_PORT=18080
ADMIN_PORT=19901

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
ZOXY_PID=""
cleanup() {
    [ -n "$ZOXY_PID" ] && kill "$ZOXY_PID" 2>/dev/null || true
    [ -f "$WORK/nginx.pid" ] && kill "$(cat "$WORK/nginx.pid")" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Bounded wait for an HTTP endpoint to come up (5s).
wait_for() {
    for _ in $(seq 1 50); do
        curl -sf -o /dev/null "$1" && return 0
        sleep 0.1
    done
    echo "bench: timeout waiting for $1" >&2
    exit 1
}

# --- core pinning: give each role its own cores so the proxied run never
# oversubscribes (that alone inflates the hop 2-3x on a busy loopback box).
# The origin and generator get the SAME cores in every run, so the only
# variable between direct and proxied is the presence of zoxy on its own
# cores. Split: the origin serves a canned 200 (cheap) so it gets the fewest;
# the proxy (under test) and the closed-loop generator split the rest evenly.
# zoxy has no worker-count flag — it spawns one worker per *visible* CPU, so
# `taskset` onto PROXY_CPUS both pins and sizes it. Needs >=3 cores to split;
# below that, pin nothing and let the note above stand.
NCPU=$(nproc)
PIN_ORIGIN=""; PIN_PROXY=""; PIN_GEN=""
ORIGIN_CPUS=""; PROXY_CPUS=""; GEN_CPUS=""
NGINX_WORKERS=4
PROXY_COUNT=0
seq_csv() { seq "$1" "$2" | paste -sd, -; }  # inclusive core range -> "a,b,c"
if command -v taskset >/dev/null && [ "$NCPU" -ge 3 ]; then
    origin_count=$(( NCPU / 4 )); [ "$origin_count" -lt 1 ] && origin_count=1
    rest=$(( NCPU - origin_count ))
    PROXY_COUNT=$(( rest / 2 )); [ "$PROXY_COUNT" -lt 1 ] && PROXY_COUNT=1
    gen_count=$(( rest - PROXY_COUNT ))
    ORIGIN_CPUS=$(seq_csv 0 $((origin_count - 1)))                          # nginx
    PROXY_CPUS=$(seq_csv "$origin_count" $((origin_count + PROXY_COUNT - 1)))  # zoxy
    GEN_CPUS=$(seq_csv $((origin_count + PROXY_COUNT)) $((NCPU - 1)))       # h2load
    PIN_ORIGIN="taskset -c $ORIGIN_CPUS"
    PIN_PROXY="taskset -c $PROXY_CPUS"
    PIN_GEN="taskset -c $GEN_CPUS"
    NGINX_WORKERS=$origin_count
    [ -z "$THREADS" ] && THREADS=$gen_count   # one generator thread per gen core
fi
[ -z "$THREADS" ] && THREADS=4

echo "== build (ReleaseFast) =="
(cd "$ROOT" && zig build -Doptimize=ReleaseFast)

mkdir -p "$WORK/nginx-tmp"
cat > "$WORK/nginx.conf" <<EOF
worker_processes $NGINX_WORKERS;
error_log $WORK/nginx-error.log;
pid $WORK/nginx.pid;
events { worker_connections 4096; }
http {
    access_log off;
    default_type text/plain;
    client_body_temp_path $WORK/nginx-tmp;
    proxy_temp_path $WORK/nginx-tmp;
    fastcgi_temp_path $WORK/nginx-tmp;
    uwsgi_temp_path $WORK/nginx-tmp;
    scgi_temp_path $WORK/nginx-tmp;
    server {
        listen 127.0.0.1:$ORIGIN_PORT;
        return 200 "hello from origin - 64 bytes of payload for the benchmark!\n";
    }
}
EOF
cat > "$WORK/zoxy.json" <<EOF
{
  "listen": "127.0.0.1:$PROXY_PORT",
  "admin": "127.0.0.1:$ADMIN_PORT",
  "routes": [{ "cluster": "origin" }],
  "clusters": [{ "name": "origin", "endpoints": ["127.0.0.1:$ORIGIN_PORT"] }]
}
EOF

if [ -n "$PIN_PROXY" ]; then
    echo "== core pinning ($NCPU cpus): nginx=[$ORIGIN_CPUS] zoxy=[$PROXY_CPUS] h2load=[$GEN_CPUS] =="
else
    echo "== core pinning: disabled (<3 cpus or no taskset) — proxied run oversubscribes; read latency, not req/s =="
fi

echo "== start origin (nginx :$ORIGIN_PORT) and proxy (zoxy :$PROXY_PORT) =="
if command -v nginx >/dev/null; then
    $PIN_ORIGIN nginx -c "$WORK/nginx.conf"
else
    $PIN_ORIGIN nix shell nixpkgs#nginx --command nginx -c "$WORK/nginx.conf"
fi
$PIN_PROXY "$ROOT/zig-out/bin/zoxy" "$WORK/zoxy.json" > "$WORK/zoxy.log" 2>&1 &
ZOXY_PID=$!
wait_for "http://127.0.0.1:$ORIGIN_PORT/"
wait_for "http://127.0.0.1:$PROXY_PORT/"

# Keep only the rows that matter: the throughput line, the request tally (its
# failed/errored counts are the protocol-bug tripwire), and the latency table.
summarize() {
    grep -E 'finished in|^requests:|^status codes:|min.*max.*median|^request |^connect |^TTFB |^req/s ' || true
}
if command -v h2load >/dev/null; then
    generate() { $PIN_GEN h2load --h1 -t"$THREADS" -c"$CONNECTIONS" -D"$DURATION" -m1 "$@" 2>/dev/null | summarize; }
else
    generate() { $PIN_GEN nix shell nixpkgs#nghttp2 --command \
        h2load --h1 -t"$THREADS" -c"$CONNECTIONS" -D"$DURATION" -m1 "$@" 2>/dev/null | summarize; }
fi

# Process-wide CPU ticks (all threads, comm-safe): drop "PID (comm) " so a comm
# containing spaces/parens can't shift the fields, then read utime+stime.
proc_cpu_ticks() {
    local stat
    stat=$(cat "/proc/$1/stat" 2>/dev/null) || { echo 0; return; }
    stat=${stat#*) }
    # shellcheck disable=SC2086
    set -- $stat
    echo $(( ${12} + ${13} ))
}

echo
echo "== baseline A: generator -> nginx, keep-alive, ${DURATION} x ${CONNECTIONS} conns =="
generate "http://127.0.0.1:$ORIGIN_PORT/"

echo
echo "== baseline B: generator -> nginx, Connection: close, ${DURATION} x ${CONNECTIONS} conns =="
generate -H 'Connection: close' "http://127.0.0.1:$ORIGIN_PORT/"

echo
echo "== proxied: generator -> zoxy -> nginx, keep-alive, ${DURATION} x ${CONNECTIONS} conns =="
cpu_before=$(proc_cpu_ticks "$ZOXY_PID")
generate "http://127.0.0.1:$PROXY_PORT/"
cpu_after=$(proc_cpu_ticks "$ZOXY_PID")
if [ "$PROXY_COUNT" -gt 0 ] && [ -n "$DURATION_S" ] && [ "$DURATION_S" -gt 0 ]; then
    clk=$(getconf CLK_TCK)
    zoxy_pct=$(( (cpu_after - cpu_before) * 100 / (clk * DURATION_S) ))
    echo "   zoxy CPU during run: ${zoxy_pct}% of $((PROXY_COUNT * 100))% available (${PROXY_COUNT} cores)"
fi

echo
echo "== reading the result =="
echo "   -m1 is closed-loop (1 req/conn in flight): req/s = conns / mean-latency,"
echo "   so it measures LATENCY. The proxied req/s is lower because the extra hop"
echo "   adds latency; the honest cost is 'baseline A mean' vs 'proxied mean' in"
echo "   the 'time for request:' rows above (a healthy loopback hop is ~10-30us)."
echo "   If 'zoxy CPU' is well under its available %, the loop is latency-bound,"
echo "   not saturated — this is NOT zoxy's throughput ceiling. On loopback there"
echo "   is no RTT to hide the hop behind; in production the hop is dwarfed by it."

echo
echo "== zoxy counters =="
curl -s "http://127.0.0.1:$ADMIN_PORT/metrics"
