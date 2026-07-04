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
# nginx is used from PATH when installed, otherwise fetched with `nix shell`.
# Ports are offset from the dev defaults so a running dev instance survives.
set -euo pipefail

DURATION=10s
CONNECTIONS=64
THREADS=4
while getopts "d:c:t:h" opt; do
    case $opt in
        d) DURATION=$OPTARG ;;
        c) CONNECTIONS=$OPTARG ;;
        t) THREADS=$OPTARG ;;
        *) sed -n '2,24p' "$0"; exit 2 ;;
    esac
done

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

echo "== build (ReleaseFast) =="
(cd "$ROOT" && zig build -Doptimize=ReleaseFast)

mkdir -p "$WORK/nginx-tmp"
cat > "$WORK/nginx.conf" <<EOF
worker_processes 4;
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

echo "== start origin (nginx :$ORIGIN_PORT) and proxy (zoxy :$PROXY_PORT) =="
if command -v nginx >/dev/null; then
    nginx -c "$WORK/nginx.conf"
else
    nix shell nixpkgs#nginx --command nginx -c "$WORK/nginx.conf"
fi
"$ROOT/zig-out/bin/zoxy" "$WORK/zoxy.json" > "$WORK/zoxy.log" 2>&1 &
ZOXY_PID=$!
wait_for "http://127.0.0.1:$ORIGIN_PORT/"
wait_for "http://127.0.0.1:$PROXY_PORT/"

if command -v h2load >/dev/null; then
    generate() { h2load --h1 -t"$THREADS" -c"$CONNECTIONS" -D"$DURATION" -m1 "$@"; }
else
    generate() { nix shell nixpkgs#nghttp2 --command \
        h2load --h1 -t"$THREADS" -c"$CONNECTIONS" -D"$DURATION" -m1 "$@"; }
fi

echo
echo "== baseline A: generator -> nginx, keep-alive, ${DURATION} x ${CONNECTIONS} conns =="
generate "http://127.0.0.1:$ORIGIN_PORT/"

echo
echo "== baseline B: generator -> nginx, Connection: close, ${DURATION} x ${CONNECTIONS} conns =="
generate -H 'Connection: close' "http://127.0.0.1:$ORIGIN_PORT/"

echo
echo "== proxied: generator -> zoxy -> nginx, keep-alive, ${DURATION} x ${CONNECTIONS} conns =="
generate "http://127.0.0.1:$PROXY_PORT/"

echo
echo "== zoxy counters =="
curl -s "http://127.0.0.1:$ADMIN_PORT/metrics"
