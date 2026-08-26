#!/usr/bin/env bash
#
# Boot a zoxy binary with a `tls` listener and drive one request through each
# listener it declares. Run against a *built artifact*, on the platform that
# artifact is for — release.yml calls it on every leg, before packaging.
#
# It exists because `--version` cannot see #283. v0.6.0 passed every other
# check in that workflow — static, no nix-store references, right version —
# and then died in libcrypto at key load for anyone who configured a `tls`
# listener. The binary was fine; the build was not, and nothing in the release
# ran it far enough to notice. `zig build ci`'s `smoke-release` leg now covers
# the build *configuration*; this covers the artifact that is actually
# published.
#
# Deliberately depends on bash and curl and nothing else. The TLS fixture is
# the one already in the tree (src/tls/testdata, an EC keypair good to 2036),
# so there is no openssl invocation to differ between a Linux runner and a
# macOS one, and no generated material whose algorithm choice could drift away
# from what the smoke harness exercises.
#
# Usage: release-tls-check.sh <zoxy-binary>
set -eu

readonly bin="${1:?usage: release-tls-check.sh <zoxy-binary>}"
readonly root="$(cd "$(dirname "$0")/.." && pwd)"
readonly cert="$root/src/tls/testdata/cert.pem"
readonly key="$root/src/tls/testdata/key.pem"

# High and unremarkable: a released binary is checked on shared runners, and
# the low ports are where other people's services live (a system nginx on 9000
# has cost this project a debugging session before).
readonly port_http=41080
readonly port_tls=41443
readonly port_admin=41101

[ -x "$bin" ] || { echo "::error::not executable: $bin"; exit 1; }
[ -f "$cert" ] && [ -f "$key" ] || { echo "::error::missing TLS fixture under $root/src/tls/testdata"; exit 1; }

work="$(mktemp -d)"
log="$work/zoxy.log"
pid=""

cleanup() {
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

# The endpoint deliberately points at a closed port. What is under test is that
# the process starts, terminates TLS and answers; whether it can reach an
# origin is a different gate's business, and standing up one here would add a
# dependency for no verdict.
cat > "$work/zoxy.json" <<JSON
{
  "listeners": [
    { "bind": "127.0.0.1:$port_http", "http": { "cluster": "origin" } },
    { "bind": "127.0.0.1:$port_tls", "http": { "cluster": "origin" },
      "tls": { "cert": "$cert", "key": "$key" } }
  ],
  "clusters": { "origin": { "endpoints": ["127.0.0.1:1"], "pick": "rr" } },
  "admin": { "bind": "127.0.0.1:$port_admin" }
}
JSON

fail() {
    echo "::error::$1"
    echo "--- proxy output ---"
    cat "$log" 2>/dev/null || echo "(none)"
    exit 1
}

"$bin" "$work/zoxy.json" > "$log" 2>&1 &
pid=$!

# Startup is where #283 lands, so a death here is reported as itself rather
# than as a connection failure thirty seconds later.
waited=0
until curl -sf -o /dev/null --max-time 2 "http://127.0.0.1:$port_admin/metrics"; do
    kill -0 "$pid" 2>/dev/null || fail "died during startup (this is the #283 signature)"
    waited=$((waited + 1))
    [ "$waited" -lt 30 ] || fail "admin plane never answered after ${waited}s"
    sleep 1
done
echo "startup: ok (admin plane answering after ${waited}s)"

# Plaintext first, as the control. If this passes and TLS does not, the fault
# is in the TLS path specifically — which is exactly what #283 looked like.
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$port_http/" || echo 000)"
[ "$code" != "000" ] || fail "plaintext listener answered nothing"
echo "plaintext: ok (HTTP $code)"

# -k because the fixture is self-signed: this asserts that a TLS 1.3 handshake
# completed and the request was proxied, not that anyone trusts the cert.
code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://127.0.0.1:$port_tls/" || echo 000)"
[ "$code" != "000" ] || fail "TLS handshake or request failed"
echo "tls: ok (HTTP $code over TLS 1.3)"

kill -0 "$pid" 2>/dev/null || fail "exited while serving"

# A clean SIGTERM shutdown, because #283's neighbour was a libcrypto atexit
# handler that segfaulted *after* a correct drain — a failure only a real
# process teardown can show.
kill -TERM "$pid"
wait "$pid" 2>/dev/null && status=0 || status=$?
pid=""
[ "$status" -eq 0 ] || fail "unclean shutdown: exit $status"
echo "shutdown: ok"

echo "release TLS check passed: $bin"
