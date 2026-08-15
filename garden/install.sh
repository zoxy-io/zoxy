#!/bin/sh
#
# Install the zoxy target into an http-garden checkout.
#
#   ./garden/install.sh /path/to/http-garden
#
# Copies images/zoxy/ in and appends the compose service if it is not already
# there. `services:` is the only top-level key in the Garden's
# docker-compose.yml and the file ends with the last service, so appending a
# two-space-indented block is a valid edit that also lands alphabetically.
# Idempotent: re-running refreshes the image directory and leaves the compose
# entry alone.

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path-to-http-garden-checkout>" >&2
    exit 2
fi

garden="$1"
here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

if [ ! -f "$garden/docker-compose.yml" ] || [ ! -d "$garden/images" ]; then
    echo "$garden does not look like an http-garden checkout" >&2
    exit 1
fi

rm -rf "$garden/images/zoxy"
cp -R "$here/images/zoxy" "$garden/images/zoxy"
chmod +x "$garden/images/zoxy/start.sh"
echo "installed $garden/images/zoxy"

if grep -q '^  zoxy:$' "$garden/docker-compose.yml"; then
    # Drop the existing block so a changed service.yml actually propagates.
    # A service key is the only thing at two-space indent ending in ':', so
    # the block runs from `  zoxy:` to the next such line, or to EOF.
    awk '
        /^  zoxy:$/ { skip = 1; next }
        skip && /^  [A-Za-z_][A-Za-z0-9_.-]*:$/ { skip = 0 }
        skip { next }
        { print }
    ' "$garden/docker-compose.yml" >"$garden/docker-compose.yml.tmp"
    mv "$garden/docker-compose.yml.tmp" "$garden/docker-compose.yml"
    echo "replaced compose service 'zoxy'"
else
    echo "appended compose service 'zoxy'"
fi
cat "$here/service.yml" >>"$garden/docker-compose.yml"
