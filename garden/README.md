# The HTTP Garden target

[HTTP Garden](https://github.com/narfindustries/http-garden) is a differential
fuzzer for HTTP implementations: it runs many servers and proxies in
containers, sends the same adversarial payload through each, and diffs how
they parsed it. A disagreement between two implementations about where one
request ends and the next begins is the ingredient of a request-smuggling
chain, which is why it is the external check worth running against DESIGN.md
§7's framing strictness — the §9 fuzz gate proves *this* parser never panics
and admits no third outcome, which is a different claim from agreeing with
everyone else's.

This directory holds zoxy's target definition. **It is not a gate**, and
deliberately: the Garden brings Docker, Compose and Python 3.12+, it is
Linux-only, and its verdict is *disagreement* rather than failure — §7 makes
zoxy stricter than nginx in several places on purpose, so discrepancies need
adjudication, not a red build. It is run on demand, and what it finds is
distilled into the gates that do run (below).

The layout mirrors upstream's (`images/<name>/`) so the target can be
contributed there unchanged.

## Running it

Prerequisites: Docker with Compose, and [uv](https://docs.astral.sh/uv/)
(the Garden pins its Python through `uv.lock`; it will fetch a suitable
interpreter itself).

```sh
git clone https://github.com/narfindustries/http-garden
cd http-garden
git checkout b417e806c1b15e8ea0b9312f81a91fbdcbc7a83e   # the audited pin
./install.sh .          # actually ../zoxy/garden/install.sh
./garden.sh start --build zoxy nginx haproxy
./garden.sh repl        # from another shell
```

`install.sh` copies `images/zoxy/` into the checkout and appends the compose
service, replacing an existing entry so a changed `service.yml` propagates.

**The checkout directory must be named `http-garden`.** `tools/targets.py`
hardcodes `_NETWORK_NAME = "http-garden_default"`, so the Compose project
name — which is the directory name — decides whether the REPL finds any
containers at all. Clone it as anything else and every target, zoxy included,
reports as "not running" while sitting there running. (`docker compose -p
http-garden` works too.)

## Two things this target needs that others do not

**seccomp must be unconfined.** zoxy is io_uring-native on Linux (§4), and
Docker's default seccomp profile denies `io_uring_setup`. Under the stock
profile the process prints its whole budget banner and then exits with
`error: PermissionDenied` — which looks like a config or privilege problem
and is neither. `service.yml` carries `security_opt: [seccomp:unconfined]`;
no other Garden target needs it because no other target uses io_uring.

**The Zig toolchain is fetched and checksummed in the image.** The soil image
provides a C toolchain and a sanitizer environment (`CC`, `CFLAGS`,
`LDFLAGS`) meant for targets that build with it. Zig takes none of those
flags, so the build step unsets them — the same thing `images/pingora`'s
Dockerfile does for cargo. Both Linux tarballs are pinned by SHA-256, because
the toolchain is part of what this image reproduces.

## Shape of the target

Upstream's transducer convention: the proxy binds `:80` in the container and
forwards to a Python echo server on `127.0.0.1:56062` (`0xdafe`) that the
base image provides, so what the Garden observes is exactly what zoxy
*forwarded*. `zoxy.json` is §5's minimal config — one `http` listener, one
cluster — with the backend written as `BACKEND_HOST_PLACEHOLDER:BACKEND_PORT_PLACEHOLDER`
and `sed`-substituted at build time. That placeholder resolves to an IP
literal, which matters: §7 resolves cluster endpoints as static socket
addresses at config load, so a hostname there would not work.

It is built `ReleaseSafe`, which is what zoxy ships and also the right mode
to be differentially tested in: TIGER_STYLE puts at least two assertions in
every function, so an invariant this proxy believes about its own state
becomes a crash the Garden observes rather than a wrong answer it has to
notice.

## Where findings go

The Garden is a discovery tool, and §9 already describes the loop it feeds:
of the two bugs the live gate caught first, *"Both were afterwards teachable
to the simulator; neither was caught by it first, because each had to be
known before it could be looked for."* The Garden manufactures the *known*.

So a confirmed discrepancy becomes one of two things, and then the Garden is
no longer needed to catch it again:

- a **fuzz corpus entry** for `zig build test --fuzz`, if it is a parse bug —
  that gate already fuzzes the head parser and the chunked decoder;
- a **simulator scenario**, if it is a state-machine bug rather than a
  parsing one.

Running `./garden.sh probe_quirks` also produces zoxy's quirk profile: an
enumeration of how it benignly differs from the field, which is the empirical
companion to §12's register of what it is *held to*.

## Upstreaming

The intent is to contribute `images/zoxy/` and the compose entry to the
Garden once this is stable, which is why the layout matches theirs and the
`APP_REPO`/`APP_BRANCH`/`APP_VERSION` build args follow their convention.
Keeping the definition here in the meantime costs nothing and fixes the
thing that would otherwise rot: zoxy's config parser is strict
(`additionalProperties: false`), so a `zoxy.json` living in another repo
breaks silently the moment a config field is renamed — here, the same commit
that renames the field fixes the target.

`APP_VERSION` pins the commit the image builds. Bump it deliberately;
upstream's `garden.sh update` bumps every target's pin, including this one.
