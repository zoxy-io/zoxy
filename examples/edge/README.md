# zoxy-edge

A proxy built on the `zoxy` library by a separate package, the way your
own build would be. It is configured entirely in code: no JSON, and no
config file. Nearly every extension hook zoxy offers a build appears
here, in one small, coherent edge (tenants, an auth service, a control
plane), with tests under zoxy's simulator and a live smoke against real
sockets. The table below points the rest to their contracts.

The contract each hook obeys is [DESIGN.md §13](../../docs/DESIGN.md#13-embedding--the-library-seam).
This page says where each one is shown and how to run it.

## Layout

| File | What it holds |
|---|---|
| [`src/edge.zig`](src/edge.zig) | The build: its extension types, their instances, and `options`, which states the listeners, routes and clusters in code |
| [`src/main.zig`](src/main.zig) | The binary: parse the command line, build the options, `App.serve` or `App.check` |
| [`src/edge_test.zig`](src/edge_test.zig) | The build under `zoxy.testing.Bed`: zoxy's serving path over the simulator, held to the zero-allocation gate and a replayed seed |
| [`smoke/main.zig`](smoke/main.zig) | The binary on real sockets against live origins, drained by SIGTERM (Linux) |
| [`build.zig`](build.zig), [`build.zig.zon`](build.zig.zon) | The package, depending on zoxy by path |

## Running it

Zig 0.17.1. From this directory:

```console
$ zig build            # zig-out/bin/zoxy-edge
$ zig build test       # the simulator tests
$ zig build smoke      # the live run (Linux)
```

The binary takes its endpoints on the command line, which stands in for
the discovery a real build does before its options exist:

```console
$ zoxy-edge [--check] LISTEN CONTROL METRICS APP STATIC AUTH
```

- `LISTEN` is where clients connect.
- `CONTROL` is the control plane's listener. It asks no credentials and
  moves all of the application's traffic, so bind it where only
  operators reach.
- `METRICS` is the metrics listener, for a Prometheus scraper.
- `APP`, `STATIC` and `AUTH` are comma-separated `IP:port` lists: the
  application's endpoints, the static-content ones, and the auth service
  `/account` asks.

`--check` resolves the options, prints the startup banner with every
budget, and asks the box for what a start would, binding nothing.

Against origins of your own, the session below expects two answers of
them: the auth service `200` to `GET /allow?tenant=acme`, and each static
endpoint `200` to `GET /healthz`. Otherwise `/account` is refused and the
`static` cluster's check fails. The smoke's origins answer both.

```console
$ zoxy-edge 127.0.0.1:8080 127.0.0.1:9901 127.0.0.1:9902 \
    127.0.0.1:3000 127.0.0.1:3001,127.0.0.1:3002 127.0.0.1:3003
$ curl -H 'x-tenant: acme' http://127.0.0.1:8080/orders          # the application
$ curl -i http://127.0.0.1:8080/orders                            # 401, the tenant challenge
$ curl -H 'x-tenant: acme' http://127.0.0.1:8080/account         # asks the auth service first
$ curl -X PUT --data '127.0.0.1:3004' http://127.0.0.1:9901/endpoints   # move the application
$ curl -s http://127.0.0.1:9902/ | grep zoxy_ext_                 # the build's own series
```

## Every hook, and where it is shown

| Hook | Issue | Shown by | What it does here |
|---|---|---|---|
| Picker `pick` | #417 | `LeastInFlight`, `PathAffinity` | Fewest requests in flight, one instance shared by `api` and `search`; a path hashed to one `static` endpoint |
| Picker `bind` | #417 | `LeastInFlight` | Counts the clusters that selected it |
| Picker `complete` | #423 | `LeastInFlight` | Hears each pick's outcome once; keeps time to the response head |
| Picker `endpointsChanged` | #428 | — | Per-endpoint picker state following a slot that changed hands: DESIGN §13, *Pickers* |
| Request policy, listener phase | #417 | `TenantGuard` | Requires one valid `x-tenant` before filters and routing run |
| Request policy, route phase | #417 | `ReadOnly`, `AccountGuard` | `/static` refuses writes; `/account` asks the auth service |
| A policy's own answers | #431 | `TenantGuard` | A `401` with `WWW-Authenticate`, rendered once at startup, in place of a static `403` |
| The request's tag | #433 | `TenantGuard` | The tenant's hash, carried by every later view and logged as `"tag":N` |
| Request header edits | #424 | `TenantGuard` | `x-edge-tenant` set upstream, replacing any copy the client forged |
| Request completion | #429 | `TenantGuard` | Counts requests in flight back down when each ends |
| Choosing a route | #430 | — | `proceed_with.route` and `PolicySite.routeNamed`: DESIGN §13, *Request policies* |
| Client certificate names | #432 | — | A verified client's URI and DNS names on the request view; needs a mutual-TLS listener |
| Consults | #437 | `AccountGuard` | Parks the request while zoxy asks the `auth` cluster; `consulted` decides; fails closed |
| Response policies | #424 | `SecurityHeaders` | Sets `x-content-type-options` and `x-frame-options`, drops `x-powered-by` |
| Connection policies and completion | #425 | `ConnectionCap` | Closes a connection past the cap before a byte of it is read |
| Handlers | #434 | `EndpointsControl` | The control plane, answering on its own listener |
| Live endpoints | #428 | `EndpointsControl`, `endpoint_slots` | `PUT /endpoints` replaces the application's set while the edge serves |
| Health-check kinds | #436 | `HealthzProbe` | The `static` cluster's check: zoxy dials and times, the type sends and judges |
| A build's own metrics | #435 | `LeastInFlight`, `TenantGuard`, `ConnectionCap`, `AccountGuard` | `zoxy_ext_<prefix>_<name>` series per cluster, listener and route |
| Testing a build | #417 | `edge_test.zig` | `zoxy.testing.Bed`, `Bed.counter`, `expectNoAllocationAfterStartup` |

`zoxy.testing` also exports scripted doubles of every kind
(`ScriptedPicker`, `ScriptedPolicy`, `ScriptedHandler`,
`ScriptedProbe`, and the rest). zoxy's own simulator drives them, and
they double as short reference implementations of each contract.

## What every hook owes

Each call is synchronous and runs to completion on the loop: no
allocation after startup (only `bind` gets the startup arena), no wall
clock, no private randomness, no syscalls, and nothing kept from a view
past the call. A verdict that outlives its call, such as an edit list or
a consult's question, lives in the instance: see `TenantGuard.edits` and
`AccountGuard.question`. The simulator tests hold the build to this.
They run each scenario twice under one seed and require the same
delivery trace, so a clock read or a private generator fails them.

State an instance keeps carries from one bed run into the next.
`TenantGuard.in_flight` and `ConnectionCap.open` return to zero once a
run drains, and the tests assert that. A picker that keeps steering
state, such as a round-robin cursor, resets it in `bind`.

The health-check kind is the one hook the bed cannot show. A bed
scenario drains within milliseconds of virtual time, before the first
sweep comes due, so the live smoke counts the probes the static origins
receive instead.

## Building your own

Depend on zoxy as this package does, by URL instead of by path, at a
release tag. 1.1.0 is the first with every hook above:

```console
$ zig fetch --save https://github.com/zoxy-io/zoxy/archive/refs/tags/<tag>.tar.gz
```

then import the module in `build.zig` with
`b.dependency("zoxy", .{ .target = target, .optimize = optimize }).module("zoxy")`.
CI builds, tests and smokes this package against a `zig fetch` of the
repository's own archive, which is what a dependent receives.
