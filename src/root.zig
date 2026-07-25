//! zoxy — bullet-proof L4/L7 proxy (see docs/DESIGN.md). This module root
//! re-exports the library surface and references every source file so that
//! `zig build test` compiles and runs all tests.

const std = @import("std");

pub const balancer = @import("balancer.zig");
pub const config = @import("config.zig");
pub const config_schema = @import("config_schema.zig");
pub const constants = @import("constants.zig");
pub const counters = @import("counters.zig");
/// L7 HTTP/1.1 modules (§7). `parser` wraps the vendored hparse behind
/// the trust boundary, `render` writes upstream/downstream heads, and
/// `proxy` is the request-lifecycle state machine over both.
pub const http = struct {
    pub const parser = @import("http/parser.zig");
    pub const render = @import("http/render.zig");
    pub const router = @import("http/router.zig");
    pub const filter = @import("http/filter.zig");
    pub const proxy = @import("http/proxy.zig");
};
pub const Io = @import("io/io.zig");
pub const Pool = @import("mem/Pool.zig").Pool;
pub const RelayBuffer = @import("net/relay.zig").RelayBuffer;
pub const UpstreamPool = @import("net/upstream.zig").UpstreamPool;
pub const Server = @import("Server.zig").Server;
pub const shed = @import("shed.zig");
/// TLS termination (§4, Phase 3a). `Engine` is the sans-I/O seam over
/// ztls, `Credentials` loads a listener's cert chain and signing key,
/// and `libcrypto_heap` keeps libcrypto's own allocations off the libc
/// heap. `src/tls/` is the only directory that may name ztls, so the
/// C-crypto surface stays behind these wrappers (lint-enforced).
pub const tls = struct {
    pub const Engine = @import("tls/Engine.zig");
    pub const Credentials = @import("tls/Credentials.zig");
    pub const libcrypto_heap = @import("tls/libcrypto_heap.zig");
};
/// Shared test-support harness pieces (used by server_test and the sim).
pub const testing = struct {
    pub const Origin = @import("testing/origin.zig").Origin;
    pub const Mode = @import("testing/origin.zig").Mode;
};

test {
    _ = balancer;
    _ = config;
    _ = config_schema;
    _ = constants;
    _ = counters;
    _ = http.parser;
    _ = http.render;
    _ = http.router;
    _ = http.filter;
    _ = http.proxy;
    _ = Io;
    _ = Server;
    _ = shed;
    _ = @import("mem/Pool.zig");
    _ = @import("net/Conn.zig");
    _ = @import("net/relay.zig");
    _ = @import("net/upstream.zig");
    _ = @import("testing/origin.zig");
    _ = @import("net/pump_transform_test.zig");
    _ = @import("io/contract_test.zig");
    _ = @import("io/sim_io_test.zig");
    _ = @import("io/xev_smoke_test.zig");
    _ = @import("server_test.zig");
    _ = @import("http_proxy_test.zig");
    _ = @import("admin_test.zig");
    _ = @import("zero_alloc_test.zig");
    // The TLS engine, its credentials loader, and the fixed libcrypto
    // heap's allocator tests (size classes, realloc, free-list poison —
    // all order-independent). Only the heap's *install* proof needs a
    // fresh process, so it alone stays in `zig build tls-heap-proof`.
    _ = tls.Engine;
    _ = tls.Credentials;
    _ = tls.libcrypto_heap;
    _ = @import("tls/spike_test.zig");
}
