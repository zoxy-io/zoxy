//! Tier-0 micro bench (§9): the per-request L7 head CPU — parse the
//! request head, canonicalize its target, render it upstream, parse the
//! origin response head, render it downstream — the work an L7 exchange
//! does that an L4 relay does not. Realistic small-GET heads (what the
//! Tier-1 loopback bench drives). poop A/B on hardware counters; decision
//! tool, not a CI gate.
//!
//! The canonicalization belongs in the loop: since #98 the proxy runs it
//! exactly once per request, between the parse and the render, so leaving
//! it out would understate the per-request head cost this bench exists to
//! report.
//!
//! Run: `zig build bench-micro` then
//! `poop ./zig-out/bin/zoxy-bench-l7_head_pipeline` for the absolute
//! per-iteration cost, or poop two builds to A/B a candidate change.

const std = @import("std");

const zoxy = @import("zoxy");

const parser = zoxy.http.parser;
const render = zoxy.http.render;

const iterations: u64 = 1_000_000;

const request_head =
    "GET / HTTP/1.1\r\n" ++
    "Host: 127.0.0.1:18181\r\n" ++
    "User-Agent: zrk/0.1\r\n" ++
    "Accept: */*\r\n\r\n";

const response_head =
    "HTTP/1.1 200 OK\r\n" ++
    "Server: nginx\r\n" ++
    "Content-Type: text/plain\r\n" ++
    "Content-Length: 18\r\n\r\n";

/// No listener filters: the unfiltered path is the one the Tier-1 bench
/// drives, and a rule set would measure the filter engine rather than the
/// head pipeline.
const no_edits: []const zoxy.http.filter.AppliedHeaderEdit = &.{};

pub fn main() void {
    var request_storage: parser.HeaderStorage = undefined;
    var response_storage: parser.HeaderStorage = undefined;
    var path_scratch: [zoxy.constants.head_bytes_max]u8 = undefined;
    var upstream_head: [zoxy.constants.head_bytes_max]u8 = undefined;
    var downstream_head: [zoxy.constants.head_bytes_max]u8 = undefined;

    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        const request = parser.parseRequestHead(request_head, false, &request_storage) catch unreachable;
        const target = parser.canonicalTarget(request.target, &path_scratch) catch unreachable;
        const upstream = render.renderRequestHead(&request, target, no_edits, false, &upstream_head) catch unreachable;
        const response = parser.parseResponseHead(response_head, false, &response_storage, request.method) catch unreachable;
        const downstream = render.renderResponseHead(&response, true, &downstream_head) catch unreachable;

        // Consume the outputs so nothing is dead-code-eliminated.
        checksum +%= upstream[upstream.len - 1];
        checksum +%= downstream[downstream.len - 1];
        checksum +%= @intFromEnum(request.method);
        checksum +%= response.status;
        checksum +%= target.path.len;
    }
    std.debug.print("checksum {d}\n", .{checksum});
}
