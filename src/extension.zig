//! The extension seam (#417): what a build adds to zoxy's serving path.
//!
//! A custom build is configured in code and never with JSON, and so are
//! its extensions: the build lists their types here, and its options
//! select instances of them. Nothing in a config file names one — the
//! stock binary's JSON cannot reach this seam at all.
//!
//! Every part of the serving path is generic over a `Runtime`, the one
//! comptime value that says what a server is built from. The stock
//! binary's runtime has empty lists, and an empty list compiles every
//! extension call out of it.

const std = @import("std");

const assert = std.debug.assert;

/// The extension types one build carries, as comptime lists. A cluster or
/// a listener selects an *instance* of one of these in code; a type the
/// build does not list cannot be selected.
pub const Extensions = struct {
    /// Endpoint pickers a cluster may select (§7).
    pickers: []const type = &.{},
    /// Request policies a listener or a route may select (§7).
    request_policies: []const type = &.{},
};

/// What a server is built from: the Io backend (§4) and the build's
/// extensions. A struct *value* rather than a type, so a server reads as
/// `Server(.{ .Io = SimIo })` — and Zig memoizes a generic on a comptime
/// value, so every part instantiating `Server(runtime)` with the same
/// runtime gets the same type.
pub const Runtime = struct {
    Io: type,
    extensions: Extensions = .{},
};

test "extension: equal runtimes name the same server" {
    // The whole serving path re-instantiates its siblings from the one
    // runtime it was given, so two spellings of the same value must
    // produce one type — or a connection's server would not be the
    // server that admitted it.
    const Probe = struct {
        fn Built(comptime runtime: Runtime) type {
            return struct {
                pub const io = runtime.Io;
            };
        }
    };
    const Io = struct {};
    const Picker = struct {};
    const first = Probe.Built(.{ .Io = Io, .extensions = .{ .pickers = &.{Picker} } });
    const second = Probe.Built(.{ .Io = Io, .extensions = .{ .pickers = &.{Picker} } });
    comptime assert(first == second);
    comptime assert(Probe.Built(.{ .Io = Io }) == Probe.Built(.{ .Io = Io, .extensions = .{} }));
    comptime assert(first != Probe.Built(.{ .Io = Io }));
}
