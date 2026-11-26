//! The resolver over the simulator (#481): a cluster that follows a name,
//! nameservers that answer as each scenario scripts them on SimIo's
//! datagrams, and the drain at a virtual time. What each run is held to:
//! the cluster's set is what the answers say — its own addresses and the
//! names', each once — or, when no answer comes, the set it had; every
//! query begun ends in one outcome (`Resolver.reconciles`); and the drain
//! leaves nothing armed.
//!
//! The sweep's seeds put the datagram adversary under it: replies and
//! queries dropped, duplicated, corrupted, delayed past one another, and
//! sockets rebound to new ports, which turns a nameserver's reply into
//! one from a peer the resolver never asked.

const std = @import("std");

const config_module = @import("../config.zig");
const constants = @import("../constants.zig");
const extension = @import("../extension.zig");
const Io = @import("../io/io.zig");
const Options = @import("../Options.zig");
const Server = @import("../Server.zig").Server;
const SimIo = @import("../io/SimIo.zig");
const message = @import("message.zig");

const assert = std.debug.assert;

const IpAddress = std.Io.net.IpAddress;
const runtime: extension.Runtime = .{ .Io = SimIo, .extensions = .{} };
const ServerSim = Server(runtime);

fn ip(literal: []const u8) IpAddress {
    return IpAddress.parseLiteral(literal) catch unreachable;
}

const nameserver_addresses = [_]IpAddress{ ip("10.53.0.1:53"), ip("10.53.0.2:53") };

/// What a nameserver does with each query.
const Behavior = enum {
    answer,
    servfail,
    nxdomain,
    truncated,
    silent,
    /// A reply under another ID first, then the answer.
    wrong_id_first,
};

/// The zone the scripted nameservers serve: the name's addresses, which
/// change by phase — each phase's from its start until the next's.
const Zone = struct {
    phases: []const Phase,
    behaviors: [2]Behavior,
    /// The simulator's clock when the server started: phases count from it.
    start_ns: u64,
    /// The TTL every answer carries.
    ttl_s: u32,
    queries_seen: u32 = 0,

    const Phase = struct {
        from_ns: u64,
        addresses: []const IpAddress,
    };

    fn addressesAt(zone: *const Zone, now_ns: u64) []const IpAddress {
        assert(zone.phases.len >= 1);
        assert(now_ns >= zone.start_ns);
        var current = zone.phases[0].addresses;
        for (zone.phases) |*phase| {
            if (phase.from_ns <= now_ns - zone.start_ns) current = phase.addresses;
        }
        return current;
    }
};

/// One scripted nameserver on the simulator's datagrams.
const Nameserver = struct {
    io: *SimIo,
    zone: *Zone,
    index: u8,
    socket: SimIo.UdpSocket,
    buffer: [SimIo.datagram_bytes_max]u8,
    receive: SimIo.DatagramCompletion,
    sends: [8]Send,

    const Send = struct {
        bytes: [constants.dns_message_bytes_max]u8,
        completion: SimIo.DatagramCompletion,
        armed: bool,
    };

    fn start(nameserver: *Nameserver, io: *SimIo, zone: *Zone, index: u8) !void {
        nameserver.* = .{
            .io = io,
            .zone = zone,
            .index = index,
            .socket = try io.udpBind(nameserver_addresses[index]),
            .buffer = undefined,
            .receive = .{},
            .sends = undefined,
        };
        for (&nameserver.sends) |*send| send.* = .{ .bytes = undefined, .completion = .{}, .armed = false };
        io.recvFrom(nameserver.socket, &nameserver.buffer, &nameserver.receive, Nameserver, nameserver, onReceive);
    }

    fn onReceive(nameserver: *Nameserver, result: Io.RecvFromError!Io.Datagram) void {
        // The run ends with the server's drain; nothing cancels this.
        const datagram = result catch unreachable;
        nameserver.answer(nameserver.buffer[0..datagram.len], &datagram.peer);
        nameserver.io.recvFrom(nameserver.socket, &nameserver.buffer, &nameserver.receive, Nameserver, nameserver, onReceive);
    }

    fn answer(nameserver: *Nameserver, bytes: []const u8, peer: *const IpAddress) void {
        // A corrupted datagram may be no query at all.
        const question = message.readQuery(bytes) orelse return;
        nameserver.zone.queries_seen += 1;
        const addresses = nameserver.zone.addressesAt(nameserver.io.nowNs());
        switch (nameserver.zone.behaviors[nameserver.index]) {
            .silent => {},
            .answer => nameserver.reply(&question, &.{ .addresses = addresses, .ttl_s = nameserver.zone.ttl_s }, peer),
            .servfail => nameserver.reply(&question, &.{ .rcode = 2 }, peer),
            .nxdomain => nameserver.reply(&question, &.{ .rcode = 3 }, peer),
            .truncated => nameserver.reply(&question, &.{ .truncated = true, .addresses = addresses }, peer),
            .wrong_id_first => {
                nameserver.reply(&question, &.{ .addresses = &.{ip("10.66.0.66:9000")}, .id = question.id +% 1 }, peer);
                nameserver.reply(&question, &.{ .addresses = addresses, .ttl_s = nameserver.zone.ttl_s }, peer);
            },
        }
    }

    fn reply(nameserver: *Nameserver, question: *const message.Question, script: *const message.Answer, peer: *const IpAddress) void {
        // A nameserver with every send out drops the query, as a busy one
        // would; the resolver's timeout is what answers that.
        const send = for (&nameserver.sends) |*send| {
            if (!send.armed) break send;
        } else return;
        const bytes = message.writeReply(&send.bytes, question, script);
        send.armed = true;
        nameserver.io.sendTo(nameserver.socket, bytes, 0, peer, &send.completion, Send, send, onSend);
    }

    fn onSend(send: *Send, result: Io.SendToError!u32) void {
        // A reply the network lost is the resolver's timeout to answer,
        // which is what these scenarios hold it to.
        _ = result catch {};
        assert(send.armed);
        send.armed = false;
    }
};

/// A server whose one cluster follows `api.test`, starting at 10.0.0.1,
/// beside a literal of its own when `literal` says so.
const Scenario = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    options: Options,
    config: config_module.Config,
    server: ServerSim,
    zone: Zone,
    nameservers: [2]Nameserver,

    const Settings = struct {
        seed: u64,
        adversary: SimIo.Adversary = .{},
        phases: []const Zone.Phase,
        behaviors: [2]Behavior = .{ .answer, .answer },
        literal: bool = false,
        addresses_max: u16 = 4,
        ttl_s: u32 = 0,
        refresh_max_ms: u32 = 400,
    };

    const listeners = [_]Options.Listener{.{
        .bind = .{ .ip = ip("127.0.0.1:8080") },
        .protocol = .{ .l4 = .{ .target = .{ .cluster = "api" } } },
    }};
    const literals = [_]Options.Cluster.Endpoint{.{ .address = .{ .ip = ip("10.0.0.9:9000") } }};

    fn setUp(scenario: *Scenario, gpa: std.mem.Allocator, settings: *const Settings) !void {
        scenario.arena_state = .init(gpa);
        errdefer scenario.arena_state.deinit();
        const arena = scenario.arena_state.allocator();
        const names = try arena.alloc(Options.Cluster.Dns.Name, 1);
        names[0] = .{ .host = "api.test", .port = 9000, .addresses = &.{ip("10.0.0.1:9000")} };
        const clusters = try arena.alloc(Options.Cluster, 1);
        clusters[0] = .{
            .name = "api",
            .endpoints = if (settings.literal) &literals else &.{},
            .pick = .p2c,
            .dns = .{ .names = names, .refresh_min_ms = 100, .refresh_max_ms = settings.refresh_max_ms, .addresses_max = settings.addresses_max },
        };
        scenario.options = .{
            .listeners = &listeners,
            .clusters = clusters,
            .timeouts = .{ .connect_ms = 50, .idle_ms = 1000, .head_ms = 100, .tunnel_ms = 60_000, .health_interval_ms = 1000 },
            .limits = .{ .conn_slots = 4, .relay_buffers = 2, .upstream_slots = 2 },
            .resolver = .{ .nameservers = &nameserver_addresses, .timeout_ms = 40 },
        };
        scenario.config = try config_module.resolve(arena, &scenario.options);
        const limits = scenario.config.limits;
        try scenario.sim_io.init(arena, .{
            .seed = settings.seed,
            .adversary = settings.adversary,
            .buffer_group_count = limits.head_buffers,
            .buffer_group_bytes = limits.head_buffer_bytes,
        });
        try scenario.server.init(arena, &scenario.sim_io, &scenario.config, limits);
        try scenario.server.bindExtensions(&.{ .arena = arena });
        scenario.zone = .{
            .phases = settings.phases,
            .behaviors = settings.behaviors,
            .start_ns = scenario.sim_io.nowNs(),
            .ttl_s = settings.ttl_s,
        };
        for (&scenario.nameservers, 0..) |*nameserver, index| {
            try nameserver.start(&scenario.sim_io, &scenario.zone, @intCast(index));
        }
        try scenario.server.start();
    }

    fn tearDown(scenario: *Scenario) void {
        scenario.arena_state.deinit();
    }

    /// Serve until a drain begun at `drain_at_ms` has finished.
    fn run(scenario: *Scenario, drain_at_ms: u64) !void {
        scenario.sim_io.scheduleSignal(.terminate, scenario.zone.start_ns + drain_at_ms * std.time.ns_per_ms);
        try scenario.sim_io.run();
        try std.testing.expect(scenario.server.isIdle());
        try std.testing.expect(scenario.server.reconcile());
    }

    fn counter(scenario: *const Scenario, comptime name: []const u8) u64 {
        return scenario.server.counters.get(name);
    }

    /// Whether the cluster's live set is exactly `expected`.
    fn expectLive(scenario: *const Scenario, expected: []const IpAddress) !void {
        const slots = scenario.server.config.clusters[0].slots.?;
        var live: u32 = 0;
        for (slots.states, slots.addresses) |state, *address| {
            if (state != .live) continue;
            live += 1;
            const listed = for (expected) |*wanted| {
                if (address.ip.eql(wanted)) break true;
            } else false;
            try std.testing.expect(listed);
        }
        try std.testing.expectEqual(expected.len, live);
    }
};

test "resolver: a cluster follows its name to where it moved, and stays (#481)" {
    const scenario = try std.testing.allocator.create(Scenario);
    defer std.testing.allocator.destroy(scenario);
    try scenario.setUp(std.testing.allocator, &.{
        .seed = 4811,
        .phases = &.{.{ .from_ns = 0, .addresses = &.{ ip("10.0.0.3:1"), ip("10.0.0.2:1") } }},
        .literal = true,
    });
    defer scenario.tearDown();
    try scenario.expectLive(&.{ ip("10.0.0.9:9000"), ip("10.0.0.1:9000") });
    try scenario.run(700);
    // The literal stays; the name's old address left, its new ones came.
    try scenario.expectLive(&.{ ip("10.0.0.9:9000"), ip("10.0.0.2:9000"), ip("10.0.0.3:9000") });
    try std.testing.expect(scenario.counter("dns_answered") >= 2);
    // One set taken, when the answer changed; the rounds after it found
    // nothing new to give.
    try std.testing.expectEqual(@as(u64, 1), scenario.counter("dns_updates_applied"));
    try std.testing.expectEqual(@as(u64, 1), scenario.counter("endpoints_departed"));
    try std.testing.expectEqual(@as(u64, 0), scenario.counter("dns_replies_dropped"));
}

test "resolver: a nameserver that fails hands the query on; when all do, the set stays (#481)" {
    const moved = [_]Zone.Phase{.{ .from_ns = 0, .addresses = &.{ip("10.0.0.2:1")} }};
    {
        const scenario = try std.testing.allocator.create(Scenario);
        defer std.testing.allocator.destroy(scenario);
        try scenario.setUp(std.testing.allocator, &.{ .seed = 4812, .phases = &moved, .behaviors = .{ .servfail, .answer } });
        defer scenario.tearDown();
        try scenario.run(300);
        try scenario.expectLive(&.{ip("10.0.0.2:9000")});
        try std.testing.expect(scenario.counter("dns_servfail") >= 1);
        try std.testing.expect(scenario.counter("dns_answered") >= 1);
    }
    {
        const scenario = try std.testing.allocator.create(Scenario);
        defer std.testing.allocator.destroy(scenario);
        try scenario.setUp(std.testing.allocator, &.{ .seed = 4813, .phases = &moved, .behaviors = .{ .silent, .nxdomain } });
        defer scenario.tearDown();
        try scenario.run(500);
        try scenario.expectLive(&.{ip("10.0.0.1:9000")});
        try std.testing.expect(scenario.counter("dns_timed_out") >= 1);
        try std.testing.expect(scenario.counter("dns_nxdomain") >= 1);
        try std.testing.expectEqual(@as(u64, 0), scenario.counter("dns_updates_applied"));
    }
}

test "resolver: a reply not the attempt's is dropped, and a truncated one changes nothing (#481)" {
    const moved = [_]Zone.Phase{.{ .from_ns = 0, .addresses = &.{ip("10.0.0.2:1")} }};
    {
        const scenario = try std.testing.allocator.create(Scenario);
        defer std.testing.allocator.destroy(scenario);
        try scenario.setUp(std.testing.allocator, &.{ .seed = 4814, .phases = &moved, .behaviors = .{ .wrong_id_first, .answer } });
        defer scenario.tearDown();
        try scenario.run(300);
        // The forged address never joined; the answer behind it did.
        try scenario.expectLive(&.{ip("10.0.0.2:9000")});
        try std.testing.expect(scenario.counter("dns_replies_dropped") >= 1);
    }
    {
        const scenario = try std.testing.allocator.create(Scenario);
        defer std.testing.allocator.destroy(scenario);
        try scenario.setUp(std.testing.allocator, &.{ .seed = 4815, .phases = &moved, .behaviors = .{ .truncated, .truncated } });
        defer scenario.tearDown();
        try scenario.run(300);
        try scenario.expectLive(&.{ip("10.0.0.1:9000")});
        try std.testing.expect(scenario.counter("dns_truncated") >= 1);
    }
}

/// One scenario, set up, run to `drain_at_ms` and torn down by the caller.
fn runScenario(settings: *const Scenario.Settings, drain_at_ms: u64) !*Scenario {
    const scenario = try std.testing.allocator.create(Scenario);
    errdefer std.testing.allocator.destroy(scenario);
    try scenario.setUp(std.testing.allocator, settings);
    errdefer scenario.tearDown();
    try scenario.run(drain_at_ms);
    return scenario;
}

fn endScenario(scenario: *Scenario) void {
    scenario.tearDown();
    std.testing.allocator.destroy(scenario);
}

test "resolver: a name's TTL paces its refresh, held between the floor and the ceiling (#481)" {
    const phases = [_]Zone.Phase{.{ .from_ns = 0, .addresses = &.{ip("10.0.0.1:1")} }};
    // Over 2.5 s: a TTL of zero asks at the floor, every 100–110 ms; one
    // second, at about 1.0–1.1 s; thirty, cut to the 5 s ceiling — the
    // first round alone, which always waits the floor.
    const paces = [_]struct { ttl_s: u32, at_least: u64, at_most: u64 }{
        .{ .ttl_s = 0, .at_least = 20, .at_most = 25 },
        .{ .ttl_s = 1, .at_least = 3, .at_most = 3 },
        .{ .ttl_s = 30, .at_least = 1, .at_most = 1 },
    };
    for (paces, 0..) |pace, index| {
        const scenario = try runScenario(&.{
            .seed = 4816 + index,
            .phases = &phases,
            .ttl_s = pace.ttl_s,
            .refresh_max_ms = 5_000,
        }, 2_500);
        defer endScenario(scenario);
        const sent = scenario.counter("dns_queries_sent");
        try std.testing.expect(sent >= pace.at_least);
        try std.testing.expect(sent <= pace.at_most);
        try std.testing.expectEqual(sent, scenario.counter("dns_answered"));
    }
}

test "resolver: a set with no endpoint is refused, and the cluster keeps the one it has (#481)" {
    // The name answers with no address at all, and the cluster has none
    // of its own: the set it is offered would send it nowhere.
    const scenario = try runScenario(&.{
        .seed = 4819,
        .phases = &.{.{ .from_ns = 0, .addresses = &.{} }},
    }, 400);
    defer endScenario(scenario);
    try scenario.expectLive(&.{ip("10.0.0.1:9000")});
    try std.testing.expect(scenario.counter("dns_answered") >= 2);
    // Refused at every round, since a refused set stays owed.
    try std.testing.expect(scenario.counter("dns_updates_refused") >= 2);
    try std.testing.expectEqual(@as(u64, 0), scenario.counter("dns_updates_applied"));
}

test "resolver: an answer past `addresses_max` keeps the first in address order (#481)" {
    const scenario = try runScenario(&.{
        .seed = 4820,
        .phases = &.{.{ .from_ns = 0, .addresses = &.{ ip("10.0.0.7:1"), ip("10.0.0.3:1"), ip("10.0.0.5:1"), ip("10.0.0.3:1") } }},
        .addresses_max = 2,
    }, 300);
    defer endScenario(scenario);
    try scenario.expectLive(&.{ ip("10.0.0.3:9000"), ip("10.0.0.5:9000") });
    try std.testing.expect(scenario.counter("dns_answers_truncated") >= 1);
}

test "resolver: every nameserver failing keeps the set, and the round asks again at the floor (#481)" {
    const scenario = try runScenario(&.{
        .seed = 4821,
        .phases = &.{.{ .from_ns = 0, .addresses = &.{ip("10.0.0.2:1")} }},
        .behaviors = .{ .servfail, .servfail },
    }, 400);
    defer endScenario(scenario);
    try scenario.expectLive(&.{ip("10.0.0.1:9000")});
    // Two nameservers a round, every round at the floor.
    try std.testing.expect(scenario.counter("dns_servfail") >= 4);
    try std.testing.expectEqual(@as(u64, 0), scenario.counter("dns_answered"));
}

test "resolver: a drain mid-round counts the attempt out canceled, and closes (#481)" {
    // The first round begins 100–110 ms in, and its attempt waits 40 ms
    // on a silent nameserver: the drain at 115 ms finds it out.
    const scenario = try runScenario(&.{
        .seed = 4822,
        .phases = &.{.{ .from_ns = 0, .addresses = &.{ip("10.0.0.2:1")} }},
        .behaviors = .{ .silent, .silent },
    }, 115);
    defer endScenario(scenario);
    try std.testing.expectEqual(@as(u64, 1), scenario.counter("dns_queries_sent"));
    try std.testing.expectEqual(@as(u64, 1), scenario.counter("dns_canceled"));
    try std.testing.expectEqual(@as(u64, 0), scenario.counter("dns_timed_out"));
    try scenario.expectLive(&.{ip("10.0.0.1:9000")});
}

/// Three sets, every one a full rotation of the one before, at a pace the
/// refresh floor can follow: each takes its slots while the last drains,
/// nothing holding the drained ones.
const rotating_phases = [_]Zone.Phase{
    .{ .from_ns = 0, .addresses = &.{ ip("10.0.1.1:1"), ip("10.0.1.2:1") } },
    .{ .from_ns = 400 * std.time.ns_per_ms, .addresses = &.{ ip("10.0.2.1:1"), ip("10.0.2.2:1") } },
    .{ .from_ns = 800 * std.time.ns_per_ms, .addresses = &.{ip("10.0.3.1:1")} },
};

/// What a set may hold: the name's startup address, or one some phase
/// answered with.
fn answeredSomewhere(address: *const IpAddress) bool {
    if (address.eql(&ip("10.0.0.1:9000"))) return true;
    for (&rotating_phases) |*phase| {
        for (phase.addresses) |*answered| {
            var placed = answered.*;
            placed.setPort(9000);
            if (address.eql(&placed)) return true;
        }
    }
    return false;
}

test "resolver: on a quiet network the set ends where the answers did, whoever asked first (#481)" {
    const behaviors = [_]Behavior{ .answer, .servfail, .silent, .wrong_id_first };
    for (behaviors, 0..) |first, index| {
        const scenario = try runScenario(&.{
            .seed = 4830 + index,
            .phases = &rotating_phases,
            .behaviors = .{ first, .answer },
            .addresses_max = 2,
        }, 1_600);
        defer endScenario(scenario);
        // The last phase began 800 ms in, and every round since asked it.
        try scenario.expectLive(&.{ip("10.0.3.1:9000")});
        try std.testing.expect(scenario.counter("dns_updates_applied") >= 3);
        try std.testing.expectEqual(@as(u64, 0), scenario.counter("dns_updates_refused"));
    }
}

test "resolver: under the datagram adversary the set only ever holds what was answered (#481)" {
    var followed: u32 = 0;
    var seed: u64 = 1;
    while (seed <= 24) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();
        const behaviors = [_]Behavior{ .answer, .servfail, .silent, .wrong_id_first };
        const scenario = try runScenario(&.{
            .seed = seed,
            .adversary = .{
                .udp_drop_percent = random.uintAtMost(u8, 20),
                .udp_duplicate_percent = random.uintAtMost(u8, 20),
                .udp_corrupt_percent = random.uintAtMost(u8, 10),
                .udp_delay_ns_max = random.uintAtMost(u64, 30) * std.time.ns_per_ms,
                .udp_rebind_percent = random.uintAtMost(u8, 5),
            },
            .phases = &rotating_phases,
            .behaviors = .{ behaviors[random.uintLessThan(usize, behaviors.len)], .answer },
            .addresses_max = 2,
        }, 1_600);
        defer endScenario(scenario);
        // Whatever the network did, the set is never empty, and holds the
        // startup address or ones the nameservers answered — never the
        // forged one a wrong-ID reply carries.
        const slots = scenario.server.config.clusters[0].slots.?;
        var live: u32 = 0;
        for (slots.states, slots.addresses) |state, *address| {
            if (state != .live) continue;
            live += 1;
            try std.testing.expect(answeredSomewhere(&address.ip));
        }
        try std.testing.expect(live >= 1);
        if (scenario.counter("dns_updates_applied") >= 1) followed += 1;
    }
    // A rebound nameserver's every later reply comes from a peer never
    // asked, so a seed may follow nothing; most do.
    try std.testing.expect(followed >= 16);
}
