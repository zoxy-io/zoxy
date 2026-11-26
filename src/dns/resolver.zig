//! The resolver (#481): every cluster that follows names asks their
//! records again as each answer's TTL runs out, and its endpoint set is
//! made of what they answer — through #428's `endpoint_sets.replace`, so
//! an address that leaves drains, one that arrives is probed first, and
//! one that stays keeps its slot, its health and its connections.
//!
//! The shape is the prober's (`net/health.zig`): one loop citizen, every
//! op it may arm reserved at startup and priced in the ring
//! (`constants.resolverOps`), a drain that cancels what is armed and
//! waits for the rest.
//!
//! - **Sockets.** One UDP socket per address family the nameservers are
//!   in, bound to the unspecified address on a port the kernel picks, a
//!   receive always armed on it.
//! - **Queries.** One per name and record type (`Config.dnsQueries`),
//!   each holding the addresses its last answer gave — the startup
//!   resolution's, to begin with. An attempt asks one nameserver under a
//!   fresh random ID; no reply within `timeout_ms`, or a SERVFAIL, asks
//!   the next; past the last, the query fails this round and keeps what
//!   it had.
//! - **Rounds.** Each cluster's queries run together. When the last
//!   settles, the cluster takes a new set if any answer changed: its own
//!   addresses and every query's, each address once
//!   (`dns.endpoints.mergeDuplicates`). The next round waits the least
//!   TTL the round saw, held between the cluster's refresh bounds — the
//!   floor after any failure — plus up to a tenth more, drawn, so
//!   processes started together do not ask together for ever.
//! - **One timer**, armed at the earliest deadline or due round, and
//!   never further out than half the shorter of the query timeout and
//!   the refresh floor: an event the timer was not armed for — a round
//!   that finished on a reply, an attempt begun on a SERVFAIL — waits at
//!   most that long, and the timer is never cancelled but by the drain.
//!
//! A reply is believed only as `dns/message.zig` lets it prove itself,
//! and only from the nameserver the attempt asked, under the attempt's
//! ID. Anything else is counted (`dns_replies_dropped`) and dropped.

const std = @import("std");

const config_module = @import("../config.zig");
const constants = @import("../constants.zig");
const counters_module = @import("../counters.zig");
const extension = @import("../extension.zig");
const Runtime = extension.Runtime;
const Io = @import("../io/io.zig");
const Options = @import("../Options.zig");
const dns_endpoints = @import("endpoints.zig");
const message = @import("message.zig");

const assert = std.debug.assert;

const IpAddress = std.Io.net.IpAddress;
const SetEndpoint = extension.EndpointSet.Endpoint;
const ClusterDns = config_module.Config.Cluster.Dns;

/// The outcome counters a query's attempt ends in, one each.
const attempt_outcomes = [_][]const u8{
    "dns_answered",
    "dns_nxdomain",
    "dns_servfail",
    "dns_truncated",
    "dns_timed_out",
    "dns_canceled",
};

pub fn Resolver(comptime runtime: Runtime) type {
    const IoType = runtime.Io;
    const ServerType = @import("../Server.zig").Server(runtime);

    return struct {
        const Self = @This();

        server: *ServerType,
        state: State,
        sockets: [2]Socket,
        sockets_count: u8,
        queries: []Query,
        rounds: []Round,
        /// One cluster's set as a round builds it: sized for the widest.
        set: []SetEndpoint,
        /// One reply's addresses, read before the reply is believed.
        reply_room: [constants.dns_addresses_max]IpAddress,
        timer: IoType.Completion,
        timer_cancel: IoType.Completion,
        timer_armed: bool,
        timer_cancel_armed: bool,
        timer_canceled: bool,
        /// Every op armed: the timer and its cancel, each socket's
        /// receive and its cancel, each query's send.
        armed: u32,

        const State = enum { off, running, stopping, stopped };

        const Socket = struct {
            resolver: *Self,
            family: IpAddress.Family,
            socket: IoType.UdpSocket,
            /// One past the largest reply taken: a datagram that fills it
            /// may have been cut, and is dropped.
            buffer: [constants.dns_message_bytes_max + 1]u8,
            receive: IoType.DatagramCompletion,
            cancel: IoType.Completion,
            receive_armed: bool,
            cancel_armed: bool,
            canceled: bool,
        };

        const Query = struct {
            resolver: *Self,
            round: u16,
            name: *const Options.Cluster.Dns.Name,
            record_type: message.RecordType,
            /// What its last answer gave, in address order: room for the
            /// cluster's `addresses_max`.
            addresses: []IpAddress,
            addresses_count: u16,
            waiting: bool,
            id: u16,
            nameserver_index: u8,
            deadline_ns: u64,
            /// This round's answer, once settled: whether it came, and
            /// its TTL.
            answered: bool,
            ttl_s: u32,
            send: IoType.DatagramCompletion,
            send_armed: bool,
            /// An attempt began while the last one's send was still out:
            /// its bytes go once that send completes, never over it.
            send_owed: bool,
            send_buffer: [message.query_bytes_max]u8,
        };

        const Round = struct {
            cluster_index: u16,
            dns: *const ClusterDns,
            queries_index: u32,
            queries_count: u32,
            running: bool,
            /// Queries this round has not settled.
            pending: u32,
            failed: bool,
            ttl_s: u32,
            /// Answers changed since the cluster last took a set: true
            /// until one is taken, so a refused set is offered again.
            dirty: bool,
            due_ns: u64,
        };

        /// The banner's term (§5): everything `init` reserves for `config`.
        pub fn bytesFor(config: *const config_module.Config) u64 {
            var total: u64 = 0;
            var set_max: u64 = 0;
            for (config.clusters) |*cluster| {
                const dns = cluster.dns orelse continue;
                const queries: u64 = dns.queries();
                total += @sizeOf(Round) + queries * (@sizeOf(Query) + @as(u64, dns.addresses_max) * @sizeOf(IpAddress));
                set_max = @max(set_max, setCapacity(dns));
            }
            return total + set_max * @sizeOf(SetEndpoint);
        }

        /// The widest set a round of `dns` builds: its own addresses and
        /// every query's room.
        fn setCapacity(dns: *const ClusterDns) u64 {
            return dns.literals.len + @as(u64, dns.queries()) * dns.addresses_max;
        }

        pub fn init(resolver: *Self, arena: std.mem.Allocator, server: *ServerType) error{OutOfMemory}!void {
            resolver.* = .{
                .server = server,
                .state = .off,
                .sockets = undefined,
                .sockets_count = 0,
                .queries = &.{},
                .rounds = &.{},
                .set = &.{},
                .reply_room = undefined,
                .timer = .{},
                .timer_cancel = .{},
                .timer_armed = false,
                .timer_cancel_armed = false,
                .timer_canceled = false,
                .armed = 0,
            };
            const config = server.config;
            const queries_count = config.dnsQueries();
            if (queries_count == 0) return;
            var rounds_count: u32 = 0;
            var set_max: u64 = 0;
            for (config.clusters) |*cluster| {
                const dns = cluster.dns orelse continue;
                rounds_count += 1;
                set_max = @max(set_max, setCapacity(dns));
            }
            resolver.queries = try arena.alloc(Query, queries_count);
            resolver.rounds = try arena.alloc(Round, rounds_count);
            resolver.set = try arena.alloc(SetEndpoint, set_max);
            try resolver.initRounds(arena);
            assert(resolver.armed == 0);
            assert(resolver.rounds.len >= 1);
        }

        fn initRounds(resolver: *Self, arena: std.mem.Allocator) error{OutOfMemory}!void {
            var round_index: u16 = 0;
            var query_index: u32 = 0;
            for (resolver.server.config.clusters, 0..) |*cluster, cluster_index| {
                const dns = cluster.dns orelse continue;
                assert(cluster.slots != null);
                resolver.rounds[round_index] = .{
                    .cluster_index = @intCast(cluster_index),
                    .dns = dns,
                    .queries_index = query_index,
                    .queries_count = dns.queries(),
                    .running = false,
                    .pending = 0,
                    .failed = false,
                    .ttl_s = 0,
                    .dirty = false,
                    .due_ns = 0,
                };
                for (dns.names) |*name| {
                    const types: []const message.RecordType = switch (name.family) {
                        .ipv4 => &.{.a},
                        .ipv6 => &.{.aaaa},
                        .any => &.{ .a, .aaaa },
                    };
                    for (types) |record_type| {
                        const query = &resolver.queries[query_index];
                        try resolver.initQuery(arena, query, round_index, name, record_type, dns.addresses_max);
                        query_index += 1;
                    }
                }
                round_index += 1;
            }
            assert(round_index == resolver.rounds.len);
            assert(query_index == resolver.queries.len);
        }

        /// A query begins from the addresses its name had at startup, of
        /// its record type, in address order.
        fn initQuery(
            resolver: *Self,
            arena: std.mem.Allocator,
            query: *Query,
            round: u16,
            name: *const Options.Cluster.Dns.Name,
            record_type: message.RecordType,
            addresses_max: u16,
        ) error{OutOfMemory}!void {
            assert(addresses_max >= 1);
            query.* = .{
                .resolver = resolver,
                .round = round,
                .name = name,
                .record_type = record_type,
                .addresses = try arena.alloc(IpAddress, addresses_max),
                .addresses_count = 0,
                .waiting = false,
                .id = 0,
                .nameserver_index = 0,
                .deadline_ns = 0,
                .answered = false,
                .ttl_s = 0,
                .send = .{},
                .send_armed = false,
                .send_owed = false,
                .send_buffer = undefined,
            };
            for (name.addresses) |address| {
                if (!typeOf(&address, record_type)) continue;
                // Held to `addresses_max` per family at resolve.
                assert(query.addresses_count < addresses_max);
                query.addresses[query.addresses_count] = address;
                query.addresses_count += 1;
            }
            dns_endpoints.sortAddresses(query.addresses[0..query.addresses_count]);
        }

        fn typeOf(address: *const IpAddress, record_type: message.RecordType) bool {
            return switch (address.*) {
                .ip4 => record_type == .a,
                .ip6 => record_type == .aaaa,
            };
        }

        /// Open a socket per nameserver family and schedule each cluster's
        /// first refresh, or stay `.off` when no cluster follows names. A
        /// start that fails — a socket the kernel would not bind — fails
        /// `Server.start`, and with it the process: nothing drains a
        /// resolver that never ran.
        pub fn start(resolver: *Self) Io.ListenError!void {
            assert(resolver.state == .off);
            assert(resolver.armed == 0);
            if (resolver.queries.len == 0) return;
            const nameservers = resolver.server.config.resolver.?.nameservers;
            for ([_]IpAddress.Family{ .ip4, .ip6 }) |family| {
                const used = for (nameservers) |*nameserver| {
                    if (nameserver.* == family) break true;
                } else false;
                if (used) try resolver.openSocket(family);
            }
            assert(resolver.sockets_count == resolver.server.config.dnsSockets());
            resolver.state = .running;
            const now_ns = resolver.server.io.nowNs();
            for (resolver.rounds) |*round| {
                const floor_ns = @as(u64, round.dns.refresh_min_ms) * std.time.ns_per_ms;
                round.due_ns = now_ns + floor_ns + resolver.jitterNs(floor_ns);
            }
            resolver.armTimer(now_ns);
        }

        fn openSocket(resolver: *Self, family: IpAddress.Family) Io.ListenError!void {
            assert(resolver.sockets_count < resolver.sockets.len);
            const unspecified: IpAddress = switch (family) {
                .ip4 => .{ .ip4 = .unspecified(0) },
                .ip6 => .{ .ip6 = .unspecified(0) },
            };
            const socket = &resolver.sockets[resolver.sockets_count];
            socket.* = .{
                .resolver = resolver,
                .family = family,
                .socket = try resolver.server.io.udpBind(unspecified),
                .buffer = undefined,
                .receive = .{},
                .cancel = .{},
                .receive_armed = false,
                .cancel_armed = false,
                .canceled = false,
            };
            resolver.sockets_count += 1;
            resolver.armReceive(socket);
        }

        /// Drain (§8): no attempt out counts any more, and every armed
        /// op is cancelled or waited for; the sockets close once none is.
        pub fn beginStop(resolver: *Self) void {
            switch (resolver.state) {
                .off => {
                    assert(resolver.armed == 0);
                    resolver.state = .stopped;
                    return;
                },
                .stopping, .stopped => return,
                .running => {},
            }
            assert(resolver.timer_armed);
            resolver.state = .stopping;
            for (resolver.queries) |*query| {
                if (!query.waiting) continue;
                query.waiting = false;
                query.send_owed = false;
                resolver.server.counters.increment("dns_canceled");
            }
            resolver.continueStop();
        }

        pub fn isQuiescent(resolver: *const Self) bool {
            if (resolver.state == .running) assert(resolver.armed >= 1);
            return resolver.armed == 0;
        }

        /// The attempt identity (#481): every query begun has ended in one
        /// outcome, or is out.
        pub fn reconciles(resolver: *const Self, counters: *const counters_module.Counters) void {
            var ended: u64 = 0;
            inline for (attempt_outcomes) |name| ended += counters.get(name);
            var waiting: u64 = 0;
            for (resolver.queries) |*query| waiting += @intFromBool(query.waiting);
            assert(counters.get("dns_queries_sent") == ended + waiting);
            assert(waiting <= resolver.queries.len);
        }

        fn continueStop(resolver: *Self) void {
            assert(resolver.state == .stopping);
            const io = resolver.server.io;
            if (resolver.timer_armed and !resolver.timer_canceled) {
                resolver.timer_canceled = true;
                resolver.timer_cancel_armed = true;
                resolver.armed += 1;
                io.timerCancel(&resolver.timer, &resolver.timer_cancel, Self, resolver, onTimerCancel);
            }
            for (resolver.sockets[0..resolver.sockets_count]) |*socket| {
                if (!socket.receive_armed or socket.canceled) continue;
                socket.canceled = true;
                socket.cancel_armed = true;
                resolver.armed += 1;
                io.datagramCancel(&socket.receive, &socket.cancel, Socket, socket, onReceiveCancel);
            }
            if (resolver.armed != 0) return;
            for (resolver.sockets[0..resolver.sockets_count]) |*socket| io.udpClose(socket.socket);
            resolver.state = .stopped;
            resolver.server.maybeStopAfterDrain();
        }

        fn onTimerCancel(resolver: *Self) void {
            assert(resolver.timer_cancel_armed);
            assert(resolver.state == .stopping);
            resolver.timer_cancel_armed = false;
            resolver.armed -= 1;
            resolver.continueStop();
        }

        fn onReceiveCancel(socket: *Socket) void {
            const resolver = socket.resolver;
            assert(socket.cancel_armed);
            assert(resolver.state == .stopping);
            socket.cancel_armed = false;
            resolver.armed -= 1;
            resolver.continueStop();
        }

        // -- the timer --

        /// Arm the one timer at the earliest deadline or due round, within
        /// `tickNs` of now.
        fn armTimer(resolver: *Self, now_ns: u64) void {
            assert(resolver.state == .running);
            assert(!resolver.timer_armed);
            var next_ns: u64 = std.math.maxInt(u64);
            for (resolver.queries) |*query| {
                if (query.waiting) next_ns = @min(next_ns, query.deadline_ns);
            }
            for (resolver.rounds) |*round| {
                if (!round.running) next_ns = @min(next_ns, round.due_ns);
            }
            assert(next_ns != std.math.maxInt(u64)); // A round is due or an attempt is out.
            const delay_ns = std.math.clamp(next_ns -| now_ns, std.time.ns_per_ms, resolver.tickNs());
            resolver.timer_armed = true;
            resolver.armed += 1;
            resolver.server.io.timerStart(&resolver.timer, delay_ns, Self, resolver, onTimer);
        }

        /// The furthest the timer sleeps: half the shorter of the query
        /// timeout and the least refresh floor.
        fn tickNs(resolver: *const Self) u64 {
            var shortest_ms: u64 = resolver.server.config.resolver.?.timeout_ms;
            for (resolver.rounds) |*round| shortest_ms = @min(shortest_ms, round.dns.refresh_min_ms);
            assert(shortest_ms >= @min(constants.dns_timeout_ms_min, constants.dns_refresh_ms_min));
            return @max(std.time.ns_per_ms, @divFloor(shortest_ms * std.time.ns_per_ms, 2));
        }

        fn onTimer(resolver: *Self, result: Io.TimerError!void) void {
            assert(resolver.timer_armed);
            resolver.timer_armed = false;
            resolver.armed -= 1;
            if (resolver.state == .stopping) {
                // A fire or the cancel the drain asked for: either way the
                // timer is done, and `TimerError` is `Canceled` alone.
                result catch {};
                return resolver.continueStop();
            }
            // Only the drain cancels the timer, and it flips `.stopping` first.
            result catch unreachable;
            assert(resolver.state == .running);
            const now_ns = resolver.server.io.nowNs();
            for (resolver.queries) |*query| {
                if (!query.waiting or query.deadline_ns > now_ns) continue;
                resolver.server.counters.increment("dns_timed_out");
                resolver.nextNameserver(query, now_ns);
            }
            for (resolver.rounds) |*round| {
                if (round.running or round.due_ns > now_ns) continue;
                resolver.beginRound(round, now_ns);
            }
            resolver.armTimer(now_ns);
        }

        /// Up to a tenth more than `delay_ns`, drawn: `fillRandom` is the
        /// OS's in production, so processes differ, and the scenario's in
        /// the simulator, so a seed replays.
        fn jitterNs(resolver: *Self, delay_ns: u64) u64 {
            var entropy: [8]u8 = undefined;
            resolver.server.io.fillRandom(&entropy);
            const jitter_ns = std.mem.readInt(u64, &entropy, .little) % (delay_ns / 10 + 1);
            assert(jitter_ns <= delay_ns / 10);
            return jitter_ns;
        }

        // -- rounds and attempts --

        fn beginRound(resolver: *Self, round: *Round, now_ns: u64) void {
            assert(!round.running);
            assert(round.queries_count >= 1);
            round.running = true;
            round.pending = round.queries_count;
            round.failed = false;
            round.ttl_s = std.math.maxInt(u32);
            for (resolver.queries[round.queries_index..][0..round.queries_count]) |*query| {
                assert(!query.waiting);
                query.answered = false;
                resolver.beginAttempt(query, now_ns, 0);
            }
        }

        fn beginAttempt(resolver: *Self, query: *Query, now_ns: u64, nameserver_index: u8) void {
            const config_resolver = resolver.server.config.resolver.?;
            assert(nameserver_index < config_resolver.nameservers.len);
            assert(!query.waiting);
            query.waiting = true;
            query.nameserver_index = nameserver_index;
            query.id = resolver.freshId();
            query.deadline_ns = now_ns + @as(u64, config_resolver.timeout_ms) * std.time.ns_per_ms;
            resolver.server.counters.increment("dns_queries_sent");
            // A send completes as its datagram leaves, before any reply to
            // it and long before its deadline, so the attempt after it
            // finds it delivered. The owed send is for the completion that
            // lags behind both: its buffer is written only once it is.
            if (query.send_armed) {
                query.send_owed = true;
                return;
            }
            resolver.armSend(query);
        }

        /// A random ID no other attempt out holds.
        fn freshId(resolver: *Self) u16 {
            var entropy: [2]u8 = undefined;
            resolver.server.io.fillRandom(&entropy);
            var id = std.mem.readInt(u16, &entropy, .little);
            var tries: u32 = 0;
            // At most one try per query out finds its ID taken.
            while (resolver.idTaken(id)) : (tries += 1) {
                assert(tries <= resolver.queries.len);
                id +%= 1;
            }
            return id;
        }

        fn idTaken(resolver: *const Self, id: u16) bool {
            assert(resolver.queries.len >= 1);
            for (resolver.queries) |*query| {
                if (query.waiting and query.id == id) return true;
            }
            return false;
        }

        fn armSend(resolver: *Self, query: *Query) void {
            assert(query.waiting);
            assert(!query.send_armed);
            const nameserver = &resolver.server.config.resolver.?.nameservers[query.nameserver_index];
            const bytes = message.writeQuery(&query.send_buffer, query.id, query.name.host, query.record_type);
            const socket = resolver.socketFor(nameserver.*);
            query.send_armed = true;
            resolver.armed += 1;
            resolver.server.io.sendTo(socket.socket, bytes, 0, nameserver, &query.send, Query, query, onSend);
        }

        fn socketFor(resolver: *Self, nameserver: IpAddress) *Socket {
            assert(resolver.sockets_count >= 1);
            for (resolver.sockets[0..resolver.sockets_count]) |*socket| {
                if (socket.family == nameserver) return socket;
            }
            unreachable; // `start` opened one for every family asked.
        }

        fn onSend(query: *Query, result: Io.SendToError!u32) void {
            const resolver = query.resolver;
            assert(query.send_armed);
            query.send_armed = false;
            resolver.armed -= 1;
            if (resolver.state == .stopping) return resolver.continueStop();
            // A send that failed leaves its attempt to time out, as a
            // datagram lost on the way would.
            _ = result catch |err| resolver.server.witnessKernelPressure(.send, err);
            if (!query.send_owed) return;
            query.send_owed = false;
            if (query.waiting) resolver.armSend(query);
        }

        fn nextNameserver(resolver: *Self, query: *Query, now_ns: u64) void {
            assert(query.waiting);
            query.waiting = false;
            const next = query.nameserver_index + 1;
            if (next < resolver.server.config.resolver.?.nameservers.len) {
                return resolver.beginAttempt(query, now_ns, next);
            }
            resolver.settle(query, false, now_ns);
        }

        /// A query's round ends for it: answered, or failed and keeping
        /// what it had. The round's last one finishes the round.
        fn settle(resolver: *Self, query: *Query, answered: bool, now_ns: u64) void {
            assert(!query.waiting);
            const round = &resolver.rounds[query.round];
            assert(round.running);
            assert(round.pending >= 1);
            query.answered = answered;
            round.pending -= 1;
            if (answered) round.ttl_s = @min(round.ttl_s, query.ttl_s) else round.failed = true;
            if (round.pending == 0) resolver.finishRound(round, now_ns);
        }

        /// Offer the cluster its new set if an answer changed, then
        /// schedule the next round.
        fn finishRound(resolver: *Self, round: *Round, now_ns: u64) void {
            assert(round.running);
            assert(round.pending == 0);
            round.running = false;
            if (round.dirty) resolver.offerSet(round);
            const dns = round.dns;
            const floor_ms: u64 = dns.refresh_min_ms;
            const ttl_ms: u64 = @as(u64, round.ttl_s) * std.time.ms_per_s;
            const ceiling_ms: u64 = dns.refresh_max_ms;
            const delay_ms = if (round.failed or round.dirty) floor_ms else std.math.clamp(ttl_ms, floor_ms, ceiling_ms);
            const delay_ns = delay_ms * std.time.ns_per_ms;
            round.due_ns = now_ns + delay_ns + resolver.jitterNs(delay_ns);
            assert(round.due_ns > now_ns);
        }

        /// The cluster's own addresses and every query's, each once.
        fn offerSet(resolver: *Self, round: *Round) void {
            assert(round.dirty);
            const dns = round.dns;
            var count: u32 = 0;
            for (dns.literals) |literal| {
                resolver.set[count] = literal;
                count += 1;
            }
            for (resolver.queries[round.queries_index..][0..round.queries_count]) |*query| {
                for (query.addresses[0..query.addresses_count]) |address| {
                    resolver.set[count] = .{ .address = address, .weight = query.name.weight, .priority = query.name.priority };
                    count += 1;
                }
            }
            assert(count <= resolver.set.len);
            const kept = dns_endpoints.mergeDuplicates(SetEndpoint, resolver.set[0..count]);
            if (resolver.server.replaceEndpoints(round.cluster_index, resolver.set[0..kept])) {
                round.dirty = false;
                resolver.server.counters.increment("dns_updates_applied");
            } else |err| {
                // No room while the last set drains, or no endpoint at
                // all: the cluster keeps the set it has, and the round
                // stays dirty so the next one offers again.
                assert(err == error.SlotsExhausted or err == error.EndpointsEmpty);
                resolver.server.counters.increment("dns_updates_refused");
            }
        }

        // -- receiving --

        fn armReceive(resolver: *Self, socket: *Socket) void {
            assert(!socket.receive_armed);
            assert(resolver.state != .stopping);
            socket.receive_armed = true;
            resolver.armed += 1;
            resolver.server.io.recvFrom(socket.socket, &socket.buffer, &socket.receive, Socket, socket, onReceive);
        }

        fn onReceive(socket: *Socket, result: Io.RecvFromError!Io.Datagram) void {
            const resolver = socket.resolver;
            assert(socket.receive_armed);
            socket.receive_armed = false;
            resolver.armed -= 1;
            if (resolver.state == .stopping) return resolver.continueStop();
            assert(resolver.state == .running);
            if (result) |datagram| {
                assert(datagram.len <= socket.buffer.len);
                const cut = datagram.len == socket.buffer.len;
                resolver.dispatch(socket.buffer[0..datagram.len], cut, &datagram.peer);
            } else |err| {
                assert(err != error.Canceled); // Only the drain cancels.
                resolver.server.witnessKernelPressure(.recv, err);
            }
            resolver.armReceive(socket);
        }

        /// A datagram, to the attempt it answers or to the dropped count.
        fn dispatch(resolver: *Self, bytes: []const u8, cut: bool, peer: *const IpAddress) void {
            const query = resolver.attemptFor(bytes, cut, peer) orelse {
                resolver.server.counters.increment("dns_replies_dropped");
                return;
            };
            assert(query.waiting);
            const reply = message.readReply(bytes, query.id, query.name.host, query.record_type, query.name.port, &resolver.reply_room) catch {
                resolver.server.counters.increment("dns_replies_dropped");
                return;
            };
            const now_ns = resolver.server.io.nowNs();
            switch (reply.outcome) {
                .answered => resolver.accept(query, &reply, now_ns),
                .nxdomain => resolver.fail(query, "dns_nxdomain", now_ns),
                .truncated => resolver.fail(query, "dns_truncated", now_ns),
                .failed => {
                    resolver.server.counters.increment("dns_servfail");
                    resolver.nextNameserver(query, now_ns);
                },
            }
        }

        /// The attempt out whose ID the reply carries, asked of the peer
        /// it came from — or null.
        fn attemptFor(resolver: *Self, bytes: []const u8, cut: bool, peer: *const IpAddress) ?*Query {
            if (cut) return null;
            const id = message.replyId(bytes) orelse return null;
            const nameservers = resolver.server.config.resolver.?.nameservers;
            for (resolver.queries) |*query| {
                if (!query.waiting or query.id != id) continue;
                // Address and port alone: a kernel may fill in an IPv6
                // peer's flow label or scope the configured one lacks.
                if (dns_endpoints.orderAddresses(&nameservers[query.nameserver_index], peer) != .eq) return null;
                return query;
            }
            return null;
        }

        /// Whether `addresses` differ from what `query` holds.
        fn changes(resolver: *const Self, query: *const Query, addresses: []const IpAddress) bool {
            assert(addresses.len <= query.addresses.len);
            assert(query.resolver == resolver);
            if (addresses.len != query.addresses_count) return true;
            for (addresses, query.addresses[0..query.addresses_count]) |*answer, *held| {
                if (dns_endpoints.orderAddresses(answer, held) != .eq) return true;
            }
            return false;
        }

        fn fail(resolver: *Self, query: *Query, comptime counter: []const u8, now_ns: u64) void {
            assert(query.waiting);
            resolver.server.counters.increment(counter);
            query.waiting = false;
            resolver.settle(query, false, now_ns);
        }

        /// A NOERROR answer: the query's addresses become the reply's, in
        /// address order, each once.
        fn accept(resolver: *Self, query: *Query, reply: *const message.Reply, now_ns: u64) void {
            assert(query.waiting);
            assert(reply.outcome == .answered);
            resolver.server.counters.increment("dns_answered");
            const answered = resolver.reply_room[0..reply.count];
            dns_endpoints.sortAddresses(answered);
            // Sorted, so a repeated address is its neighbour; compacted in
            // place, never past the query's room — and an address left
            // out for want of it is what the truncation counts, not a
            // record the reply merely repeated.
            var unique: u16 = 0;
            var truncated = reply.dropped != 0;
            for (answered) |address| {
                if (unique >= 1 and dns_endpoints.orderAddresses(&resolver.reply_room[unique - 1], &address) == .eq) continue;
                if (unique == query.addresses.len) {
                    truncated = true;
                    continue;
                }
                resolver.reply_room[unique] = address;
                unique += 1;
            }
            assert(unique <= query.addresses.len);
            if (truncated) resolver.server.counters.increment("dns_answers_truncated");
            if (resolver.changes(query, resolver.reply_room[0..unique])) resolver.rounds[query.round].dirty = true;
            @memcpy(query.addresses[0..unique], resolver.reply_room[0..unique]);
            query.addresses_count = unique;
            query.ttl_s = reply.ttl_s;
            query.waiting = false;
            resolver.settle(query, true, now_ns);
        }
    };
}
