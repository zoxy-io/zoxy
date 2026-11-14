//! The shared recv → send → recv body pump, factored out of `relay.zig`
//! (L4) and the two L7 body legs in `http/proxy.zig` (DESIGN.md §6, §7).
//! Every one of those sites ran the identical loop — arm a recv into a
//! fixed buffer, forward the chunk fully (short sends resume from the
//! offset), only then arm the next recv — differing solely in *policy*:
//! how a message ends (framing), what EOF and errors mean, and what "the
//! body finished" does next.
//!
//! The mechanical plumbing is keyed off the direction tag: for a given
//! `direction` the source/target sockets, the `relay_buffer` field, the
//! embedded `Op`, the armed bit, and the `DirectionState` debt all derive
//! from `@tagName(direction)` — exactly the naming convention `relay.zig`
//! already exploited. What is left is the `Policy`: a comptime struct of
//! hooks the caller supplies. Two of those hooks (`recvBuffer`, `sendSlice`)
//! can override *which buffer* a half of the direction uses, because a
//! transforming direction does not read and write the same one — see the
//! transform seam below; a policy that declares neither keeps the derived
//! relay buffer for both halves.
//!
//! Required Policy decls:
//!   feed(stream, chunk) FeedResult    how many bytes belong to the message
//!   framingDone(stream) bool          is the message fully forwarded
//!   onRecvError(server, stream, err)  terminal: EOF/reset handling
//!   onSendError(server, stream, err)  terminal: send failure
//!   onDrained(server, stream)         a recv yielded 0 forwardable bytes, done
//!   onComplete(server, stream)        the whole body reached the far side
//! Optional Policy decls (skipped when absent):
//!   beforeRecv(stream) / beforeSend(stream)  pre-arm bookkeeping (flags, phase)
//!   onRecvEntry(stream)                      post-await recv invariant re-checks
//!   afterFeed(stream, received, fr)          e.g. pipelined-tail detection
//!   afterSend(stream, sent)                  e.g. access-log byte accounting
//!   onSendEntry(server, stream) bool         divert a settled verdict; true = handled
//!   recvBuffer(stream) []u8                  where a read lands
//!   transformIn(stream, chunk) ?[]const u8   read bytes → framed bytes
//!   transformEnded(stream) bool              an empty transform: ended, not partial
//!   transformOut(stream, consumed) bool      framed bytes → wire bytes
//!   sendSlice(stream) []const u8             what a send writes; empty = drained
//!   creditSend(stream, sent)                 credit whichever cursor tracks the wire
//!
//! **The transform seam** (the last six). A plain relay recvs and sends the
//! same bytes, so one buffer per direction serves both halves and the framed
//! debt (`DirectionState`) is settled in the units it was incurred. A
//! *transforming* direction is neither: its halves live in different buffers,
//! and the bytes on the wire are not the bytes that arrived nor the same
//! count of them — §4's TLS termination decrypts what it reads and encrypts
//! what it writes. These six hooks are the only places that difference is
//! encoded, and a policy declaring none of them gets exactly the plain
//! behaviour, so the L4 and L7 body paths are unaffected by construction.
//!
//! Two contracts beyond the signatures:
//!
//! 1. **`creditSend` must settle the framed debt by the time `sendSlice`
//!    runs empty.** A transform may carry its own wire cursor and ignore the
//!    framed one while a chunk is going out, but when the wire is drained the
//!    chunk it framed is delivered, and `onSend` asserts exactly that — which
//!    is what lets the next chunk's `owe` demand a clean slate (§6).
//! 2. **`sendSlice` must be stable across `beforeSend`.** The pump calls it
//!    twice per completion: once to decide whether anything is left to arm,
//!    and again inside `armSend` to arm it, with `beforeSend` in between. A
//!    `beforeSend` that stages wire bytes would make those two answers
//!    disagree — stage in `transformOut`, which runs exactly once per chunk,
//!    and leave `beforeSend` to the bookkeeping it exists for.
//! 3. **A policy whose `transformIn` can yield nothing must tolerate
//!    `beforeRecv` twice with no send between**, because that is how the pump
//!    reads on for the rest of a fragment (see `onRecv`). Identity never can:
//!    a recv delivers at least one byte and identity forwards all of them.
//!    Such a policy must also answer `transformEnded`, because "no framed
//!    bytes" has two meanings that could not differ more: the unit is
//!    incomplete and the rest is coming, or the transformed stream is over.
//!    The second is an *in-band* EOF — the peer said so inside the transform,
//!    and no socket EOF need ever follow, so `onRecvError` will not fire for
//!    it. Reading on for a stream that ended waits for bytes that will never
//!    come, until a deadline reaps a connection that said a clean goodbye.
//!    The default is "partial", the only answer an identity transform needs.
//!
//!    The same end can arrive *with* bytes rather than instead of them, when
//!    the peer puts its last data and its end marker in one read. Then the
//!    chunk is non-empty, `transformEnded` is never consulted, and it is
//!    `framingDone` that has to report it — after the pump has forwarded
//!    what came with it. A policy with an in-band EOF therefore answers
//!    both, or it drops those last bytes or hangs holding them.
//!
//! The `on*Entry` hooks fire at completion time — after `delivered`, before
//! the I/O result is unwrapped — so a Policy can re-assert the invariants
//! that must have held across the in-flight await (the pre-arm `before*`
//! hooks only see the state at submit time, not after the await). `onSend`'s
//! variant additionally returns whether it handled the completion (a §7
//! verdict divert); `onRecv` has no divert — a client-side recv cannot be
//! forced (§8) — so `onRecvEntry` is assertion-only.

const std = @import("std");

const conn_module = @import("Conn.zig");
const stream_module = @import("Stream.zig");
const Io = @import("../io/io.zig");

const assert = std.debug.assert;

/// How many of a received chunk belong to the current message. `consumed`
/// < chunk.len means the message ended mid-buffer (the rest is a pipelined
/// tail); `done` means no more body follows; `malformed` fails the framing.
///
/// `over_limit` is a *policy* stop rather than a framing one (#236): the
/// bytes were well-formed and the message simply outgrew what this
/// listener said it would carry. Named apart from `malformed` because the
/// two end the exchange the same way and mean opposite things — one is
/// the client speaking badly, the other is the client speaking too much —
/// and a counter that could not tell them apart would send an operator
/// looking for a broken client that does not exist.
pub const FeedResult = struct {
    consumed: u32,
    done: bool,
    malformed: bool,
    over_limit: bool = false,
};

pub fn Pump(
    comptime IoType: type,
    comptime direction: conn_module.Conn(IoType).StreamType.Direction,
    comptime Policy: type,
) type {
    const ConnType = conn_module.Conn(IoType);
    const StreamType = ConnType.StreamType;
    const ServerType = @import("../Server.zig").Server(IoType);
    const direction_tag = @tagName(direction);

    return struct {
        const bit = "data_" ++ direction_tag;

        /// The exchange's op, on the stream slot since #274 — and the
        /// pump is keyed on that stream, not on the connection under it,
        /// because a multiplexed connection (#173) carries several: the
        /// stream names whose direction this is, and `stream.conn` is the
        /// socket and the teardown it shares with its siblings.
        fn op(stream: *StreamType) *StreamType.Op {
            return &@field(stream, "op_data_" ++ direction_tag);
        }

        fn directionState(stream: *StreamType) *stream_module.DirectionState {
            return &stream.directions[@backingInt(direction)];
        }

        fn buffer(stream: *StreamType) []u8 {
            return @field(stream.relay_buffer.?, direction_tag);
        }

        // -- the transform seam (§4, §6; see the module header) --

        /// Where a read lands. Plain: the direction's relay buffer.
        /// Transforming: wherever the *untransformed* bytes belong, since
        /// the relay buffer is then the transform's destination and cannot
        /// also be the read target.
        fn recvBuffer(stream: *StreamType) []u8 {
            if (@hasDecl(Policy, "recvBuffer")) return Policy.recvBuffer(stream);
            return buffer(stream);
        }

        /// Turn what was read into the bytes framing should see, so framing
        /// never learns a transform happened. Null is a failed transform,
        /// which is this connection's alone — a peer chooses what it sends
        /// (§8) — so the caller tears it down instead of asserting.
        fn transformIn(stream: *StreamType, chunk: []u8) ?[]const u8 {
            if (@hasDecl(Policy, "transformIn")) return Policy.transformIn(stream, chunk);
            return chunk;
        }

        /// Whether an empty `transformIn` means the transformed stream is
        /// over rather than mid-unit. Only ever asked when the transform
        /// yielded nothing, so identity — which never does — is never asked.
        fn transformEnded(stream: *StreamType) bool {
            if (@hasDecl(Policy, "transformEnded")) return Policy.transformEnded(stream);
            return false;
        }

        /// Stage the framed chunk for the wire, exactly once per chunk:
        /// before the first send, never on a resume, or a short write would
        /// re-transform bytes already gone. False fails the connection for
        /// the same reason `transformIn` may.
        fn transformOut(stream: *StreamType, consumed: u32) bool {
            assert(consumed >= 1);
            if (@hasDecl(Policy, "transformOut")) return Policy.transformOut(stream, consumed);
            return true;
        }

        /// What a send writes, and what a short write resumes from. Plain:
        /// the framed window still owed, empty once the debt is settled —
        /// which is how `onSend` asks "anything left to write?" without
        /// knowing whether a transform is in play. Transforming: the staged
        /// wire bytes, which carry their own cursor.
        fn sendSlice(stream: *StreamType) []const u8 {
            if (@hasDecl(Policy, "sendSlice")) return Policy.sendSlice(stream);
            const state = directionState(stream);
            if (state.owed() == 0) return &.{};
            return state.pending(buffer(stream));
        }

        /// Credit whichever cursor tracks the wire. Plain: the framed debt
        /// itself, since the wire carries exactly those bytes. Transforming:
        /// the transform's own cursor — ciphertext does not count against a
        /// debt framing measured in plaintext — but the framed debt must
        /// still be settled by the time `sendSlice` empties (module header).
        fn creditSend(stream: *StreamType, sent: u32) void {
            if (@hasDecl(Policy, "creditSend")) return Policy.creditSend(stream, sent);
            directionState(stream).credit(sent);
        }

        fn source(stream: *const StreamType) IoType.Socket {
            const conn = stream.conn;
            return switch (direction) {
                .client_to_upstream => conn.client_socket,
                .upstream_to_client => stream.upstream_socket.?,
            };
        }

        fn target(stream: *const StreamType) IoType.Socket {
            const conn = stream.conn;
            return switch (direction) {
                .client_to_upstream => stream.upstream_socket.?,
                .upstream_to_client => conn.client_socket,
            };
        }

        pub fn armRecv(server: *ServerType, stream: *StreamType) void {
            // A direction-agnostic precondition the pump enforces itself, so
            // the shared mechanism never relies solely on the optional
            // `beforeRecv` hook: every pump reads and writes the relay buffer.
            assert(stream.relay_buffer != null);
            if (@hasDecl(Policy, "beforeRecv")) Policy.beforeRecv(stream);
            stream.arm(op(stream), bit);
            server.io.recv(
                source(stream),
                recvBuffer(stream),
                &op(stream).completion,
                StreamType,
                stream,
                onRecv,
            );
        }

        fn onRecv(stream: *StreamType, result: Io.RecvError!u32) void {
            const conn = stream.conn;
            const server = conn.server;
            stream.delivered(op(stream), bit);
            if (server.exchangeOver(stream)) return;
            if (@hasDecl(Policy, "onRecvEntry")) Policy.onRecvEntry(stream);
            const received = result catch |err| return Policy.onRecvError(server, stream, err);
            assert(received >= 1);
            assert(received <= recvBuffer(stream).len);
            const chunk = transformIn(stream, recvBuffer(stream)[0..received]) orelse {
                server.beginTeardown(conn);
                return;
            };
            // A transform may legally yield nothing from a read: what
            // arrived is a fragment of a unit it can only decode whole — a
            // TLS record, a length-prefixed frame. Framing must never see an
            // empty chunk, because `feed` reporting `consumed == 0` means
            // *end of message*, so the read is re-armed and the transform
            // keeps the fragment until the rest lands. A policy whose
            // transform can do this must therefore tolerate `beforeRecv`
            // twice with no send between (identity never can: a recv
            // delivers at least one byte and identity forwards all of them).
            if (chunk.len == 0) {
                // Nothing was framed, so nothing is owed: a fragment must
                // never leave a debt deferred across the next read.
                assert(directionState(stream).owed() == 0);
                // …but an empty transform is also how an in-band EOF
                // arrives, and reading on for a stream that ended waits
                // for bytes that will never come.
                if (transformEnded(stream)) {
                    Policy.onDrained(server, stream);
                    return;
                }
                armRecv(server, stream);
                return;
            }
            const fr = Policy.feed(stream, chunk);
            if (fr.malformed or fr.over_limit) {
                // Both end the exchange here and for the same reason: the
                // response leg is already armed by now, so no status can
                // be sent (§7) — the policy has already counted which of
                // the two it was.
                server.beginTeardown(conn);
                return;
            }
            if (@hasDecl(Policy, "afterFeed")) Policy.afterFeed(stream, received, fr);
            const state = directionState(stream);
            state.owe(fr.consumed);
            if (state.owed() >= 1) {
                // Stage the wire bytes once, here: a short write resumes
                // through `sendSlice`, never back through the transform.
                if (!transformOut(stream, fr.consumed)) {
                    server.beginTeardown(conn);
                    return;
                }
                armSend(server, stream);
            } else {
                assert(fr.done);
                Policy.onDrained(server, stream);
            }
        }

        pub fn armSend(server: *ServerType, stream: *StreamType) void {
            assert(stream.relay_buffer != null);
            if (@hasDecl(Policy, "beforeSend")) Policy.beforeSend(stream);
            const wire = sendSlice(stream);
            // Nothing arms an empty send: the seam's contract is
            // `bytes.len >= 1` (§4), and an empty slice here would mean a
            // caller asked to write with nothing staged.
            assert(wire.len >= 1);
            stream.arm(op(stream), bit);
            server.io.send(
                target(stream),
                wire,
                &op(stream).completion,
                StreamType,
                stream,
                onSend,
            );
        }

        fn onSend(stream: *StreamType, result: Io.SendError!u32) void {
            const conn = stream.conn;
            const server = conn.server;
            stream.delivered(op(stream), bit);
            if (server.exchangeOver(stream)) return;
            if (@hasDecl(Policy, "onSendEntry")) {
                if (Policy.onSendEntry(server, stream)) return;
            }
            const sent = result catch |err| return Policy.onSendError(server, stream, err);
            assert(sent >= 1);
            creditSend(stream, sent);
            // What actually left on the wire, whether or not framing
            // counts in the same units (the transform seam above): the
            // access log reports bytes moved, not bytes framed.
            if (@hasDecl(Policy, "afterSend")) Policy.afterSend(stream, sent);
            // "Anything left to write?" rather than "is the framed debt
            // settled?" — the same question for a plain policy, whose
            // `sendSlice` empties exactly when the debt does, and the only
            // form that still holds when the wire carries a different number
            // of bytes than framing counted.
            if (sendSlice(stream).len > 0) {
                armSend(server, stream);
                return;
            }
            // The wire is drained, so the chunk framing chose is delivered:
            // the seam's contract (module header) is that a transform has
            // settled the framed debt by now, which is what lets the next
            // chunk's `owe` demand a clean slate.
            assert(directionState(stream).owed() == 0);
            // A full chunk moved: this is activity — push the idle deadline
            // out (§6); the armed timer op is not touched. The exchange's
            // deadline, which on the stream an L4 relay or a tunnel runs on
            // — always its connection's admission stream — is the
            // connection's: the store routes by the stream, not the pump.
            server.storeExchangeDeadline(stream, server.idleTimeoutMs());
            if (Policy.framingDone(stream)) {
                Policy.onComplete(server, stream);
            } else {
                armRecv(server, stream);
            }
        }
    };
}
