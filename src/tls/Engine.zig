//! The TLS engine (DESIGN.md §4): zoxy's seam over ztls's sans-I/O TLS
//! 1.3 server. Static caller-owned buffers, key material injected as
//! plain data (so the simulator's seeded stream drives it, §9), zero
//! allocation in the wrapper — libcrypto's own allocations ride the fixed
//! heap of `libcrypto_heap.zig`.
//!
//! An engine is ~132 KiB — mostly ztls's record and reassembly buffers,
//! each two max records wide — so the serving path holds these in a
//! shared `Pool` rather than one per conn slot: a listener that
//! terminates TLS pays for concurrent *handshaking and terminated*
//! connections, not for every slot it could ever admit (§5).
//!
//! The drive shape: ciphertext in through `recvBuffer`/`received` (or
//! `feed`, for bytes a caller already holds), plaintext out through
//! `Sink` (synchronous), ciphertext out through `outbound`/`outboundSent`
//! — an engine-owned outbox the transport drains at its own pace, partial
//! writes included. Wire and plaintext travel differently on purpose;
//! see `Sink`.
//!
//! Ownership rules ztls imposes, encoded here so callers inherit them:
//! - `Credentials` (cert chain + signing key) is shared per listener and
//!   borrowed by pointer; `setCredentials` keeps a pointer into its chain
//!   and key, so it must outlive every engine referencing it.
//! - Every `.write` event hands out bytes borrowed from the out buffer;
//!   `completeWrite` must follow before the next `handleRecord`. The
//!   engine copies into its outbox and calls it immediately, so no
//!   caller has to know this.

const std = @import("std");

const constants = @import("../constants.zig");
const ztls = @import("ztls");

const Credentials = @import("Credentials.zig");

const assert = std.debug.assert;

const Engine = @This();

/// `Pool` slot bookkeeping (§5): the intrusive free-list link and the
/// generation counter that catches a stale reference into a recycled
/// engine. Owned by the pool, never touched by the engine itself.
pool_next: u32,
generation: u32,

hs: ztls.ServerHandshake,
record_storage: ztls.RecordBuffer.Storage,
records: ztls.RecordBuffer,
out: ztls.ServerHandshake.OutBuffer,
flight: ztls.ServerHandshake.FlightBuffer,
/// Storage for reassembling a ClientHello fragmented across records.
/// Without it ztls answers a fragmented ClientHello with a decode_error
/// alert; with it the engine tolerates the split — which a hostile or
/// MTU-shaped peer will produce whether or not an ordinary client does.
reassembly: ztls.ServerHandshake.Storage,
/// Ciphertext produced but not yet handed to the transport, and how much
/// of it the transport has already written. Engine-owned so it stays
/// valid across an async send (see `Sink`).
outbox: [outbox_bytes]u8,
outbox_len: u32,
outbox_sent: u32,
/// Where decrypted bytes land: the caller's destination for everything
/// this session ever receives in plaintext. Assigned once at pool init
/// from a startup slab, never reassigned — runtime-sized because L7's
/// head may be up to `limits.head_buffer_bytes`, which the operator
/// chooses (§5). `plaintext_bytes_min` is the floor.
///
/// The engine owns the buffer; the caller owns the cursor. What
/// "consumed" means differs by protocol — an L4 direction drains it every
/// step, an L7 head accumulates across reads until the parser is
/// satisfied — and only the caller knows which.
plaintext: []u8,
/// A second destination, for a request *body* (§7). Separate from the
/// one above and not an economy the pool can skip: on the L7 path the
/// head buffer holds the request head until the response head renders
/// over it, and an origin may legally answer before the request body
/// finishes — a 413 mid-upload is §7's own example. So the two legs run
/// concurrently, and a body chunk decrypting into the buffer a response
/// head is still being written out of would clobber it.
///
/// Sized by the same floor and unused on the L4 path, where a relayed
/// direction's plaintext has nothing to share with.
body_plaintext: []u8,
/// How much of `plaintext` an L7 *head* may occupy —
/// `limits.head_buffer_bytes`, and not the buffer's own length.
///
/// The two are different numbers and conflating them was a real hole: the
/// buffer is sized `max(head_bytes, plaintext_bytes_min)` so a record's
/// decrypt always has somewhere to land, and a deployment that set the
/// head limit *below* that floor to bound what it accepts would otherwise
/// have got the floor instead. The limit is operator-visible behaviour —
/// it decides 414 and 431 — so it is carried rather than inferred.
head_bytes: u32,
/// Whether this session's close_notify has been staged. The engine owns
/// it because `sendClose` is its only writer, and because the transport
/// needs the answer *after* the outbox drains — by which time the alert
/// bytes it would otherwise have to recognize are gone.
close_staged: bool,
/// Whether the *peer's* close_notify has arrived. `Sink.closed` reports
/// it to whoever drove the step that saw it, but the fact outlives that
/// call: a caller that only learns "this read yielded no plaintext" has
/// to ask afterwards whether that was a fragment or the end of the
/// stream, and those two answers could not differ more (§6 half-close).
peer_closed: bool,

/// What a drive step hands back *synchronously*: plaintext the caller
/// consumes before returning, and the peer's orderly close. Ciphertext
/// does **not** come through here — see `outbound`.
///
/// The asymmetry is deliberate. Decrypted bytes are consumed inside the
/// call (copied into a relay buffer, appended to a head), so borrowing
/// ztls's buffer is safe. Ciphertext must outlive the call: it is handed
/// to an async send that completes long after the step returns, while
/// ztls's own buffers are valid only until the next engine call. So the
/// engine stages ciphertext in its own outbox and the caller drains it at
/// its own pace.
pub const Sink = struct {
    ctx: *anyopaque,
    /// Decrypted application data from the peer. Valid only for the
    /// duration of the callback.
    appData: *const fn (ctx: *anyopaque, bytes: []const u8) void,
    /// The peer closed the TLS session (close_notify).
    closed: *const fn (ctx: *anyopaque) void,
};

/// The largest record ztls can put on the wire — what a *peer* may send.
/// Not what zoxy emits (see `emitted_record_bytes_max`).
pub const record_bytes_max = ztls.frame.max_wire_record_len;

/// The most plaintext one record may yield. With the read cap, what
/// bounds a single step's output (see `plaintext_bytes_min`).
///
/// RFC 8446 §5.2 caps `TLSInnerPlaintext.content` at 2^14 — but this is a
/// bound zoxy *enforces*, not one it inherits. ztls checks the length on
/// the send path only: its receive path admits any record inside
/// `max_ciphertext_len` (2^14 + 256) and takes the content up to the last
/// non-zero byte, so a non-conforming peer can produce up to 239 bytes
/// more than this. `pump` refuses that record, which is what makes this
/// number true of everything a `Sink` can ever see.
pub const plaintext_record_bytes_max = ztls.frame.max_plaintext_len;

/// A ServerHello record, generously: the fixed fields plus the largest
/// key share in play (X25519MLKEM768's is ~1.1 KiB).
const server_hello_bytes_max: usize = 2 * 1024;

/// The server flight: the certificate chain (bounded at startup by
/// `tls_cert_chain_bytes_max`) plus CertificateVerify, Finished, framing.
const flight_bytes_max: usize = @as(usize, constants.tls_cert_chain_bytes_max) + 512;

/// One application record we emit: a capped plaintext chunk plus header
/// and AEAD tag.
const app_record_bytes_max: usize = @as(usize, constants.tls_app_chunk_bytes) + 256;

/// One post-handshake control record we emit: a close_notify alert (two
/// bytes of payload) or a KeyUpdate response (one). Named so the room
/// checks in `sendClose` and `pump` state a ceiling rather than "more
/// than nothing", which is what lets `stage`'s "overflow is impossible by
/// construction" be read off each call site instead of reasoned about
/// across all of them.
const control_record_bytes_max: usize = 256;

/// The largest record zoxy itself emits.
///
/// The distinction from `record_bytes_max` is what keeps the engine a
/// fixed size. Inbound buffers must cover a full record, because a client
/// that does not offer RFC 8449 `record_size_limit` may legally send one.
/// Outbound buffers need cover only what *we* choose to write, and
/// emitting smaller records is always legal.
pub const emitted_record_bytes_max: usize = @max(flight_bytes_max, app_record_bytes_max);

/// Ciphertext staged for the transport. Sized for the largest burst one
/// step can produce — a ServerHello record plus the encrypted server
/// flight — and, in steady state, one staged application record while an
/// earlier one is still draining.
const outbox_bytes: usize = 2 * emitted_record_bytes_max;

/// The floor on the caller's `plaintext` buffer.
///
/// One step carries over at most one incomplete record and drains
/// whatever the fed chunk completes, so its output is bounded by one
/// record's plaintext plus that chunk — not by the record buffer's whole
/// capacity. Sizing the destination by the *read* size alone is the trap:
/// a client that writes 16 KiB in one go overflows it, because the record
/// was reassembled across earlier reads and lands whole.
pub const plaintext_bytes_min: usize =
    @as(usize, plaintext_record_bytes_max) + constants.tls_read_chunk_bytes;

comptime {
    // The handshake burst has to fit alongside a full emitted record:
    // ServerHello and the flight are staged in the same drive step.
    assert(outbox_bytes >= server_hello_bytes_max + flight_bytes_max);
    // Emitting more than a peer must accept would be a protocol error
    // regardless of our own buffering.
    assert(emitted_record_bytes_max <= record_bytes_max);
    // The engine's sizing is a property of the record layer and our own
    // chunk caps, never of the operator's head size — that is what makes
    // an engine's footprint answerable at compile time (§5).
    assert(plaintext_bytes_min > constants.tls_read_chunk_bytes);
    assert(plaintext_record_bytes_max == constants.tls_record_plaintext_bytes_max);
    // What the §5 pool is costed against. Stated in `constants.zig` and
    // checked here, so growing the engine is a decision someone makes
    // rather than a number that quietly moved.
    assert(@sizeOf(Engine) <= constants.tls_engine_bytes_max);
}

pub const Config = struct {
    /// Ephemeral X25519 seed — deterministic in the simulator, from
    /// entropy in production. The engine derives the keypair.
    x25519_seed: [32]u8,
    /// ServerHello random (RFC 8446 §4.1.3) — same injection rule.
    random: [32]u8,
    /// This listener's cert chain and signing key. Borrowed, not owned:
    /// shared across the listener's engines, and must outlive them.
    credentials: *const Credentials,
};

/// What one slot's plaintext buffer must be, given the head size the
/// operator chose. The closed form lives here rather than at the pool,
/// because only the engine knows its own floor — and both the startup
/// banner and the allocation itself have to arrive at the same number or
/// §5's printed total is a fiction.
///
/// One pool serves both protocols, so every slot is sized for whichever
/// use is wider: an L7 head, which accumulates until the parser is
/// satisfied and so may need `limits.head_buffer_bytes`, or a decrypt
/// step's own output.
pub fn plaintextBytesFor(head_buffer_bytes: u32) u32 {
    assert(head_buffer_bytes >= constants.head_buffer_bytes_min);
    assert(head_buffer_bytes <= constants.head_buffer_bytes_max);
    // The head destination, then the body's. The first has to cover a
    // whole L7 head as well as a decrypt; the second only ever holds
    // body bytes, so the floor is enough for it.
    const head = @max(head_buffer_bytes, plaintext_bytes_min);
    const bytes = head + plaintext_bytes_min;
    assert(bytes >= 2 * plaintext_bytes_min);
    return @intCast(bytes);
}

/// Bind this slot's plaintext destination. Called once at pool init, not
/// per session: the slab is startup memory and a slot keeps its slice for
/// the process, so `init` below can assume it is already there.
pub fn bindPlaintext(engine: *Engine, buffer: []u8, body: []u8, head_bytes: u32) void {
    assert(buffer.len >= plaintext_bytes_min);
    assert(body.len >= plaintext_bytes_min);
    assert(head_bytes >= constants.head_buffer_bytes_min);
    assert(head_bytes <= buffer.len);
    engine.head_bytes = head_bytes;
    // Distinct regions, which is the whole point of there being two: one
    // slab handing the same slice twice would reintroduce the aliasing
    // the split exists to remove, and silently.
    assert(buffer.ptr != body.ptr);
    engine.plaintext = buffer;
    engine.body_plaintext = body;
}

/// In-place init via out-pointer: `records` borrows `record_storage` and
/// `hs` borrows `reassembly`, so an Engine must never be copied after
/// init (the zoxy pool-slot rule).
pub fn init(engine: *Engine, config: *const Config) !void {
    assert(config.credentials.chain.len >= 1);
    assert(engine.plaintext.len >= plaintext_bytes_min); // bindPlaintext ran.
    assert(engine.body_plaintext.len >= plaintext_bytes_min);
    const keypair = try ztls.x25519.KeyPair.generateDeterministic(
        .init(config.x25519_seed),
    );
    engine.reassembly = .empty;
    engine.hs = .init(.{
        .keypairs = .init(keypair),
        .random = .init(config.random),
        .reassembly = &engine.reassembly.buffer,
    });
    engine.hs.setCredentials(config.credentials.chain, config.credentials.signer());
    engine.record_storage = .empty;
    engine.records = .init(&engine.record_storage.buffer);
    engine.out = .empty;
    engine.flight = .empty;
    engine.outbox_len = 0;
    engine.outbox_sent = 0;
    engine.close_staged = false;
    engine.peer_closed = false;
    assert(!engine.hs.isConnected());
}

pub fn deinit(engine: *Engine) void {
    engine.hs.deinit();
}

pub fn isConnected(engine: *const Engine) bool {
    return engine.hs.isConnected();
}

/// Where the next read's ciphertext goes. Reading straight into the
/// record buffer is what keeps the wire path copy-free — there is no
/// second buffer between the socket and reassembly.
///
/// Capped at `tls_read_chunk_bytes` rather than handing out everything
/// free, because what one read delivers is what bounds one decrypt's
/// output, and `plaintext_bytes_min` is sized against that cap.
///
/// Never empty, and asserted rather than reported: ztls sizes the record
/// buffer at two max records, so what is left after a drain is always
/// under one record and the writable region always has room. That is the
/// dependency's invariant rather than ours, but the pin is audited and
/// every other invariant it states is trusted the same way here — a
/// caller has no useful second move if it were false, and an error return
/// would only push the same dead end one frame up.
pub fn recvBuffer(engine: *Engine) []u8 {
    const writable = engine.records.writable();
    assert(writable.len > 0);
    const take = @min(writable.len, constants.tls_read_chunk_bytes);
    assert(take > 0);
    return writable[0..take];
}

/// Report `n` bytes landed in the buffer `recvBuffer` handed out, and
/// drive whatever they complete. Any error is the connection's: the
/// caller tears down.
pub fn received(engine: *Engine, n: usize, sink: *const Sink) !void {
    assert(n > 0);
    assert(n <= constants.tls_read_chunk_bytes);
    // What `pump` may stage: a handshake burst before the session is up, a
    // control record after. Staging appends, so an in-flight send is
    // undisturbed — its slice sits earlier in the outbox and never moves —
    // but only while the append fits, which is what this demands.
    const room_needed: usize = if (engine.isConnected())
        control_record_bytes_max
    else
        server_hello_bytes_max + flight_bytes_max;
    assert(engine.outboundRoom() >= room_needed);
    engine.records.advance(n);
    try engine.pump(sink);
}

/// Feed ciphertext the caller already holds — bytes that arrived before
/// the engine existed, or a test's. Consumes all of `wire`: each
/// iteration stages a chunk and drains every complete record, so the
/// record buffer's free space is reclaimed between chunks.
///
/// The read path uses `recvBuffer`/`received` instead and copies nothing.
pub fn feed(engine: *Engine, wire: []const u8, sink: *const Sink) !void {
    var remaining = wire;
    // Bounded: every iteration moves at least one byte out of `remaining`
    // — `recvBuffer` is never empty — so this runs at most `wire.len`
    // times and normally once.
    while (remaining.len > 0) {
        const destination = engine.recvBuffer();
        const take = @min(destination.len, remaining.len);
        assert(take > 0);
        @memcpy(destination[0..take], remaining[0..take]);
        remaining = remaining[take..];
        try engine.received(take, sink);
    }
}

/// Room left to stage. The relay drives both directions at once, so a
/// step may append while an earlier send is still in flight — safe,
/// because staged bytes never move and `outboundSent` credits off the
/// front, but only while the append fits.
pub fn outboundRoom(engine: *const Engine) usize {
    assert(engine.outbox_len <= engine.outbox.len);
    return engine.outbox.len - engine.outbox_len;
}

/// Ciphertext waiting for the transport; empty when there is nothing to
/// write. A later step may *append* while this slice is in flight —
/// staged bytes never move, so the in-flight region stays valid; only the
/// remainder grows.
pub fn outbound(engine: *const Engine) []const u8 {
    assert(engine.outbox_sent <= engine.outbox_len);
    return engine.outbox[engine.outbox_sent..engine.outbox_len];
}

/// Report `n` bytes written, which a short send makes a partial credit.
/// Once everything staged has gone out, the outbox resets to empty.
pub fn outboundSent(engine: *Engine, n: usize) void {
    assert(n <= engine.outbound().len);
    engine.outbox_sent += @intCast(n);
    assert(engine.outbox_sent <= engine.outbox_len);
    if (engine.outbox_sent == engine.outbox_len) {
        engine.outbox_len = 0;
        engine.outbox_sent = 0;
    }
}

/// Encrypt application data into the outbox. Handshake must be complete.
/// Chunked by the caller: `tls_app_chunk_bytes` is what the outbox is
/// sized against, so a larger plaintext has nowhere to go.
pub fn sendApp(engine: *Engine, bytes: []const u8) !void {
    assert(engine.hs.isConnected());
    assert(bytes.len > 0);
    assert(bytes.len <= constants.tls_app_chunk_bytes);
    assert(engine.outboundRoom() >= app_record_bytes_max);
    const wire = try engine.hs.sendApplicationData(bytes, &engine.out.buffer);
    assert(wire.len > bytes.len); // Record header + AEAD tag overhead.
    engine.stage(wire);
    engine.hs.completeWrite();
}

/// Stage an orderly TLS close (close_notify) for the transport.
pub fn sendClose(engine: *Engine) !void {
    assert(!engine.close_staged); // Said goodbye twice.
    assert(engine.outboundRoom() >= control_record_bytes_max);
    const wire = try engine.hs.sendAlert(.close_notify, &engine.out.buffer);
    assert(wire.len > 0);
    engine.stage(wire);
    engine.hs.completeWrite();
    engine.close_staged = true;
}

/// True once `sendClose` has staged this session's close_notify: the
/// transport's answer to "is this the last thing I will ever send here?",
/// which survives the outbox draining out from under it.
pub fn closeStaged(engine: *const Engine) bool {
    return engine.close_staged;
}

/// True once the peer's close_notify has arrived: an in-band EOF that no
/// socket-level EOF need follow, so a caller seeing an empty decrypt asks
/// this to tell "the record was a fragment" from "the stream ended".
pub fn peerClosed(engine: *const Engine) bool {
    return engine.peer_closed;
}

/// Stage ciphertext for the transport. Overflow is impossible by
/// construction — the outbox covers the largest burst one step can
/// produce, and `outboundRoom` bounds what a caller may add on top of an
/// in-flight send — so it is an invariant violation, not a condition to
/// shed.
fn stage(engine: *Engine, wire: []const u8) void {
    assert(wire.len > 0);
    assert(engine.outbox_len + wire.len <= engine.outbox.len);
    @memcpy(engine.outbox[engine.outbox_len..][0..wire.len], wire);
    engine.outbox_len += @intCast(wire.len);
}

/// Drain every complete record the last chunk made available.
fn pump(engine: *Engine, sink: *const Sink) !void {
    // Bounded: `next()` consumes a record per iteration from a buffer no
    // chunk refills mid-pump, so it runs at most as many times as there
    // are whole records staged.
    while (try engine.records.next()) |record| {
        assert(record.len > 0);
        const event = try engine.hs.handleRecord(record, &engine.out.buffer);
        switch (event) {
            .write => |wire| {
                assert(wire.len > 0);
                engine.stage(wire);
                engine.hs.completeWrite();
                if (try engine.hs.sendServerFlightBuffered(&engine.flight)) |flight_bytes| {
                    engine.stage(flight_bytes);
                    engine.hs.completeWrite();
                }
            },
            .application_data => |bytes| {
                // The one place a peer chooses how many bytes land in a
                // zoxy buffer, so it is checked rather than assumed —
                // §5's sizing for `plaintext` is exactly this bound, and
                // ztls does not enforce it on receive (see
                // `plaintext_record_bytes_max`). An error, not an assert:
                // the input is the peer's, so the consequence should be
                // theirs — a per-connection teardown, not a panic anyone
                // with a socket could trigger.
                if (bytes.len > plaintext_record_bytes_max) {
                    return error.RecordTooLarge;
                }
                sink.appData(sink.ctx, bytes);
            },
            .key_update => |key_update| {
                if (key_update.response) |wire| {
                    engine.stage(wire);
                    engine.hs.completeWrite();
                }
            },
            .closed => {
                engine.peer_closed = true;
                sink.closed(sink.ctx);
            },
            .none => {},
        }
    }
}
