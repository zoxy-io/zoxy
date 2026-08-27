//! The TLS engine (DESIGN.md §4): zoxy's seam over zssl's sans-I/O TLS
//! 1.3 server. Static caller-owned buffers, key material injected as
//! plain data (so the simulator's seeded stream drives it, §9), zero
//! allocation in the wrapper — libcrypto's own allocations ride the fixed
//! heap of `libcrypto_heap.zig`.
//!
//! An engine is ~91 KiB — the outbox and flight scratch dominate, with
//! one record buffer, one out buffer and a ClientHello-sized reassembly
//! beside them (`constants.tls_engine_bytes_max` states the ceiling) —
//! so the serving path holds these in a
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
//! Ownership rules zssl imposes, encoded here so callers inherit them:
//! - `Credentials` (cert chain + signing key) is shared per listener and
//!   borrowed by pointer; the handshake holds that pointer, so it must
//!   outlive every engine referencing it.
//! - Every event hands out bytes borrowed from the scratch buffer, valid
//!   only until the next call. The engine copies ciphertext into its
//!   outbox immediately, so no caller has to know this.

const std = @import("std");

const constants = @import("../constants.zig");
const zssl = @import("zssl");

const Credentials = @import("Credentials.zig");
const Tickets = @import("Tickets.zig");

const assert = std.debug.assert;

const Engine = @This();

/// `Pool` slot bookkeeping (§5): the intrusive free-list link and the
/// generation counter that catches a stale reference into a recycled
/// engine. Owned by the pool, never touched by the engine itself.
pool_next: u32,
generation: u32,

hs: zssl.ServerHandshake,
record_storage: [zssl.record.wire_record_bytes_max]u8,
records: zssl.record_buffer.RecordBuffer,
/// Where one `handleRecord` writes: a whole flight, or a whole record's
/// decrypted plaintext. Borrowed out and copied before the next call.
out: [zssl.ServerHandshake.out_bytes_min]u8,
/// Where the server flight is assembled before it is sealed.
flight: [flight_scratch_bytes]u8,
/// Storage for reassembling a ClientHello fragmented across records —
/// which a hostile or MTU-shaped peer will produce whether or not an
/// ordinary client does.
reassembly: [reassembly_bytes]u8,
/// Ciphertext produced but not yet handed to the transport, and how much
/// of it the transport has already written. Engine-owned so it stays
/// valid across an async send (see `Sink`).
outbox: [outbox_bytes]u8,
outbox_len: u32,
outbox_sent: u32,
/// Resumption's two halves, both engine-owned because zssl asks this
/// session's own state for them mid-handshake (§4).
///
/// `tickets` is the listener's sealing keys, borrowed and shared — null
/// when the deployment has none, which is what turns resumption off. The
/// PSK a ticket opens to lands in `psk_storage` and is handed back to
/// zssl as a *borrowed* slice, so it has to outlive the lookup call: per
/// session is the only lifetime that works, since the handshake reads it
/// after the callback returns.
tickets: ?*const Tickets,
psk_storage: [Tickets.psk_bytes_max]u8,
/// Wall-clock seconds at this session's start, for sealing and for
/// ageing an offered ticket out. Injected rather than read: the engine
/// has no clock, and the simulator's must be the one that answers (§9).
now_unix: u64,
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
/// zssl's buffer is safe. Ciphertext must outlive the call: it is handed
/// to an async send that completes long after the step returns, while
/// zssl's own buffers are valid only until the next engine call. So the
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

/// The largest record zssl can put on the wire — what a *peer* may send.
/// Not what zoxy emits (see `emitted_record_bytes_max`).
pub const record_bytes_max = zssl.record.wire_record_bytes_max;

/// The most plaintext one record may yield. With the read cap, what
/// bounds a single step's output (see `plaintext_bytes_min`).
///
/// RFC 8446 §5.2 caps `TLSInnerPlaintext.content` at 2^14. zssl enforces
/// it in `protect.open` — a record past the cap draws `RecordOverflow`
/// before its plaintext reaches anyone — so unlike the ztls it
/// replaced, the bound is the dependency's as well as ours. `pump`
/// checks it anyway: the number below is what §5 sizes `plaintext`
/// against, and a bound that sizes a buffer is worth restating where the
/// buffer is filled.
pub const plaintext_record_bytes_max = zssl.record.plaintext_bytes_max;

/// Space for reassembling a ClientHello split across records. A real
/// one is ~1.5 KiB; the budget is generous because the alternative to
/// tolerating a split is refusing a peer whose MTU chose it.
const reassembly_bytes: usize = 16 * 1024;

/// Where zssl assembles the server flight before sealing it: the chain
/// plus EncryptedExtensions, CertificateVerify and Finished around it.
const flight_scratch_bytes: usize = @as(usize, constants.tls_cert_chain_bytes_max) + 1024;

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
    /// The sealing keys resumption runs on, or null to offer none. Same
    /// borrowing rule as `credentials`: the server owns them for the
    /// process, an engine only reads them.
    tickets: ?*const Tickets = null,
    /// Wall-clock seconds now. Only meaningful when `tickets` is set —
    /// it is the stamp a sealed ticket carries and the clock an offered
    /// one is aged against.
    now_unix: u64 = 0,
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
    engine.tickets = config.tickets;
    engine.now_unix = config.now_unix;
    // The seed *is* the private scalar: x25519 clamps internally, so
    // there is no keypair to generate and no failure to shed. That
    // retires #222's livelock at the source — the fallible P-256 keygen
    // it lived in is not on this path any more.
    engine.hs = .init(&.{
        .credentials = &config.credentials.inner,
        .server_random = config.random,
        .x25519_private = config.x25519_seed,
        .reassembly = &engine.reassembly,
        .flight = &engine.flight,
        // Offered only when this deployment can actually open one. A
        // lookup that always answers null would work too, but saying so
        // in the config keeps "resumption is off" a single readable fact
        // rather than a callback that turns out to never succeed.
        .psk_lookup = if (config.tickets != null) .{
            .context = engine,
            .lookup = openOfferedTicket,
        } else null,
    });
    engine.records = .init(&engine.record_storage);
    engine.outbox_len = 0;
    engine.outbox_sent = 0;
    engine.close_staged = false;
    engine.peer_closed = false;
    assert(!engine.isConnected());
}

pub fn deinit(engine: *Engine) void {
    engine.hs.deinit();
}

pub fn isConnected(engine: *const Engine) bool {
    return engine.hs.state == .connected;
}

/// Where the next read's ciphertext goes. Reading straight into the
/// record buffer is what keeps the wire path copy-free — there is no
/// second buffer between the socket and reassembly.
///
/// Capped at `tls_read_chunk_bytes` rather than handing out everything
/// free, because what one read delivers is what bounds one decrypt's
/// output, and `plaintext_bytes_min` is sized against that cap.
///
/// Never empty, and asserted rather than reported: `writable` reclaims
/// what `next` has consumed, so a drained buffer offers all of itself and
/// a partly drained one offers everything past the fragment still
/// arriving. A caller has no useful second move if that were false, and
/// an error return would only push the same dead end one frame up.
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
    assert(engine.isConnected());
    assert(bytes.len > 0);
    assert(bytes.len <= constants.tls_app_chunk_bytes);
    assert(engine.outboundRoom() >= app_record_bytes_max);
    const wire = try engine.hs.sendApplicationData(bytes, &engine.out);
    assert(wire.len > bytes.len); // Record header + AEAD tag overhead.
    engine.stage(wire);
}

/// What one NewSessionTicket costs the outbox: the encoded message plus
/// a handshake record's header and AEAD tag. The message is dominated by
/// the ticket itself, which is fixed-size, so this is a closed form and
/// not an estimate.
/// The 128 covers the NewSessionTicket fields around the ticket
/// (lifetime, age add, nonce, extensions) and the 256 the record header
/// and AEAD tag, on `control_record_bytes_max`'s own reasoning.
const session_ticket_record_bytes_max: usize = Tickets.ticket_bytes + 128 + 256;

comptime {
    // Both tickets are staged into an outbox the transport has not begun
    // draining, so they must fit beside each other or the second would
    // trip `stage`'s invariant rather than shed.
    assert(outbox_bytes >= constants.tls_tickets_per_handshake *
        session_ticket_record_bytes_max);
}

/// Stage one NewSessionTicket: derive this session's resumption PSK,
/// seal it into a ticket only this server can open, and encrypt the
/// message onto the application stream (RFC 8446 §4.6.1).
///
/// **When this is called is the point of it.** The flight must go out
/// *after* the client's Finished is processed, not alongside the server
/// flight — TLS 1.3 permits either, but only the later one carries an
/// ACK covering that Finished. Without it the client's next small write
/// sits in its own Nagle queue waiting for an ACK zoxy has no reason to
/// send, which is the ~45 ms stall (IMPLEMENTATION_NOTES).
///
/// The randomness is passed in rather than drawn: the engine has no I/O,
/// and a seeded simulator must be able to replay a ticket byte for byte
/// (§9). `seal_nonce` must never repeat under one sealing key — it is a
/// GCM nonce, and a repeat there is not a weak ticket but a broken one.
pub fn sendSessionTicket(
    engine: *Engine,
    ticket_nonce: []const u8,
    age_add: u32,
    seal_nonce: [Tickets.nonce_bytes]u8,
) !void {
    assert(engine.isConnected());
    assert(ticket_nonce.len >= 1);
    assert(engine.outboundRoom() >= session_ticket_record_bytes_max);
    const tickets = engine.tickets orelse return error.NoTicketKeys;

    var psk_buffer: [Tickets.psk_bytes_max]u8 = undefined;
    const psk = engine.hs.resumptionPsk(ticket_nonce, &psk_buffer);
    var ticket: [Tickets.ticket_bytes]u8 = undefined;
    const sealed = try tickets.seal(
        &ticket,
        psk,
        engine.hs.cipherSuite(),
        engine.now_unix,
        seal_nonce,
    );
    const wire = try engine.hs.sendNewSessionTicket(&.{
        .lifetime_s = constants.tls_ticket_lifetime_s,
        .age_add = age_add,
        .ticket_nonce = ticket_nonce,
        .ticket = sealed,
    }, &engine.out);
    assert(wire.len > 0);
    engine.stage(wire);
}

/// True when this handshake resumed a previous session rather than
/// running a full one — an offered ticket that opened, and that zssl then
/// selected. The counter this feeds is the only way to tell resumption
/// *working* from resumption merely *configured*.
pub fn isResumed(engine: *const Engine) bool {
    return engine.hs.resumed;
}

/// zssl asking whether an offered ticket is one of ours. Called during
/// the handshake, synchronously, with the identity the client sent.
///
/// Null for every failure — not ours, not intact, expired — because the
/// answer a peer is entitled to is only that resumption did not happen.
/// A full handshake follows either way, so nothing is lost but a round
/// trip's worth of work. Answering with the PSK is *not* the same as
/// accepting: zssl verifies the binder against it next, and a recognised
/// identity whose binder does not check aborts the handshake rather than
/// falling back (§4.2.11) — a replayed identity is refused, not
/// downgraded.
///
/// The obfuscated age goes unread. Ageing a ticket out is this side's
/// job and is done against the sealed stamp, which the client cannot
/// move; the age it reports is the client's own arithmetic and worth
/// nothing as a bound.
fn openOfferedTicket(
    context: *anyopaque,
    identity: []const u8,
    obfuscated_age: u32,
    psk_out: *[zssl.cipher_suite.hash_bytes_max]u8,
) ?u8 {
    _ = obfuscated_age;
    const engine: *Engine = @ptrCast(@alignCast(context));
    const tickets = engine.tickets orelse return null;
    const opened = tickets.open(
        identity,
        &engine.psk_storage,
        engine.now_unix,
        constants.tls_ticket_lifetime_s,
    ) orelse return null;
    assert(opened.psk.ptr == &engine.psk_storage);
    assert(opened.psk.len <= psk_out.len);
    @memcpy(psk_out[0..opened.psk.len], opened.psk);
    // 0-RTT is not offered (§4): a replayed ticket buys a resumed
    // handshake and nothing else, which is what lets these tickets be
    // multi-use without the replay table that would defeat the point.
    return @intCast(opened.psk.len);
}

/// Stage an orderly TLS close (close_notify) for the transport.
pub fn sendClose(engine: *Engine) !void {
    assert(!engine.close_staged); // Said goodbye twice.
    assert(engine.outboundRoom() >= control_record_bytes_max);
    const wire = try engine.hs.sendClose(&engine.out);
    assert(wire.len > 0);
    engine.stage(wire);
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
    while (try engine.records.next()) |wire_record| {
        assert(wire_record.len > 0);
        const event = try engine.hs.handleRecord(wire_record, &engine.out);
        switch (event) {
            // One arm where ztls had three. zssl assembles the server
            // flight before it seals it and answers a KeyUpdate from
            // inside the machine, so everything the peer is owed arrives
            // as bytes to put on the wire — there is no borrowed-buffer
            // handshake to complete afterwards.
            .send => |wire| {
                assert(wire.len > 0);
                engine.stage(wire);
            },
            .application_data => |bytes| {
                // The one place a peer chooses how many bytes land in a
                // zoxy buffer, so it is checked rather than assumed —
                // §5's sizing for `plaintext` is exactly this bound.
                // zssl enforces it too (`protect.open` refuses a longer
                // record), so this is the second of two locks on the
                // same door; an error rather than an assert, because the
                // input is the peer's and so should the consequence be.
                if (bytes.len > plaintext_record_bytes_max) {
                    return error.RecordTooLarge;
                }
                sink.appData(sink.ctx, bytes);
            },
            .closed => {
                engine.peer_closed = true;
                sink.closed(sink.ctx);
            },
            // The handshake completing is not news to the transport: it
            // asks `isConnected` when it needs to know, and the bytes
            // that carried it were staged by the `.send` before this.
            .connected, .none => {},
        }
    }
}
