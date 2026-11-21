//! QUIC packet protection from libcrypto (#449): the backend h3's
//! `Connection.Config.crypto` names, so every AEAD and header-protection
//! cipher a QUIC connection runs is libcrypto's — §4's rule for TLS over
//! TCP, held for QUIC too — rather than h3's `std.crypto` default.
//!
//! h3's contract (its `src/quic/crypto/backend.zig`) passes the raw key on
//! every call and keeps nothing between calls. libcrypto keys a context
//! once and runs it many times, and making one per call would reach the
//! libcrypto heap per packet. So this keeps one context per suite and
//! direction, and one per header-protection cipher, for the whole process
//! — made at `init`, at startup, and rekeyed in place on every call
//! (zssl's `rekey`), which allocates nothing. One thread runs every QUIC
//! connection (§3), so one set of contexts serves them all, and no call
//! re-enters another.
//!
//! HKDF is `std.crypto`'s HMAC, as zssl's own key schedule is: hash-based
//! and free of the table lookups that make a software AES leak, so there
//! is no constant-time argument for libcrypto there.
//!
//! The signatures are h3's contract's exactly, written out rather than
//! imported: h3 may only be imported under `src/quic/` and zssl only here,
//! so the QUIC endpoint hands this type to h3, whose comptime `check`
//! holds it to the contract, and runs h3's conformance suite over it.

const std = @import("std");
const zssl = @import("zssl");

const assert = std.debug.assert;

const QuicCrypto = @This();

/// The one error an open may return, by h3's contract.
pub const AuthenticationError = error{AuthenticationFailed};

/// The process's contexts, made by `init`; null until then.
var contexts: ?Contexts = null;

const Contexts = struct {
    aes128_seal: zssl.quic.PacketKey,
    aes128_open: zssl.quic.PacketKey,
    aes256_seal: zssl.quic.PacketKey,
    aes256_open: zssl.quic.PacketKey,
    chacha_seal: zssl.quic.PacketKey,
    chacha_open: zssl.quic.PacketKey,
    aes128_header: zssl.quic.HeaderKey,
    aes256_header: zssl.quic.HeaderKey,
    chacha_header: zssl.quic.HeaderKey,
};

/// The contexts every call rekeys: nine, made once. Their libcrypto
/// allocations are startup's, on the fixed heap (§5), which a QUIC
/// listener's budget widens by `context_count`. A failure is the heap's,
/// at startup, and is returned for startup to refuse on, with every
/// context made before it given back.
pub fn init() error{LibcryptoFailed}!void {
    assert(contexts == null);
    const zero: [32]u8 = @splat(0);
    var made: Contexts = undefined;
    var count: u32 = 0;
    errdefer inline for (@typeInfo(Contexts).@"struct".field_names, 0..) |name, index| {
        if (index < count) @field(made, name).deinit();
    };
    made.aes128_seal = try packetKey(.aes_128_gcm_sha256, zero[0..16], .seal);
    count += 1;
    made.aes128_open = try packetKey(.aes_128_gcm_sha256, zero[0..16], .open);
    count += 1;
    made.aes256_seal = try packetKey(.aes_256_gcm_sha384, &zero, .seal);
    count += 1;
    made.aes256_open = try packetKey(.aes_256_gcm_sha384, &zero, .open);
    count += 1;
    made.chacha_seal = try packetKey(.chacha20_poly1305_sha256, &zero, .seal);
    count += 1;
    made.chacha_open = try packetKey(.chacha20_poly1305_sha256, &zero, .open);
    count += 1;
    made.aes128_header = try headerKey(.aes_128_gcm_sha256, zero[0..16]);
    count += 1;
    made.aes256_header = try headerKey(.aes_256_gcm_sha384, &zero);
    count += 1;
    made.chacha_header = try headerKey(.chacha20_poly1305_sha256, &zero);
    count += 1;
    assert(count == context_count);
    contexts = made;
}

/// How many libcrypto contexts `init` makes, for the heap's budget.
pub const context_count: u32 = @typeInfo(Contexts).@"struct".field_names.len;

/// Give the contexts back: tests, and a process shutting down.
pub fn deinit() void {
    assert(contexts != null);
    inline for (@typeInfo(Contexts).@"struct".field_names) |name| @field(contexts.?, name).deinit();
    contexts = null;
}

/// Whether `init` has run and `deinit` has not.
pub fn initialized() bool {
    return contexts != null;
}

/// The contexts made unless something earlier in the process made them
/// already — a server's `start` makes them once and keeps them — and
/// whether this call did, so a test unmakes only what it made.
pub fn ensure() error{LibcryptoFailed}!bool {
    if (initialized()) return false;
    try init();
    assert(initialized());
    return true;
}

fn packetKey(
    suite: zssl.cipher_suite.CipherSuite,
    key: []const u8,
    operation: zssl.quic.PacketKey.Operation,
) error{LibcryptoFailed}!zssl.quic.PacketKey {
    return zssl.quic.PacketKey.init(suite, key, operation) catch return error.LibcryptoFailed;
}

fn headerKey(suite: zssl.cipher_suite.CipherSuite, key: []const u8) error{LibcryptoFailed}!zssl.quic.HeaderKey {
    return zssl.quic.HeaderKey.init(suite, key) catch return error.LibcryptoFailed;
}

/// The contexts, which `init` made at startup: a QUIC connection cannot
/// exist before it does.
fn madeContexts() *Contexts {
    assert(contexts != null);
    return &contexts.?;
}

// -- AEAD, in place (RFC 9001 §5.3): h3's contract, one wrapper per
// suite and direction, each rekeying its own context --

/// AES-128-GCM, sealing `data` in place.
pub fn aes128GcmSeal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [16]u8) void {
    seal(&madeContexts().aes128_seal, data, tag, ad, nonce, key);
}

/// AES-128-GCM, opening `data` in place against `tag`.
pub fn aes128GcmOpen(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [16]u8) AuthenticationError!void {
    return open(&madeContexts().aes128_open, data, tag, ad, nonce, key);
}

/// AES-256-GCM, sealing `data` in place.
pub fn aes256GcmSeal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) void {
    seal(&madeContexts().aes256_seal, data, tag, ad, nonce, key);
}

/// AES-256-GCM, opening `data` in place against `tag`.
pub fn aes256GcmOpen(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) AuthenticationError!void {
    return open(&madeContexts().aes256_open, data, tag, ad, nonce, key);
}

/// ChaCha20-Poly1305, sealing `data` in place.
pub fn chacha20Poly1305Seal(data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) void {
    seal(&madeContexts().chacha_seal, data, tag, ad, nonce, key);
}

/// ChaCha20-Poly1305, opening `data` in place against `tag`.
pub fn chacha20Poly1305Open(data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: *const [32]u8) AuthenticationError!void {
    return open(&madeContexts().chacha_open, data, tag, ad, nonce, key);
}

/// h3's contract: a seal cannot fail, since every input is sized by its
/// type. libcrypto failing anyway — the rekey or the cipher itself — is an
/// internal fault, and the contract's answer to one is to stop: a packet h3
/// believes sealed and sends would otherwise go out in the clear.
fn seal(context: *zssl.quic.PacketKey, data: []u8, tag: *[16]u8, ad: []const u8, nonce: *const [12]u8, key: []const u8) void {
    assert(data.len <= zssl.quic.payload_bytes_max);
    assert(ad.len >= 1);
    context.rekey(key) catch @panic("libcrypto failed to rekey a QUIC packet key");
    context.sealDetached(nonce, ad, data, tag) catch @panic("libcrypto failed to seal a QUIC packet");
}

/// A forgery is `AuthenticationFailed`, which is all the contract lets an
/// open return; a rekey libcrypto refused is folded into it too, since the
/// packet cannot be opened either way and a peer's packet must never stop
/// the process.
fn open(context: *zssl.quic.PacketKey, data: []u8, tag: *const [16]u8, ad: []const u8, nonce: *const [12]u8, key: []const u8) AuthenticationError!void {
    assert(ad.len >= 1);
    assert(key.len == 16 or key.len == 32);
    context.rekey(key) catch return error.AuthenticationFailed;
    context.openDetached(nonce, ad, data, tag) catch return error.AuthenticationFailed;
}

// -- header protection (RFC 9001 §5.4.3, §5.4.4): h3's contract; a
// failure stops the process for the reason `seal` gives --

/// One AES-128 block: §5.4.3's header-protection mask source.
pub fn aes128EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [16]u8) void {
    encryptBlock(&madeContexts().aes128_header, out, in, key);
}

/// One AES-256 block: §5.4.3's header-protection mask source.
pub fn aes256EncryptBlock(out: *[16]u8, in: *const [16]u8, key: *const [32]u8) void {
    encryptBlock(&madeContexts().aes256_header, out, in, key);
}

fn encryptBlock(context: *zssl.quic.HeaderKey, out: *[16]u8, input: *const [16]u8, key: []const u8) void {
    assert(key.len == 16 or key.len == 32);
    assert(@intFromPtr(out) != @intFromPtr(input));
    context.rekey(key) catch @panic("libcrypto failed to rekey a QUIC header key");
    context.encryptBlock(input, out) catch @panic("libcrypto failed a QUIC header block");
}

/// RFC 8439 §2.4's keystream, `out.len` octets from block `counter`: the
/// sixteen-octet IV libcrypto's ChaCha20 takes is the counter, little
/// endian, then the nonce — h3's sample, put back together.
pub fn chacha20Keystream(out: []u8, key: *const [32]u8, counter: u32, nonce: *const [12]u8) void {
    assert(out.len >= 1);
    assert(out.len <= zssl.quic.HeaderKey.keystream_bytes_max);
    var iv: [16]u8 = undefined;
    std.mem.writeInt(u32, iv[0..4], counter, .little);
    iv[4..16].* = nonce.*;
    const context = &madeContexts().chacha_header;
    context.rekey(key) catch @panic("libcrypto failed to rekey a QUIC header key");
    context.writeKeystream(&iv, out) catch @panic("libcrypto failed a QUIC header keystream");
}

// -- key derivation (RFC 5869): h3's contract, over std.crypto's HMAC --

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

/// RFC 5869 extract over SHA-256: RFC 9001 §5.2's Initial secret.
pub fn hkdfSha256Extract(prk: *[32]u8, salt: []const u8, ikm: []const u8) void {
    assert(salt.len >= 1);
    assert(ikm.len <= 20);
    prk.* = HkdfSha256.extract(salt, ikm);
}

/// RFC 5869 expand over SHA-256, `info` the label h3 built.
pub fn hkdfSha256Expand(out: []u8, prk: *const [32]u8, info: []const u8) void {
    assert(out.len >= 1);
    assert(out.len <= 48);
    HkdfSha256.expand(out, info, prk.*);
}

/// RFC 5869 expand over SHA-384, for AES-256-GCM's schedule.
pub fn hkdfSha384Expand(out: []u8, prk: *const [48]u8, info: []const u8) void {
    assert(out.len >= 1);
    assert(out.len <= 48);
    HkdfSha384.expand(out, info, prk.*);
}

test "QuicCrypto: every suite round-trips in place, refuses a forgery, and rekeys between keys" {
    const made = try ensure();
    defer if (made) deinit();
    const ad = "a QUIC packet header";
    const nonce: [12]u8 = @splat(0x07);
    var tag: [16]u8 = undefined;
    var data: [33]u8 = undefined;
    // Two keys in turn on one context: the rekey is what keeps the
    // process off the libcrypto heap, so it is what has to be exact.
    for ([_]u8{ 0x11, 0x22 }) |fill| {
        const key16: [16]u8 = @splat(fill);
        const key32: [32]u8 = @splat(fill);
        @memset(&data, 0x5a);
        aes128GcmSeal(&data, &tag, ad, &nonce, &key16);
        try std.testing.expect(!std.mem.allEqual(u8, &data, 0x5a));
        try aes128GcmOpen(&data, &tag, ad, &nonce, &key16);
        try std.testing.expect(std.mem.allEqual(u8, &data, 0x5a));
        aes256GcmSeal(&data, &tag, ad, &nonce, &key32);
        try aes256GcmOpen(&data, &tag, ad, &nonce, &key32);
        try std.testing.expect(std.mem.allEqual(u8, &data, 0x5a));
        chacha20Poly1305Seal(&data, &tag, ad, &nonce, &key32);
        tag[0] ^= 1;
        try std.testing.expectError(error.AuthenticationFailed, chacha20Poly1305Open(&data, &tag, ad, &nonce, &key32));
    }
}

test "QuicCrypto: the header block and keystream are libcrypto's AES and ChaCha20" {
    const made = try ensure();
    defer if (made) deinit();
    const key16: [16]u8 = @splat(0x33);
    const in: [16]u8 = @splat(0x44);
    var ours: [16]u8 = undefined;
    aes128EncryptBlock(&ours, &in, &key16);
    var theirs: [16]u8 = undefined;
    std.crypto.core.aes.Aes128.initEnc(key16).encrypt(&theirs, &in);
    try std.testing.expectEqualSlices(u8, &theirs, &ours);
    const key32: [32]u8 = @splat(0x55);
    const nonce: [12]u8 = @splat(0x66);
    var stream: [5]u8 = undefined;
    chacha20Keystream(&stream, &key32, 9, &nonce);
    var expected: [5]u8 = @splat(0);
    std.crypto.stream.chacha.ChaCha20IETF.xor(&expected, &expected, 9, key32, nonce);
    try std.testing.expectEqualSlices(u8, &expected, &stream);
}
