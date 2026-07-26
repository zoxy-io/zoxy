//! Per-listener TLS credentials (DESIGN.md §4, Phase 3a slice 3): a PEM
//! certificate chain and its private key, parsed once at startup into a
//! form the engines of that listener share. One Credentials serves every
//! handshake on the listener — the cert chain and the libcrypto signing
//! key are built here, not per connection.
//!
//! ECDSA only. ztls's CertificateVerify offers no Ed25519 scheme, and RSA
//! is excluded by the Phase-3a on-loop handshake budget (an RSA sign is
//! ~1–2 ms, an order past the ECDSA cost the budget is sized for —
//! PLANS.md), so a non-ECDSA leaf is rejected loudly at load, never
//! silently downgraded.
//!
//! Lives under `src/tls/` because it names ztls (libcrypto); the config
//! layer stays IO-free and hands only file paths (§1). Reading the files
//! is the caller's (a startup step); this takes the bytes.

const std = @import("std");
const constants = @import("../constants.zig");

const ztls = @import("ztls");

const assert = std.debug.assert;

const Credentials = @This();

/// The certificate chain, DER, leaf first — as `setCredentials` wants it.
/// Arena-allocated at load; lives for the process.
chain: []const []const u8,
/// The leaf's signing key. Owns a libcrypto object; `deinit` frees it.
key: ztls.signature.PrivateKey,
/// The CertificateVerify scheme, derived from the leaf's key.
scheme: ztls.SignatureScheme,

pub const LoadError = error{
    NoCertificates,
    /// The DER chain exceeds `constants.tls_cert_chain_bytes_max`.
    /// The engine sizes its outbound staging from that bound, so a
    /// larger chain has nowhere to be staged whole.
    CertChainTooLarge,
    MalformedPem,
    /// The leaf certificate's key is not ECDSA P-256/P-384.
    UnsupportedCertKey,
} || std.mem.Allocator.Error || std.crypto.Certificate.ParseError || ztls.signature.SignError;

pub const Options = struct {
    /// RFC 6979 deterministic ECDSA nonce (mattrobenolt/ztls#82): set by
    /// the simulator so a seeded handshake replays byte-exact; production
    /// keeps the default random nonce.
    deterministic_nonce: bool = false,
};

/// Parse a PEM certificate chain and PEM private key into credentials.
/// `arena` owns the decoded chain for the process; the caller keeps the
/// key-PEM bytes only until this returns.
pub fn load(
    arena: std.mem.Allocator,
    cert_pem: []const u8,
    key_pem: []const u8,
    options: Options,
) LoadError!Credentials {
    const chain = try decodePemChain(arena, cert_pem);
    assert(chain.len >= 1);
    // Bound what goes on the wire, not just what came off disk: the
    // engine sizes its outbound staging from this, because the server
    // flight carrying the chain is staged whole before any of it is
    // written (§5). Caught here so an oversized chain is a startup error
    // naming the limit, rather than a `stage` assertion on the first
    // client to arrive.
    var chain_bytes: usize = 0;
    for (chain) |entry| chain_bytes += entry.len;
    if (chain_bytes > constants.tls_cert_chain_bytes_max) {
        return error.CertChainTooLarge;
    }
    // Parse every chain entry at load so a corrupt intermediate fails
    // here, not mid-handshake against a real client — ztls forwards
    // non-leaf entries as opaque bytes without validating them.
    for (chain) |entry| {
        const cert: std.crypto.Certificate = .{ .buffer = entry, .index = 0 };
        _ = try cert.parse();
    }
    const scheme = try schemeForLeaf(chain[0]);
    var key = try ztls.signature.PrivateKey.fromPem(scheme, key_pem);
    key.deterministic_nonce = options.deterministic_nonce;
    assert(key.scheme == scheme); // fromPem stamps the derived scheme.
    return .{ .chain = chain, .key = key, .scheme = scheme };
}

pub fn deinit(credentials: *Credentials) void {
    credentials.key.deinit();
}

/// The signer for this listener's key. ztls's `PrivateKey.signer` takes
/// `*PrivateKey`, but the sign path only reads the key and a Credentials
/// is shared read-only across a listener's engines, so the cast is sound
/// and keeps the shared pointer const for its holders.
pub fn signer(credentials: *const Credentials) ztls.signature.Signer {
    return @constCast(&credentials.key).signer();
}

/// The CertificateVerify scheme for a leaf certificate — ECDSA P-256 or
/// P-384 only; every other key type is `UnsupportedCertKey`.
fn schemeForLeaf(leaf_der: []const u8) LoadError!ztls.SignatureScheme {
    assert(leaf_der.len > 0); // A decoded, non-empty cert block (§ decodePemBody).
    const cert: std.crypto.Certificate = .{ .buffer = leaf_der, .index = 0 };
    const parsed = try cert.parse();
    return switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| switch (curve) {
            .secp384r1 => .ecdsa_secp384r1_sha384,
            .X9_62_prime256v1 => .ecdsa_secp256r1_sha256,
            // P-521 has no ztls CertificateVerify scheme.
            .secp521r1 => error.UnsupportedCertKey,
        },
        else => error.UnsupportedCertKey,
    };
}

const pem_cert_begin = "-----BEGIN CERTIFICATE-----";
const pem_cert_end = "-----END CERTIFICATE-----";

/// Decode every `CERTIFICATE` block in a PEM file to DER, in file order
/// (leaf first, by convention). Rejects a `BEGIN` with no matching `END`
/// and a body that is not valid base64.
fn decodePemChain(arena: std.mem.Allocator, pem: []const u8) LoadError![]const []const u8 {
    var chain: std.ArrayList([]const u8) = .empty;
    var cursor: usize = 0;
    // Bounded: `cursor` strictly advances past each END marker every
    // iteration (body_end > cursor), so it reaches pem.len and the scan
    // ends after at most one pass over the file.
    while (std.mem.indexOfPos(u8, pem, cursor, pem_cert_begin)) |begin| {
        assert(begin >= cursor);
        const body_start = begin + pem_cert_begin.len;
        const body_end = std.mem.indexOfPos(u8, pem, body_start, pem_cert_end) orelse
            return error.MalformedPem;
        const der = try decodePemBody(arena, pem[body_start..body_end]);
        try chain.append(arena, der);
        cursor = body_end + pem_cert_end.len;
        assert(cursor <= pem.len);
    }
    if (chain.items.len == 0) return error.NoCertificates;
    return chain.toOwnedSlice(arena);
}

/// Strip PEM whitespace from a base64 body and decode it to a fresh DER
/// buffer. The stripped base64 goes to a scratch slice, freed to the
/// arena's high-water on return — startup-only, so the churn is fine.
fn decodePemBody(arena: std.mem.Allocator, body: []const u8) LoadError![]const u8 {
    const scratch = try arena.alloc(u8, body.len);
    var len: usize = 0;
    for (body) |c| switch (c) {
        ' ', '\t', '\n', '\r' => {},
        else => {
            scratch[len] = c;
            len += 1;
        },
    };
    assert(len <= body.len); // Only non-whitespace bytes were copied.
    // A whitespace-only block would base64-decode to an empty DER — a
    // malformed certificate, not a valid zero-length one.
    if (len == 0) return error.MalformedPem;
    const base64 = std.base64.standard.Decoder;
    const der_len = base64.calcSizeForSlice(scratch[0..len]) catch return error.MalformedPem;
    const der = try arena.alloc(u8, der_len);
    base64.decode(der, scratch[0..len]) catch return error.MalformedPem;
    return der;
}

const fixture_cert_pem = @embedFile("testdata/cert.pem");
const fixture_key_pem = @embedFile("testdata/key.pem");

test "credentials: an ECDSA P-256 PEM pair loads with the right scheme" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var credentials = try Credentials.load(arena_state.allocator(), fixture_cert_pem, fixture_key_pem, .{});
    defer credentials.deinit();

    try std.testing.expectEqual(@as(usize, 1), credentials.chain.len);
    try std.testing.expect(credentials.chain[0].len > 0);
    try std.testing.expectEqual(ztls.SignatureScheme.ecdsa_secp256r1_sha256, credentials.scheme);
    // The parsed leaf DER round-trips through std.crypto's parser.
    const cert: std.crypto.Certificate = .{ .buffer = credentials.chain[0], .index = 0 };
    _ = try cert.parse();
}

test "credentials: a PEM with no certificate block is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.NoCertificates,
        Credentials.load(arena_state.allocator(), "not a pem file", fixture_key_pem, .{}),
    );
}

test "credentials: a BEGIN without END is malformed, not a silent empty chain" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.MalformedPem,
        Credentials.load(arena_state.allocator(), pem_cert_begin ++ "\nAAAA\n", fixture_key_pem, .{}),
    );
}

test "credentials: a whitespace-only certificate block is malformed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    // Well-formed markers, empty body — must not decode to a zero-length
    // DER that only fails later against a real client.
    const empty_block = pem_cert_begin ++ "\n   \n\t\n" ++ pem_cert_end ++ "\n";
    try std.testing.expectError(
        error.MalformedPem,
        Credentials.load(arena_state.allocator(), empty_block, fixture_key_pem, .{}),
    );
}

// The engine sizes its outbound staging from `tls_cert_chain_bytes_max`,
// so a chain past it has nowhere to be staged whole. Catching that at
// load makes it a startup error naming the limit, instead of a `stage`
// assertion the first time a real client connects.
test "credentials: a chain past the wire bound is refused at load" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Repeat the fixture until the DER total clears the bound. Each copy
    // parses, so this fails on size and nothing else.
    const copies = (constants.tls_cert_chain_bytes_max / 400) + 4;
    var pem: std.ArrayList(u8) = .empty;
    for (0..copies) |_| try pem.appendSlice(arena, fixture_cert_pem);

    try std.testing.expectError(
        error.CertChainTooLarge,
        load(arena, pem.items, fixture_key_pem, .{}),
    );
}
