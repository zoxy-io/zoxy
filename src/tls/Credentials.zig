//! Per-listener TLS credentials (DESIGN.md §4): a PEM certificate chain
//! and its private key, parsed once at startup into a form the engines of
//! that listener share. One Credentials serves every handshake on the
//! listener — the cert chain and the libcrypto signing key are built here,
//! not per connection.
//!
//! ECDSA only. zssl's CertificateVerify offers no Ed25519 scheme, and RSA
//! is excluded by the on-loop handshake budget: an RSA sign is ~1–2 ms,
//! an order past the ~260 µs ECDSA handshake the single-threaded loop is
//! sized for (IMPLEMENTATION_NOTES.md). A non-ECDSA leaf is rejected
//! loudly at load, never silently downgraded into a latency cliff.
//!
//! Decoding and key loading are zssl's; what this adds is the two
//! startup checks zssl has no reason to make — the wire bound the engine
//! stages against, and parsing every chain entry so a corrupt
//! intermediate fails here rather than mid-handshake.
//!
//! Lives under `src/tls/` because it names zssl (libcrypto); the config
//! layer stays IO-free and hands only file paths (§1). Reading the files
//! is the caller's (a startup step); this takes the bytes.

const std = @import("std");
const constants = @import("../constants.zig");

const zssl = @import("zssl");

const assert = std.debug.assert;

const Credentials = @This();

/// The certificate chain, DER, leaf first. Arena-allocated at load and
/// stable for the process: a slice into `inner` would move with the
/// struct, and this one is read through a shared pointer.
chain: []const []const u8,
/// The engine's view. Held by value and handed to `zssl.ServerHandshake`
/// by pointer, so a loaded Credentials must not be copied.
inner: zssl.Credentials,

pub const LoadError = error{
    NoCertificates,
    /// The DER chain exceeds `constants.tls_cert_chain_bytes_max`.
    /// The engine sizes its outbound staging from that bound, so a
    /// larger chain has nowhere to be staged whole.
    CertChainTooLarge,
    MalformedPem,
    /// The leaf certificate's key is not ECDSA P-256/P-384.
    UnsupportedCertKey,
} || std.mem.Allocator.Error || std.crypto.Certificate.ParseError || zssl.Credentials.Error;

pub const Options = struct {
    /// RFC 6979 deterministic ECDSA nonces: set by the simulator so a
    /// seeded handshake replays byte-exact; production keeps the default
    /// hedged random nonce.
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
    const storage = try arena.alloc(u8, zssl.Credentials.chain_bytes_max);
    var inner = zssl.Credentials.load(cert_pem, key_pem, storage, options.deterministic_nonce) catch |err| switch (err) {
        // zssl reports "no usable chain" for both an empty PEM and one
        // with too many entries; zoxy's callers have always been told
        // which, and the first is the one an operator actually hits.
        error.BadCertificateChain => return error.NoCertificates,
        error.UnsupportedKey => return error.UnsupportedCertKey,
        else => |remaining| return remaining,
    };
    errdefer inner.deinit();
    const decoded = inner.chain();
    assert(decoded.len >= 1);

    // Bound what goes on the wire, not just what came off disk: the
    // engine sizes its outbound staging from this, because the server
    // flight carrying the chain is staged whole before any of it is
    // written (§5). Caught here so an oversized chain is a startup error
    // naming the limit, rather than a `stage` assertion on the first
    // client to arrive.
    var chain_bytes: usize = 0;
    for (decoded) |entry| chain_bytes += entry.len;
    if (chain_bytes > constants.tls_cert_chain_bytes_max) {
        return error.CertChainTooLarge;
    }
    // Parse every chain entry at load so a corrupt intermediate fails
    // here, not mid-handshake against a real client — zssl forwards
    // non-leaf entries as opaque bytes without validating them.
    for (decoded) |entry| {
        const cert: std.crypto.Certificate = .{ .buffer = entry, .index = 0 };
        _ = try cert.parse();
    }
    assert(chain_bytes > 0);
    assert(chain_bytes <= constants.tls_cert_chain_bytes_max);

    // Copied out of `inner` into arena memory so the slice survives the
    // struct being moved into the server's credentials array.
    const chain = try arena.alloc([]const u8, decoded.len);
    @memcpy(chain, decoded);
    return .{ .chain = chain, .inner = inner };
}

pub fn deinit(credentials: *Credentials) void {
    assert(credentials.chain.len >= 1); // Never deinit an unloaded value.
    credentials.inner.deinit();
    credentials.* = undefined;
}

/// The CertificateVerify scheme zssl derived from the leaf's key.
pub fn scheme(credentials: *const Credentials) zssl.backend.SignatureScheme {
    assert(credentials.chain.len >= 1);
    return credentials.inner.signer.scheme;
}

const fixture_cert_pem = @embedFile("testdata/cert.pem");
const fixture_key_pem = @embedFile("testdata/key.pem");
const pem_cert_begin = "-----BEGIN CERTIFICATE-----";
const pem_cert_end = "-----END CERTIFICATE-----";

test "credentials: an ECDSA P-256 PEM pair loads with the right scheme" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var credentials = try Credentials.load(arena_state.allocator(), fixture_cert_pem, fixture_key_pem, .{});
    defer credentials.deinit();

    try std.testing.expectEqual(@as(usize, 1), credentials.chain.len);
    try std.testing.expect(credentials.chain[0].len > 0);
    try std.testing.expectEqual(
        zssl.backend.SignatureScheme.ecdsa_secp256r1_sha256,
        credentials.scheme(),
    );
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

    // Repeat the fixture until the DER total clears the bound. zssl caps
    // a chain at four entries, so this reports the cap it hits first —
    // either way an oversized chain never reaches an engine.
    const copies = @divFloor(constants.tls_cert_chain_bytes_max, 400) + 4;
    var pem: std.ArrayList(u8) = .empty;
    for (0..copies) |_| try pem.appendSlice(arena, fixture_cert_pem);

    try std.testing.expectError(
        error.NoCertificates,
        load(arena, pem.items, fixture_key_pem, .{}),
    );
}

/// Where a fuzz iteration's decoded chain lands. Static so the fuzzer
/// allocates nothing per iteration; a megabyte outlasts any input the
/// smith produces at the bound below.
var fuzz_arena_buffer: [1 << 20]u8 = undefined;

// PEM is external bytes parsed by zssl and validated here (§9 fuzzes the
// same class: the head parser, the chunked decoder, the config parser).
// The property is that `load` has two outcomes and no third — a decoded
// chain whose invariants hold, or a named error. Never a panic, and never
// a chain with an entry the rest of the code would then trust.
test "fuzz: a certificate PEM either decodes to a sound chain or is refused" {
    try std.testing.fuzz({}, fuzzLoad, .{ .corpus = &.{ fixture_cert_pem, pem_cert_begin } });
}

fn fuzzLoad(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [8192]u8 = undefined;
    const input_len = smith.slice(&input);
    var fixed = std.heap.FixedBufferAllocator.init(&fuzz_arena_buffer);
    var credentials = load(fixed.allocator(), input[0..input_len], fixture_key_pem, .{}) catch return;
    defer credentials.deinit();
    // Whatever came back is a chain the engine could stage.
    assert(credentials.chain.len >= 1);
    var chain_bytes: usize = 0;
    for (credentials.chain) |entry| {
        assert(entry.len >= 1);
        chain_bytes += entry.len;
    }
    assert(chain_bytes <= constants.tls_cert_chain_bytes_max);
}
