//! Per-listener TLS credentials (DESIGN.md §4): a PEM certificate chain
//! and its private key, parsed once at startup into a form the engines of
//! that listener share. One Credentials serves every handshake on the
//! listener — the cert chain and the libcrypto signing key are built here,
//! not per connection.
//!
//! ECDSA P-256/P-384, or RSA of 2048 to 4096 bits signing RSA-PSS (#411).
//! Configuring an RSA key opts into its signing cost on the loop (§3).
//! Certificate selection prefers ECDSA among compatible keys within
//! each name tier (`certificate_set.zig`), and `tls_rsa_signed` counts
//! completed handshakes that used RSA.
//!
//! Decoding and key loading are zssl's; what this adds is the three
//! startup checks zssl has no reason to make — the wire bound the engine
//! stages against, parsing every chain entry so a corrupt intermediate
//! fails here rather than mid-handshake, and that the key is the leaf's.
//!
//! Lives under `src/tls/` because it names zssl (libcrypto); the config
//! layer stays IO-free (§1). Reading the files is the front-end's, and
//! this takes the bytes (#417).

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
    /// The key is neither ECDSA P-256/P-384 nor RSA of 2048 to 4096 bits.
    UnsupportedCertKey,
    /// The key is not the leaf certificate's: a signature it makes does
    /// not verify against the leaf's public key, or the two are not even
    /// the same kind of key. Every handshake would fail the client's
    /// CertificateVerify check, so the pair is refused here instead.
    CertificateKeyMismatch,
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
    // An empty file is an operator mistake worth naming, and zssl
    // asserts rather than returns on one — its contract is that the
    // embedder validated its own config. This is where that validation
    // lives.
    if (cert_pem.len == 0) return error.NoCertificates;
    if (key_pem.len == 0) return error.UnsupportedCertKey;
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
    // zssl classified the key and refused anything outside its policy;
    // what it admits is one ECDSA scheme or the three RSA-PSS digests.
    const supported = inner.signer.supported();
    assert(supported.len >= 1);
    for (supported) |each| assert(each.keyKind() == supported[0].keyKind());
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
    // non-leaf entries as opaque bytes without validating them. The leaf
    // is kept: its public key is the one the key must match.
    var leaf: ?std.crypto.Certificate.Parsed = null;
    for (decoded, 0..) |entry, index| {
        const cert: std.crypto.Certificate = .{ .buffer = entry, .index = 0 };
        const parsed = try cert.parse();
        if (index == 0) leaf = parsed;
    }
    assert(chain_bytes > 0);
    assert(chain_bytes <= constants.tls_cert_chain_bytes_max);
    try expectKeyOfLeaf(&inner.signer, &leaf.?);

    // Copied out of `inner` into arena memory so the slice survives the
    // struct being moved into the server's credentials array.
    const chain = try arena.alloc([]const u8, decoded.len);
    @memcpy(chain, decoded);
    return .{ .chain = chain, .inner = inner };
}

/// What `load` signs to learn whether the key is the leaf's. Any bytes
/// would do: the question is whether the leaf's public key verifies a
/// signature the key made, not what was signed.
const pairing_message = "zoxy: is this the key of this certificate?";

/// What the leaf says about a signature the key made.
const Pairing = enum {
    matched,
    mismatched,
    /// An RSA modulus `std.crypto` cannot verify at (`rsaPairing`).
    unverifiable,
};

/// Refuse a key that is not the leaf's. zssl loads the two apart and
/// never compares them. Without this a mismatched pair would start, pass
/// `--check`, and fail every handshake: a client checks the
/// CertificateVerify against the leaf, and another key's signature fails
/// that check. So load makes the same check once: the key signs, and the
/// leaf's public key must verify the signature.
///
/// The verifiers are the ones zssl uses for a peer's CertificateVerify:
/// libcrypto for ECDSA (`zssl.backend.verifyEcdsa`) and `std.crypto` for
/// RSA-PSS. Keep ECDSA on libcrypto, though it means libcrypto checks its
/// own signature. `std.crypto` verifies P-256 slowly in a Debug build,
/// and the simulator loads a pair for every TLS seed in Debug, so it more
/// than doubled every sweep's time. zssl's differential test already
/// checks `std.crypto` signatures against libcrypto's verifier.
fn expectKeyOfLeaf(
    signer: *const zssl.backend.Signer,
    leaf: *const std.crypto.Certificate.Parsed,
) LoadError!void {
    const scheme = signer.supported()[0];
    var signature_buffer: [zssl.backend.signature_bytes_max]u8 = undefined;
    const signature = try signer.sign(scheme, pairing_message, &signature_buffer);
    assert(signature.len >= 8);
    assert(signature.len <= zssl.backend.signature_bytes_max);
    const pairing: Pairing = switch (scheme.keyKind()) {
        .ecdsa => try ecdsaPairing(scheme, leaf, signature),
        .rsa => rsaPairing(scheme, leaf, signature),
    };
    switch (pairing) {
        .matched, .unverifiable => {},
        .mismatched => return error.CertificateKeyMismatch,
    }
}

/// An ECDSA key against the leaf: the leaf's curve must be the key's,
/// and its point must verify the signature under libcrypto.
fn ecdsaPairing(
    scheme: zssl.backend.SignatureScheme,
    leaf: *const std.crypto.Certificate.Parsed,
    signature: []const u8,
) error{LibcryptoFailed}!Pairing {
    assert(scheme.keyKind() == .ecdsa);
    assert(signature.len >= 8);
    const leaf_curve = switch (leaf.pub_key_algo) {
        .X9_62_id_ecPublicKey => |named_curve| named_curve,
        else => return .mismatched, // An ECDSA key beside an RSA leaf.
    };
    const key_curve: std.crypto.Certificate.NamedCurve = switch (scheme) {
        .ecdsa_secp256r1_sha256 => .X9_62_prime256v1,
        .ecdsa_secp384r1_sha384 => .secp384r1,
        // `keyKind` admitted only the two ECDSA schemes.
        .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => unreachable,
    };
    if (leaf_curve != key_curve) return .mismatched;
    // A leaf point off the curve is a leaf that cannot hold this key.
    zssl.backend.verifyEcdsa(scheme, leaf.pubKey(), pairing_message, signature) catch |err| return switch (err) {
        error.BadPublicKey, error.SignatureInvalid => .mismatched,
        else => error.LibcryptoFailed,
    };
    return .matched;
}

/// An RSA key against the leaf, under RSA-PSS with SHA-256, the scheme
/// the key signs first.
///
/// `std.crypto` verifies PSS at a modulus width fixed at compile time.
/// This verifies at three: 256, 384 and 512 bytes, the 2048-, 3072- and
/// 4096-bit moduli operators deploy. The verifier also asserts that the
/// encoded message fills the width, which a modulus of 8k+1 bits does
/// not. A pair at any other width, or at 8k+1 bits, loads unchecked: zssl
/// signs at any width from 2048 to 4096 bits and real clients verify
/// them, so refusing one would break a pair that works.
fn rsaPairing(
    scheme: zssl.backend.SignatureScheme,
    leaf: *const std.crypto.Certificate.Parsed,
    signature: []const u8,
) Pairing {
    // The verifier below digests with SHA-256. Were zssl to order another
    // scheme first, every RSA pair would read as a mismatch, so say so.
    assert(scheme == .rsa_pss_rsae_sha256);
    assert(signature.len >= 256); // zssl signs with 2048 bits or more.
    assert(signature.len <= zssl.backend.signature_bytes_max);
    switch (leaf.pub_key_algo) {
        .rsaEncryption => {},
        else => return .mismatched, // An RSA key beside an ECDSA leaf.
    }
    const rsa = std.crypto.Certificate.rsa;
    const components = rsa.PublicKey.parseDer(leaf.pubKey()) catch return .mismatched;
    // A PSS signature is exactly one modulus wide, so a leaf of another
    // width holds another key.
    if (signature.len != components.modulus.len) return .mismatched;
    const public_key = rsa.PublicKey.fromBytes(components.exponent, components.modulus) catch
        return .mismatched;
    if (public_key.n.bits() % 8 == 1) return .unverifiable;
    switch (components.modulus.len) {
        inline 256, 384, 512 => |width| {
            const padded = rsa.PSSSignature.fromBytes(width, signature);
            rsa.PSSSignature.verify(width, &padded, pairing_message, public_key, std.crypto.hash.sha2.Sha256) catch
                return .mismatched;
            return .matched;
        },
        else => return .unverifiable,
    }
}

pub fn deinit(credentials: *Credentials) void {
    assert(credentials.chain.len >= 1); // Never deinit an unloaded value.
    credentials.inner.deinit();
    credentials.* = undefined;
}

/// The CertificateVerify schemes zssl derived from the leaf's key, in its
/// preference order: the one its curve names for an ECDSA key, the three
/// RSA-PSS digests for an RSA one. A client must have offered one of them
/// (RFC 8446 §4.4.2), which is what `certificate_set.select` checks.
/// Borrowed from the signer, so as stable as the credentials themselves.
pub fn schemes(credentials: *const Credentials) []const zssl.backend.SignatureScheme {
    assert(credentials.chain.len >= 1);
    const supported = credentials.inner.signer.supported();
    assert(supported.len >= 1);
    assert(supported.len <= 3);
    return supported;
}

const fixture_cert_pem = @embedFile("testdata/cert.pem");
const fixture_key_pem = @embedFile("testdata/key.pem");
/// An RSA-2048 key and its self-signed certificate (#411).
const fixture_rsa_key_pem = @embedFile("testdata/rsa2048-key.pem");
const fixture_rsa_cert_pem = @embedFile("testdata/rsa2048-cert.pem");
/// The pairing check's fixtures (`testdata/README.md`): a P-384 pair, a
/// second RSA-2048 key, the RSA-4096 pair, an RSA pair whose 3065-bit
/// modulus `std.crypto` cannot verify at, and the mutual-TLS client's
/// P-256 key, which is not `cert.pem`'s.
const fixture_p384_key_pem = @embedFile("testdata/p384-key.pem");
const fixture_p384_cert_pem = @embedFile("testdata/p384-cert.pem");
const fixture_rsa_other_key_pem = @embedFile("testdata/rsa2048-other-key.pem");
const fixture_rsa4096_key_pem = @embedFile("testdata/rsa4096-key.pem");
const fixture_rsa4096_cert_pem = @embedFile("testdata/rsa4096-cert.pem");
const fixture_rsa3065_key_pem = @embedFile("testdata/rsa3065-key.pem");
const fixture_rsa3065_cert_pem = @embedFile("testdata/rsa3065-cert.pem");
const fixture_other_p256_key_pem = @embedFile("testdata/client-key.pem");
const pem_cert_begin = "-----BEGIN CERTIFICATE-----";
const pem_cert_end = "-----END CERTIFICATE-----";
const fuzzSeed = @import("../testing/bytes.zig").fuzzSeed;

test "credentials: a key that is not its certificate's is refused at load" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Mismatch = struct { cert: []const u8, key: []const u8 };
    const mismatches = [_]Mismatch{
        // The same kind and size, another key: the signature fails.
        .{ .cert = fixture_cert_pem, .key = fixture_other_p256_key_pem },
        .{ .cert = fixture_rsa_cert_pem, .key = fixture_rsa_other_key_pem },
        // The same kind, another size: another curve, another width.
        .{ .cert = fixture_cert_pem, .key = fixture_p384_key_pem },
        .{ .cert = fixture_p384_cert_pem, .key = fixture_key_pem },
        .{ .cert = fixture_rsa_cert_pem, .key = fixture_rsa4096_key_pem },
        .{ .cert = fixture_rsa4096_cert_pem, .key = fixture_rsa_key_pem },
        // Another kind altogether.
        .{ .cert = fixture_cert_pem, .key = fixture_rsa_key_pem },
        .{ .cert = fixture_rsa_cert_pem, .key = fixture_key_pem },
        // A width `std.crypto` cannot verify at is still refused when the
        // key's own width differs from it.
        .{ .cert = fixture_rsa3065_cert_pem, .key = fixture_rsa_key_pem },
    };
    for (mismatches) |mismatch| {
        try std.testing.expectError(
            error.CertificateKeyMismatch,
            Credentials.load(arena, mismatch.cert, mismatch.key, .{}),
        );
    }
}

test "credentials: every key kind and RSA width loads beside its own certificate" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Pair = struct { cert: []const u8, key: []const u8, scheme: zssl.backend.SignatureScheme };
    const pairs = [_]Pair{
        .{ .cert = fixture_cert_pem, .key = fixture_key_pem, .scheme = .ecdsa_secp256r1_sha256 },
        .{ .cert = fixture_p384_cert_pem, .key = fixture_p384_key_pem, .scheme = .ecdsa_secp384r1_sha384 },
        .{ .cert = fixture_rsa_cert_pem, .key = fixture_rsa_key_pem, .scheme = .rsa_pss_rsae_sha256 },
        .{ .cert = fixture_rsa4096_cert_pem, .key = fixture_rsa4096_key_pem, .scheme = .rsa_pss_rsae_sha256 },
        // Loaded unchecked rather than refused: real clients verify a
        // 3065-bit modulus, and `std.crypto` would assert on it.
        .{ .cert = fixture_rsa3065_cert_pem, .key = fixture_rsa3065_key_pem, .scheme = .rsa_pss_rsae_sha256 },
    };
    for (pairs) |pair| {
        var credentials = try Credentials.load(arena, pair.cert, pair.key, .{});
        defer credentials.deinit();
        try std.testing.expectEqual(pair.scheme, credentials.schemes()[0]);
    }
}

test "credentials: an ECDSA P-256 PEM pair loads with the right scheme" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var credentials = try Credentials.load(arena_state.allocator(), fixture_cert_pem, fixture_key_pem, .{});
    defer credentials.deinit();

    try std.testing.expectEqual(@as(usize, 1), credentials.chain.len);
    try std.testing.expect(credentials.chain[0].len > 0);
    try std.testing.expectEqualSlices(
        zssl.backend.SignatureScheme,
        &.{.ecdsa_secp256r1_sha256},
        credentials.schemes(),
    );
    // The parsed leaf DER round-trips through std.crypto's parser.
    const cert: std.crypto.Certificate = .{ .buffer = credentials.chain[0], .index = 0 };
    _ = try cert.parse();
}

test "credentials: an RSA-2048 pair loads, signing under the three RSA-PSS digests (#411)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var credentials = try Credentials.load(arena_state.allocator(), fixture_rsa_cert_pem, fixture_rsa_key_pem, .{});
    defer credentials.deinit();
    try std.testing.expectEqualSlices(
        zssl.backend.SignatureScheme,
        &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
        credentials.schemes(),
    );
    // PSS draws a fresh salt per signature, so an RSA key cannot give the
    // simulator the replayable flights it asks for — refused, not faked.
    try std.testing.expectError(
        error.DeterministicNonceUnsupported,
        Credentials.load(arena_state.allocator(), fixture_rsa_cert_pem, fixture_rsa_key_pem, .{ .deterministic_nonce = true }),
    );
}

test "credentials: a PEM with no certificate block is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.NoCertificates,
        Credentials.load(arena_state.allocator(), "not a pem file", fixture_key_pem, .{}),
    );
}

// Both guards exist because zssl *asserts* on empty input rather than
// returning — its contract is that the embedder validated its own
// config, and this is where that validation lives. A guard added to
// close an assert-on-operator-input gap needs a gate of its own, or the
// next refactor removes it as dead code.
test "credentials: an empty certificate or key file is named, not asserted" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectError(
        error.NoCertificates,
        Credentials.load(arena, "", fixture_key_pem, .{}),
    );
    try std.testing.expectError(
        error.UnsupportedCertKey,
        Credentials.load(arena, fixture_cert_pem, "", .{}),
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
//
// Seeds go through `fuzzSeed`: `Smith.slice` reads a length before the
// bytes, so a bare seed lost its first four.
test "fuzz: a certificate PEM either decodes to a sound chain or is refused" {
    try std.testing.fuzz(@as([]const u8, fixture_key_pem), fuzzLoad, .{
        .corpus = &.{ fuzzSeed(fixture_cert_pem), fuzzSeed(pem_cert_begin) },
    });
}

// The same property beside an RSA key, so the pairing check's RSA arm
// sees mutated leaves: a modulus parsed out of fuzzed DER and fed to
// `std.crypto`'s PSS verifier. A mutation that turns the 2048-bit
// modulus into 2041 bits, still 256 bytes, reaches the 8k+1 guard.
test "fuzz: a certificate PEM beside an RSA key decodes to a sound chain or is refused" {
    try std.testing.fuzz(@as([]const u8, fixture_rsa_key_pem), fuzzLoad, .{
        .corpus = &.{ fuzzSeed(fixture_rsa_cert_pem), fuzzSeed(fixture_rsa3065_cert_pem) },
    });
}

fn fuzzLoad(key_pem: []const u8, smith: *std.testing.Smith) !void {
    assert(key_pem.len >= 1);
    var input: [8192]u8 = undefined;
    const input_len = smith.slice(&input);
    var fixed = std.heap.FixedBufferAllocator.init(&fuzz_arena_buffer);
    var credentials = load(fixed.allocator(), input[0..input_len], key_pem, .{}) catch return;
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
