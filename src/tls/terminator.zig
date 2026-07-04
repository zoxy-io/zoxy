//! TLS termination over memory BIO pairs (docs/DESIGN.md §6, Phase 3
//! slice 2). Sans-io: the `Channel` is a pure byte transformer — ciphertext
//! in/out through fixed-size BIO-pair buffers, plaintext in/out through the
//! caller's buffers. It knows nothing about sockets or the ring; ProxyConn
//! drives it from recv/send completions, so run-to-completion holds and all
//! real I/O stays completion-based.
//!
//! Everything here allocates only via the OpenSSL memory hook (the reserved
//! TLS heap): `Context.init` at startup, `Channel.init` at accept time.
//! Exhaustion fails the accept — load-shedding, not OOM.

const std = @import("std");
const assert = std.debug.assert;
const openssl = @import("openssl.zig");
const kernel = @import("kernel.zig");
const constants = @import("../constants.zig");

/// The ALPN identifier we speak today. h2 joins this list in the HTTP/2
/// slice; preference order is ours (server-chosen), first match wins.
pub const alpn_http1 = "http/1.1";

/// A connection's TLS 1.3 application traffic secrets, captured by the
/// process-wide keylog callback while the handshake derives them (kTLS
/// slice 2, docs/DESIGN.md §6). Armed per connection via
/// `Channel.capture_secrets`; must sit at a stable address from arming
/// until the channel is freed — OpenSSL holds a raw pointer to it.
pub const TrafficSecrets = struct {
    client: [secret_bytes_max]u8 = undefined,
    client_length: u8 = 0,
    server: [secret_bytes_max]u8 = undefined,
    server_length: u8 = 0,

    /// SHA-384 suites have the largest secrets.
    pub const secret_bytes_max = 48;

    pub fn complete(secrets: *const TrafficSecrets) bool {
        return secrets.client_length > 0 and secrets.server_length > 0;
    }

    pub fn client_secret(secrets: *const TrafficSecrets) []const u8 {
        assert(secrets.client_length > 0);
        assert(secrets.client_length <= secret_bytes_max);
        return secrets.client[0..secrets.client_length];
    }

    pub fn server_secret(secrets: *const TrafficSecrets) []const u8 {
        assert(secrets.server_length > 0);
        assert(secrets.server_length <= secret_bytes_max);
        return secrets.server[0..secrets.server_length];
    }
};

/// A process-lifetime SSL_CTX: the identity plus protocol policy every
/// connection's SSL is stamped from. Startup-only; workers treat it as
/// immutable (session cache and tickets are off, so OpenSSL does not
/// mutate shared state per handshake behind our back).
pub const Context = struct {
    context: *openssl.SSL_CTX,
    role: Role,

    pub const Role = enum { server, client };

    pub const InitError = error{
        ContextCreateFailed,
        InvalidCertificate,
        InvalidPrivateKey,
        CertificateKeyMismatch,
        ContextSetupFailed,
    };

    pub fn init_server(certificate_pem: []const u8, private_key_pem: []const u8) InitError!Context {
        assert(certificate_pem.len > 0);
        assert(private_key_pem.len > 0);
        defer openssl.ERR_clear_error();

        const context = openssl.SSL_CTX_new(openssl.TLS_server_method()) orelse
            return error.ContextCreateFailed;
        errdefer openssl.SSL_CTX_free(context);

        const certificate = openssl.read_pem_x509(certificate_pem) orelse
            return error.InvalidCertificate;
        defer openssl.X509_free(certificate);
        const private_key = openssl.read_pem_private_key(private_key_pem) orelse
            return error.InvalidPrivateKey;
        defer openssl.EVP_PKEY_free(private_key);

        // use_certificate/use_PrivateKey take their own references; our
        // parsed objects are freed on the way out either way.
        if (openssl.SSL_CTX_use_certificate(context, certificate) != 1)
            return error.InvalidCertificate;
        if (openssl.SSL_CTX_use_PrivateKey(context, private_key) != 1)
            return error.InvalidPrivateKey;
        if (openssl.SSL_CTX_check_private_key(context) != 1)
            return error.CertificateKeyMismatch;

        try harden(context);
        openssl.SSL_CTX_set_alpn_select_cb(context, alpn_select, null);
        return .{ .context = context, .role = .server };
    }

    /// Test-side peer: drives the server Channel deterministically through
    /// memory. No verification — the fixtures are self-signed.
    pub fn init_client() InitError!Context {
        const context = openssl.SSL_CTX_new(openssl.TLS_client_method()) orelse
            return error.ContextCreateFailed;
        errdefer openssl.SSL_CTX_free(context);
        try harden(context);
        return .{ .context = context, .role = .client };
    }

    /// TLS >= 1.2 only, no session cache, no tickets: every handshake is
    /// full (resumption is a later, measured decision) and the SSL_CTX
    /// stays effectively immutable across worker threads.
    fn harden(context: *openssl.SSL_CTX) InitError!void {
        const minimum = openssl.SSL_CTX_ctrl(
            context,
            openssl.SSL_CTRL_SET_MIN_PROTO_VERSION,
            openssl.TLS1_2_VERSION,
            null,
        );
        if (minimum != 1) return error.ContextSetupFailed;
        _ = openssl.SSL_CTX_ctrl(
            context,
            openssl.SSL_CTRL_SET_SESS_CACHE_MODE,
            openssl.SSL_SESS_CACHE_OFF,
            null,
        );
        if (openssl.SSL_CTX_set_num_tickets(context, 0) != 1) return error.ContextSetupFailed;
        // Keylog feeds the kTLS switchover (traffic secrets -> kernel keys).
        // Registered unconditionally: the callback is inert for connections
        // that never arm capture_secrets.
        openssl.SSL_CTX_set_keylog_callback(context, keylog_capture);
    }

    pub fn deinit(context: Context) void {
        openssl.SSL_CTX_free(context.context);
    }
};

/// OpenSSL's reserved application-data ex_data slot (the SSL_set_app_data
/// macro's index): holds the connection's `*TrafficSecrets` when capture
/// is armed, null otherwise.
const application_data_index: c_int = 0;

/// The process-wide keylog callback: routes the NSS-format line
/// ("<label> <client_random_hex> <secret_hex>") into the connection's
/// armed `TrafficSecrets`. Runs on whichever worker drives the handshake;
/// no shared state is touched.
fn keylog_capture(ssl: *const openssl.SSL, line: [*:0]const u8) callconv(.c) void {
    const data = openssl.SSL_get_ex_data(ssl, application_data_index) orelse return;
    const secrets: *TrafficSecrets = @ptrCast(@alignCast(data));
    store_keylog_line(secrets, std.mem.span(line));
}

fn store_keylog_line(secrets: *TrafficSecrets, line: []const u8) void {
    assert(line.len < 1024); // keylog lines are label + random + secret
    var parts = std.mem.splitScalar(u8, line, ' ');
    const label = parts.next() orelse return;
    _ = parts.next() orelse return; // client random: identifies, we already know
    const secret_hex = parts.next() orelse return;
    if (parts.next() != null) return; // malformed: extra fields
    if (std.mem.eql(u8, label, "CLIENT_TRAFFIC_SECRET_0")) {
        secrets.client_length = decode_secret(&secrets.client, secret_hex);
    } else if (std.mem.eql(u8, label, "SERVER_TRAFFIC_SECRET_0")) {
        secrets.server_length = decode_secret(&secrets.server, secret_hex);
    }
    // Handshake/exporter secrets and unknown labels fall through untouched.
}

fn decode_secret(target: *[TrafficSecrets.secret_bytes_max]u8, hex: []const u8) u8 {
    if (hex.len == 0 or hex.len % 2 != 0) return 0;
    if (hex.len / 2 > target.len) return 0;
    const decoded = std.fmt.hexToBytes(target, hex) catch return 0;
    assert(decoded.len == hex.len / 2);
    return @intCast(decoded.len);
}

/// Server-side ALPN selection: pick `http/1.1` from the client's list, or
/// answer "no overlap" (NOACK) — the handshake then completes without ALPN
/// and HTTP/1.1 is assumed, which matches pre-ALPN clients.
fn alpn_select(
    ssl: *openssl.SSL,
    out: *?[*]const u8,
    out_length: *u8,
    in: [*]const u8,
    in_length: c_uint,
    argument: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    assert(argument == null); // registered with no state
    var index: usize = 0;
    // The client list is length-prefixed entries; a zero-length entry is
    // malformed, so every iteration advances by at least one byte.
    while (index < in_length) {
        const length: usize = in[index];
        if (length == 0 or index + 1 + length > in_length) break;
        const protocol = in[index + 1 ..][0..length];
        if (std.mem.eql(u8, protocol, alpn_http1)) {
            // out points at our static string — valid for the SSL lifetime.
            out.* = alpn_http1.ptr;
            out_length.* = alpn_http1.len;
            return openssl.SSL_TLSEXT_ERR_OK;
        }
        index += 1 + length;
    }
    return openssl.SSL_TLSEXT_ERR_NOACK;
}

/// One connection's TLS state machine plus its in-memory "network": a BIO
/// pair with `constants.tls_bio_pair_bytes` per direction. The caller owns
/// all I/O; this type only transforms bytes.
pub const Channel = struct {
    ssl: *openssl.SSL,
    /// Our half of the pair — ciphertext to/from the actual network.
    network_bio: *openssl.BIO,

    pub const InitError = error{ChannelCreateFailed};

    pub const HandshakeStatus = enum { done, want_io, failed };
    pub const ReadResult = union(enum) {
        /// Plaintext bytes produced (> 0).
        bytes: usize,
        /// Needs more ciphertext fed (or drained) first.
        want_io,
        /// Peer sent close_notify: clean TLS EOF.
        closed,
        failed,
    };
    pub const WriteResult = union(enum) {
        /// Plaintext bytes consumed (> 0); ciphertext now pending.
        bytes: usize,
        /// The pair buffer is full: drain ciphertext, then retry.
        want_io,
        failed,
    };

    pub fn init(context: *const Context) InitError!Channel {
        const ssl = openssl.SSL_new(context.context) orelse return error.ChannelCreateFailed;
        errdefer openssl.SSL_free(ssl);

        var internal_bio: ?*openssl.BIO = null;
        var network_bio: ?*openssl.BIO = null;
        const paired = openssl.BIO_new_bio_pair(
            &internal_bio,
            constants.tls_bio_pair_bytes,
            &network_bio,
            constants.tls_bio_pair_bytes,
        );
        if (paired != 1) return error.ChannelCreateFailed;
        assert(internal_bio != null);
        assert(network_bio != null);

        // The SSL owns the internal half (single reference: rbio == wbio);
        // we own the network half until deinit.
        openssl.SSL_set_bio(ssl, internal_bio.?, internal_bio.?);
        switch (context.role) {
            .server => openssl.SSL_set_accept_state(ssl),
            .client => openssl.SSL_set_connect_state(ssl),
        }
        return .{ .ssl = ssl, .network_bio = network_bio.? };
    }

    pub fn deinit(channel: Channel) void {
        openssl.SSL_free(channel.ssl);
        _ = openssl.BIO_free(channel.network_bio);
        openssl.ERR_clear_error(); // leave no error-queue residue behind
    }

    /// Feed ciphertext that arrived from the network. Returns bytes
    /// consumed; short counts mean the pair buffer is full — make progress
    /// (handshake_step/read_plaintext), then re-feed the remainder.
    pub fn feed_ciphertext(channel: *Channel, ciphertext: []const u8) usize {
        assert(ciphertext.len > 0);
        assert(ciphertext.len <= std.math.maxInt(c_int));
        const written = openssl.BIO_write(
            channel.network_bio,
            ciphertext.ptr,
            @intCast(ciphertext.len),
        );
        if (written <= 0) return 0; // pair full: retryable, never fatal
        assert(@as(usize, @intCast(written)) <= ciphertext.len);
        return @intCast(written);
    }

    /// Ciphertext the state machine wants sent to the network.
    pub fn pending_ciphertext(channel: *const Channel) usize {
        return openssl.BIO_ctrl_pending(channel.network_bio);
    }

    /// Move pending ciphertext into `buffer` for an io.send. Returns bytes
    /// moved (0 = nothing pending).
    pub fn drain_ciphertext(channel: *Channel, buffer: []u8) usize {
        assert(buffer.len > 0);
        assert(buffer.len <= std.math.maxInt(c_int));
        if (channel.pending_ciphertext() == 0) return 0;
        const read = openssl.BIO_read(channel.network_bio, buffer.ptr, @intCast(buffer.len));
        if (read <= 0) return 0;
        assert(@as(usize, @intCast(read)) <= buffer.len);
        return @intCast(read);
    }

    /// Drive the handshake. `.want_io` means: drain pending ciphertext to
    /// the peer and/or feed more from it, then step again.
    pub fn handshake_step(channel: *Channel) HandshakeStatus {
        if (openssl.SSL_is_init_finished(channel.ssl) != 0) return .done;
        const result = openssl.SSL_do_handshake(channel.ssl);
        if (result == 1) return .done;
        return switch (openssl.SSL_get_error(channel.ssl, result)) {
            openssl.SSL_ERROR_WANT_READ, openssl.SSL_ERROR_WANT_WRITE => .want_io,
            else => failed: {
                openssl.ERR_clear_error();
                break :failed .failed;
            },
        };
    }

    pub fn handshake_done(channel: *const Channel) bool {
        return openssl.SSL_is_init_finished(channel.ssl) != 0;
    }

    /// Arm keylog capture: the handshake writes this connection's traffic
    /// secrets into `secrets` as it derives them. Must be called before the
    /// handshake runs, and `secrets` must keep its address until the
    /// channel is freed (OpenSSL holds the raw pointer).
    pub fn capture_secrets(channel: *Channel, secrets: *TrafficSecrets) void {
        assert(!channel.handshake_done()); // arming afterwards captures nothing
        assert(!secrets.complete()); // a fresh capture target
        const stored = openssl.SSL_set_ex_data(channel.ssl, application_data_index, secrets);
        assert(stored == 1);
    }

    /// The negotiated cipher suite's IANA id (0x1301, 0x1302, ...).
    pub fn negotiated_cipher_suite(channel: *const Channel) u16 {
        assert(channel.handshake_done());
        const cipher = openssl.SSL_get_current_cipher(channel.ssl).?; // non-null post-handshake
        const suite = openssl.SSL_CIPHER_get_protocol_id(cipher);
        assert(suite != 0);
        return suite;
    }

    /// Whether the kernel can take over the receive direction at record
    /// sequence zero (docs/DESIGN.md §6): true only when the SSL has
    /// consumed every fed ciphertext byte AND buffers nothing — any
    /// application-epoch record the peer sent with (or right after) its
    /// handshake flight would still be sitting in the pair's read side or
    /// inside the SSL, and makes the connection ineligible. The caller
    /// must additionally hold no unfed wire bytes of its own (ProxyConn's
    /// staging) and have issued no application write yet (its switch
    /// ordering); this checks everything the channel can see.
    pub fn kernel_switch_eligible(channel: *const Channel) bool {
        if (!channel.handshake_done()) return false;
        const read_bio = openssl.SSL_get_rbio(channel.ssl).?; // set at init
        if (openssl.BIO_ctrl_pending(read_bio) != 0) return false;
        if (openssl.SSL_has_pending(channel.ssl) != 0) return false;
        return true;
    }

    pub const KernelParameters = struct {
        transmit: kernel.CryptoParameters,
        receive: kernel.CryptoParameters,
    };

    pub const KernelParametersError = kernel.DeriveError || error{SecretsIncomplete};

    /// Compose the kernel install for a *server-role* connection from its
    /// captured secrets: we transmit under the server traffic secret and
    /// receive under the client's.
    pub fn kernel_parameters(
        channel: *const Channel,
        secrets: *const TrafficSecrets,
    ) KernelParametersError!KernelParameters {
        assert(channel.handshake_done()); // the suite is only known after
        if (!secrets.complete()) return error.SecretsIncomplete;
        const suite = channel.negotiated_cipher_suite();
        return .{
            .transmit = try kernel.derive_crypto_parameters(suite, secrets.server_secret()),
            .receive = try kernel.derive_crypto_parameters(suite, secrets.client_secret()),
        };
    }

    /// The ALPN protocol both sides agreed on, if any. Valid post-handshake.
    pub fn alpn_selected(channel: *const Channel) ?[]const u8 {
        assert(channel.handshake_done());
        var data: ?[*]const u8 = null;
        var length: c_uint = 0;
        openssl.SSL_get0_alpn_selected(channel.ssl, &data, &length);
        const pointer = data orelse return null;
        assert(length > 0);
        return pointer[0..length];
    }

    /// Decrypt buffered ciphertext into `buffer`.
    pub fn read_plaintext(channel: *Channel, buffer: []u8) ReadResult {
        assert(buffer.len > 0);
        assert(buffer.len <= std.math.maxInt(c_int));
        const result = openssl.SSL_read(channel.ssl, buffer.ptr, @intCast(buffer.len));
        if (result > 0) return .{ .bytes = @intCast(result) };
        return switch (openssl.SSL_get_error(channel.ssl, result)) {
            openssl.SSL_ERROR_WANT_READ, openssl.SSL_ERROR_WANT_WRITE => .want_io,
            openssl.SSL_ERROR_ZERO_RETURN => .closed,
            else => failed: {
                openssl.ERR_clear_error();
                break :failed .failed;
            },
        };
    }

    /// Encrypt `plaintext`; the records land in the pair for draining.
    pub fn write_plaintext(channel: *Channel, plaintext: []const u8) WriteResult {
        assert(plaintext.len > 0);
        assert(plaintext.len <= std.math.maxInt(c_int));
        const result = openssl.SSL_write(channel.ssl, plaintext.ptr, @intCast(plaintext.len));
        if (result > 0) return .{ .bytes = @intCast(result) };
        return switch (openssl.SSL_get_error(channel.ssl, result)) {
            openssl.SSL_ERROR_WANT_READ, openssl.SSL_ERROR_WANT_WRITE => .want_io,
            else => failed: {
                openssl.ERR_clear_error();
                break :failed .failed;
            },
        };
    }

    /// Queue a close_notify alert (best effort — drain and send afterwards).
    pub fn shutdown_notify(channel: *Channel) void {
        const result = openssl.SSL_shutdown(channel.ssl);
        assert(result >= -1); // -1/0/1 per the API contract
        if (result < 0) openssl.ERR_clear_error();
    }
};

// -- tests ----------------------------------------------------------------

const test_certificate_pem = @embedFile("testdata/certificate.pem");
const test_private_key_pem = @embedFile("testdata/private_key.pem");
const hook = @import("openssl.zig");

/// Shuttle ciphertext between two channels until both are quiet: the
/// deterministic in-memory "network". `chunk_bytes` throttles each move so
/// tests can be adversarial about partial I/O.
fn pump(client: *Channel, server: *Channel, chunk_bytes: usize) !void {
    var scratch: [constants.tls_bio_pair_bytes]u8 = undefined;
    assert(chunk_bytes > 0);
    const budget_max = 10_000; // bounded: a quiet network must converge
    var budget: u32 = budget_max;
    while (budget > 0) : (budget -= 1) {
        var moved: usize = 0;
        moved += move_one(client, server, scratch[0..chunk_bytes]);
        moved += move_one(server, client, scratch[0..chunk_bytes]);
        _ = client.handshake_step();
        _ = server.handshake_step();
        if (moved == 0 and client.pending_ciphertext() == 0) {
            if (server.pending_ciphertext() == 0) return;
        }
    }
    return error.PumpDidNotConverge;
}

fn move_one(from: *Channel, to: *Channel, scratch: []u8) usize {
    const drained = from.drain_ciphertext(scratch);
    if (drained == 0) return 0;
    var offset: usize = 0;
    var budget: u32 = 1000; // bounded: the pair always makes progress
    while (offset < drained and budget > 0) : (budget -= 1) {
        const fed = to.feed_ciphertext(scratch[offset..drained]);
        if (fed == 0) break; // peer pair full: progress happens next pump turn
        offset += fed;
    }
    assert(offset <= drained);
    return offset;
}

fn test_handshaken_pair(client: *Channel, server: *Channel, chunk_bytes: usize) !void {
    _ = client.handshake_step(); // client speaks first (ClientHello)
    try pump(client, server, chunk_bytes);
    try std.testing.expect(client.handshake_done());
    try std.testing.expect(server.handshake_done());
}

const install_test_hook = hook.install_memory_hook_for_tests;

test "terminator: server context builds from the fixture identity" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    try std.testing.expectEqual(Context.Role.server, server_context.role);

    try std.testing.expectError(
        error.InvalidCertificate,
        Context.init_server("not a pem", test_private_key_pem),
    );
}

test "terminator: full handshake, ALPN http/1.1, plaintext echo both ways" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    var server = try Channel.init(&server_context);
    defer server.deinit();
    var client = try Channel.init(&client_context);
    defer client.deinit();

    // Offer http/1.1 from the client (wire format: length-prefixed).
    const offer = "\x08http/1.1";
    try std.testing.expectEqual(
        @as(c_int, 0), // 0 is success for this one API
        openssl.SSL_set_alpn_protos(client.ssl, offer.ptr, offer.len),
    );

    try test_handshaken_pair(&client, &server, constants.tls_bio_pair_bytes);
    try std.testing.expectEqualStrings(alpn_http1, server.alpn_selected().?);
    try std.testing.expectEqualStrings(alpn_http1, client.alpn_selected().?);

    // client -> server
    const request = "GET / HTTP/1.1\r\nhost: zoxy.test\r\n\r\n";
    const sent = client.write_plaintext(request);
    try std.testing.expectEqual(Channel.WriteResult{ .bytes = request.len }, sent);
    try pump(&client, &server, constants.tls_bio_pair_bytes);
    var buffer: [256]u8 = undefined;
    const got = server.read_plaintext(&buffer);
    try std.testing.expectEqual(Channel.ReadResult{ .bytes = request.len }, got);
    try std.testing.expectEqualStrings(request, buffer[0..request.len]);

    // server -> client
    const response = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
    const replied = server.write_plaintext(response);
    try std.testing.expectEqual(Channel.WriteResult{ .bytes = response.len }, replied);
    try pump(&client, &server, constants.tls_bio_pair_bytes);
    const echoed = client.read_plaintext(&buffer);
    try std.testing.expectEqual(Channel.ReadResult{ .bytes = response.len }, echoed);
    try std.testing.expectEqualStrings(response, buffer[0..response.len]);
}

test "terminator: handshake survives 1-byte adversarial ciphertext delivery" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    var server = try Channel.init(&server_context);
    defer server.deinit();
    var client = try Channel.init(&client_context);
    defer client.deinit();

    try test_handshaken_pair(&client, &server, 1);
}

test "terminator: no ALPN overlap completes the handshake without ALPN" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    var server = try Channel.init(&server_context);
    defer server.deinit();
    var client = try Channel.init(&client_context);
    defer client.deinit();

    const offer = "\x02h2"; // we do not speak h2 yet -> NOACK, not fatal
    try std.testing.expectEqual(
        @as(c_int, 0),
        openssl.SSL_set_alpn_protos(client.ssl, offer.ptr, offer.len),
    );
    try test_handshaken_pair(&client, &server, constants.tls_bio_pair_bytes);
    try std.testing.expectEqual(@as(?[]const u8, null), server.alpn_selected());
}

test "terminator: close_notify reads as clean TLS EOF" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    var server = try Channel.init(&server_context);
    defer server.deinit();
    var client = try Channel.init(&client_context);
    defer client.deinit();
    try test_handshaken_pair(&client, &server, constants.tls_bio_pair_bytes);

    client.shutdown_notify();
    try pump(&client, &server, constants.tls_bio_pair_bytes);
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqual(Channel.ReadResult.closed, server.read_plaintext(&buffer));
}

test "terminator: keylog capture yields identical kernel parameters on both ends" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    var server = try Channel.init(&server_context);
    defer server.deinit();
    var client = try Channel.init(&client_context);
    defer client.deinit();
    var server_secrets = TrafficSecrets{};
    var client_secrets = TrafficSecrets{};
    server.capture_secrets(&server_secrets);
    client.capture_secrets(&client_secrets);

    try test_handshaken_pair(&client, &server, constants.tls_bio_pair_bytes);
    try std.testing.expect(server_secrets.complete());
    try std.testing.expect(client_secrets.complete());

    const suite = server.negotiated_cipher_suite();
    try std.testing.expectEqual(suite, client.negotiated_cipher_suite());
    try std.testing.expect(suite == kernel.cipher_suite_aes_128_gcm_sha256 or
        suite == kernel.cipher_suite_aes_256_gcm_sha384);

    // Both ends captured independently through their own callbacks; the
    // derived kernel parameters must agree per direction — the server's TX
    // (server secret) is the client's RX, and vice versa.
    const server_tx = try kernel.derive_crypto_parameters(suite, server_secrets.server_secret());
    const client_rx = try kernel.derive_crypto_parameters(suite, client_secrets.server_secret());
    try std.testing.expectEqualSlices(u8, server_tx.bytes(), client_rx.bytes());

    const server_rx = try kernel.derive_crypto_parameters(suite, server_secrets.client_secret());
    const client_tx = try kernel.derive_crypto_parameters(suite, client_secrets.client_secret());
    try std.testing.expectEqualSlices(u8, server_rx.bytes(), client_tx.bytes());

    // The two directions must never share keys.
    try std.testing.expect(!std.mem.eql(u8, server_tx.bytes(), server_rx.bytes()));
}

test "terminator: a clean handshake is kernel-switch eligible; composition works" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    var server = try Channel.init(&server_context);
    defer server.deinit();
    var client = try Channel.init(&client_context);
    defer client.deinit();
    var secrets = TrafficSecrets{};
    server.capture_secrets(&secrets);

    try std.testing.expect(!server.kernel_switch_eligible()); // not before the handshake
    try std.testing.expectError(error.SecretsIncomplete, blk: {
        // Composition needs the handshake first; feed it a done channel below.
        try test_handshaken_pair(&client, &server, constants.tls_bio_pair_bytes);
        break :blk server.kernel_parameters(&TrafficSecrets{});
    });

    // The client sent nothing beyond its handshake flight: eligible.
    try std.testing.expect(server.kernel_switch_eligible());

    const parameters = try server.kernel_parameters(&secrets);
    const suite = server.negotiated_cipher_suite();
    const expected_tx = try kernel.derive_crypto_parameters(suite, secrets.server_secret());
    try std.testing.expectEqualSlices(u8, expected_tx.bytes(), parameters.transmit.bytes());
    const expected_rx = try kernel.derive_crypto_parameters(suite, secrets.client_secret());
    try std.testing.expectEqualSlices(u8, expected_rx.bytes(), parameters.receive.bytes());
}

test "terminator: a request riding the handshake flight defeats eligibility" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    var server = try Channel.init(&server_context);
    defer server.deinit();
    var client = try Channel.init(&client_context);
    defer client.deinit();

    // Drive the handshake until the *client* believes it is done (the
    // client finishes first in TLS 1.3) while the server still waits for
    // the client Finished flight.
    var scratch: [constants.tls_bio_pair_bytes]u8 = undefined;
    _ = client.handshake_step(); // ClientHello out
    var budget: u32 = 100;
    while (!client.handshake_done() and budget > 0) : (budget -= 1) {
        const to_server = client.drain_ciphertext(&scratch);
        if (to_server > 0) assert(server.feed_ciphertext(scratch[0..to_server]) == to_server);
        _ = server.handshake_step();
        const to_client = server.drain_ciphertext(&scratch);
        if (to_client > 0) assert(client.feed_ciphertext(scratch[0..to_client]) == to_client);
        _ = client.handshake_step();
    }
    try std.testing.expect(client.handshake_done());
    try std.testing.expect(!server.handshake_done()); // Finished not yet delivered

    // The client pipelines a request into the same flight as its Finished:
    // the server receives both in one batch.
    const early = "GET / HTTP/1.1\r\nhost: eager\r\n\r\n";
    switch (client.write_plaintext(early)) {
        .bytes => |n| try std.testing.expectEqual(early.len, n),
        else => return error.TestUnexpectedResult,
    }
    const flight = client.drain_ciphertext(&scratch);
    try std.testing.expect(flight > 0);
    try std.testing.expectEqual(flight, server.feed_ciphertext(scratch[0..flight]));
    try std.testing.expectEqual(Channel.HandshakeStatus.done, server.handshake_step());

    // Handshake done — but the early request sits in the pair or the SSL:
    // installing kTLS RX now would desynchronize the sequence. Ineligible,
    // so this connection stays on the userspace relay (which must still
    // deliver that request intact).
    try std.testing.expect(!server.kernel_switch_eligible());
    var buffer: [128]u8 = undefined;
    switch (server.read_plaintext(&buffer)) {
        .bytes => |n| try std.testing.expectEqualStrings(early, buffer[0..n]),
        else => return error.TestUnexpectedResult,
    }
}

test "terminator: channels drain the hook heap to baseline" {
    install_test_hook();
    const server_context = try Context.init_server(test_certificate_pem, test_private_key_pem);
    defer server_context.deinit();
    const client_context = try Context.init_client();
    defer client_context.deinit();

    // Warm-up handshake so OpenSSL's lazy one-time allocations are done.
    {
        var server = try Channel.init(&server_context);
        defer server.deinit();
        var client = try Channel.init(&client_context);
        defer client.deinit();
        try test_handshaken_pair(&client, &server, constants.tls_bio_pair_bytes);
    }

    const before = hook.memory_hook_stats();
    {
        var server = try Channel.init(&server_context);
        defer server.deinit();
        var client = try Channel.init(&client_context);
        defer client.deinit();
        try test_handshaken_pair(&client, &server, constants.tls_bio_pair_bytes);
        try std.testing.expect(hook.memory_hook_stats().live_count > before.live_count);
    }
    const after = hook.memory_hook_stats();
    try std.testing.expectEqual(before.live_count, after.live_count);
    try std.testing.expectEqual(@as(u64, 0), after.rejection_count);
}
