const std = @import("std");

const nethernet = @import("nethernet");

pub const std_options: std.Options = nethernet.log.options;

const ServerOptions = struct {
    answer_ping: bool = true,
    cpk_encoding: nethernet.identity.CpkEncoding = .jwk,
    key_path: []const u8 = "server.key",
    domain: []const u8 = "self",
    lifetime: i64 = 3600,
    jwks_uri: ?[]const u8 = null,
    jwks_document: ?[]const u8 = null,
    insecure: bool = false,
    public_address: ?[]const u8 = null,
    public_port: u16 = 0,
    public_base_address: ?[]const u8 = null,
    public_base_port: ?u16 = null,
    stun: ?[]const u8 = null,
};

fn serverUsageAndExit() noreturn {
    std.debug.print(
        "usage: example-cli server [--key=<path>] [--jwks=<url> | --jwks-document=<path> | --insecure]\n" ++
            "                          [--domain=<name>] [--lifetime=<seconds>] [--no-ping] [cpk=jwk|base64_der]\n" ++
            "                          [--public-address=<ip> --public-port=<port>] [--public-base=<ip:port>] [--stun=<url>]\n" ++
            "One of --jwks, --jwks-document or --insecure is required.\n",
        .{},
    );
    std.process.exit(2);
}

fn runServer(init: std.process.Init, options: ServerOptions) !void {
    var nonce_bytes: [8]u8 = undefined;
    var nonce_hex: [16]u8 = undefined;
    init.io.random(&nonce_bytes);
    const nonce = nethernet.discovery_protocol.encodeHexLower(&nonce_hex, &nonce_bytes);

    const advertisement: nethernet.discovery_protocol.ServerData = .{
        .server_name = "NetherNet Zig test server",
        .level_name = "nethernet-zig-test",
        .game_type = .creative,
        .max_player_count = 1,
        .nonce = nonce,
    };

    const identity = try nethernet.identity.ServerProvider.loadOrCreateWith(init.io, init.gpa, options.key_path, .{
        .domain = options.domain,
        .lifetime_seconds = options.lifetime,
        .cpk_encoding = options.cpk_encoding,
    });

    var verifier: ?nethernet.identity.Verifier = null;
    if (options.jwks_uri) |uri| {
        verifier = try nethernet.identity.Verifier.init(init.io, init.gpa, .{ .jwks_uri = uri });
    } else if (options.jwks_document) |document| {
        verifier = try nethernet.identity.Verifier.init(init.io, init.gpa, .{ .jwks_document = document });
    }
    defer if (verifier) |*value| value.deinit();

    const public_candidate: ?nethernet.sdp_edit.PublicCandidate = if (options.public_address) |address| .{
        .address = address,
        .port = options.public_port,
        .base_address = options.public_base_address,
        .base_port = options.public_base_port,
    } else null;
    var stun_server: [1]nethernet.web_rtc.IceServer = undefined;
    const ice_servers: []const nethernet.web_rtc.IceServer = if (options.stun) |url| blk: {
        stun_server[0] = .{ .url = url };
        break :blk stun_server[0..1];
    } else &.{};

    const host = nethernet.server.Host.init(init.io, init.gpa, .{
        .server_data = advertisement,
        .paths = .{ .motd = options.answer_ping },
        .cpk_encoding = options.cpk_encoding,
        .identity = identity,
        .identity_verifier = if (verifier) |*value| value else null,
        .require_client_identity = true,
        .accept_unverified_identity = options.insecure,
        .ice_servers = ice_servers,
        .public_candidate = public_candidate,
    }) catch |err| {
        std.debug.print("could not start the server: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer host.deinit();
    try host.start();

    var stdout_buffer: [1024]u8 = undefined;
    var stdout = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    defer stdout.interface.flush() catch {};
    const discovery_status = if (host.isLanBound())
        "LAN discovery and trickle ICE signaling are enabled on 0.0.0.0:7551."
    else
        "LAN discovery is waiting for UDP 7551 (retrying in the background); HTTP signaling is up on 19132.";
    const ping_status = if (!options.answer_ping)
        "External server ping is disabled by request; only NetherNet discovery can announce this server."
    else if (host.isMotdBound())
        "External server ping is answering on UDP 19132 with the server MOTD."
    else
        "External server ping is waiting for UDP 19132 (retrying in the background).";
    const fingerprint = std.fmt.bytesToHex(host.keyFingerprint(), .lower);
    try stdout.interface.print(
        "NetherNet Zig server listening on 0.0.0.0:19132\n{s}\n{s}\n" ++
            "Server identity: the JWT `cpk` claim is a {s}; `cpk=jwk|base64_der` switches it.\n" ++
            "Key: {s} (persisted, 0600). Pin the sha-256 below out of band when signaling is not HTTPS.\n" ++
            "Identity mode: {s}\n" ++
            "Key fingerprint (sha-256 of the operator key): {s}\n" ++
            "Reachability: {s}\n" ++
            "Logs carry one line per connection and per session event; a Debug build adds every request, candidate and packet.\n",
        .{
            discovery_status,
            ping_status,
            @tagName(options.cpk_encoding),
            options.key_path,
            if (options.insecure) "INSECURE (claims are not anchored)" else "anchored to the configured JWKS",
            fingerprint[0..],
            if (options.public_address) |_|
                "a srflx candidate is announced from --public-address"
            else if (options.stun != null)
                "ICE gathering uses the --stun server"
            else
                "host candidates only, reachable on a routable address (see --public-address)",
        },
    );
    try stdout.interface.flush();

    while (true) {
        std.Io.sleep(init.io, .fromMilliseconds(1000), .awake) catch return;
    }
}

const ConnectOptions = struct {
    url: []const u8,
    pins_path: []const u8 = "pins.json",
    network_id: []const u8 = "1",
    assume_yes: bool = false,
};

const Prompt = struct {
    io: std.Io,
    assume_yes: bool,

    fn decide(ctx: *anyopaque, domain: []const u8, digest: [std.crypto.hash.sha2.Sha256.digest_length]u8) nethernet.identity.UnknownKey {
        const self: *Prompt = @ptrCast(@alignCast(ctx));
        const hex = std.fmt.bytesToHex(digest, .lower);
        std.debug.print("unknown operator key\n  idp.domain: {s}\n  sha-256   : {s}\n", .{ domain, hex[0..] });
        if (self.assume_yes) {
            std.debug.print("--yes given: pinning without confirmation\n", .{});
            return .pin_and_accept;
        }
        const tty = std.Io.File.stdin().isTty(self.io) catch false;
        if (!tty) {
            std.debug.print("no terminal to confirm on, so the key is refused: pre-load the pin or pass --yes.\n", .{});
            return .reject;
        }
        std.debug.print("pin it and continue? [y/N] ", .{});
        var buffer: [64]u8 = undefined;
        var reader = std.Io.File.stdin().reader(self.io, &buffer);
        const answer = reader.interface.takeDelimiterExclusive('\n') catch return .reject;
        const trimmed = std.mem.trim(u8, answer, " \r\t");
        return if (std.ascii.eqlIgnoreCase(trimmed, "y") or std.ascii.eqlIgnoreCase(trimmed, "yes"))
            .pin_and_accept
        else
            .reject;
    }
};

fn runConnect(init: std.process.Init, options: ConnectOptions) !void {
    var stdout_buffer: [8192]u8 = undefined;
    var stdout = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    defer stdout.interface.flush() catch {};

    var store = try nethernet.identity.PinStore.init(init.io, init.gpa, .{ .path = options.pins_path });
    defer store.deinit();
    store.load() catch |err| {
        try stdout.interface.print("could not read {s}: {s}\n", .{ options.pins_path, @errorName(err) });
        try stdout.interface.flush();
        std.process.exit(1);
    };

    var transport = try nethernet.signaling.ClientTransport.init(init.io, init.gpa, options.url);
    defer transport.deinit();

    var prompt = Prompt{ .io = init.io, .assume_yes = options.assume_yes };
    var joiner = nethernet.signaling.Joiner.init(init.io, init.gpa, transport.transport(), "", .{
        .trust = .{ .tofu = .{ .store = &store, .on_unknown = Prompt.decide, .ctx = &prompt } },
    });

    var info = joiner.capability() catch |err| {
        try stdout.interface.print("server is not answering: {s}\n", .{@errorName(err)});
        try stdout.interface.flush();
        std.process.exit(1);
    };
    defer joiner.deinitInfo(init.gpa, &info);
    try stdout.interface.print(
        "server: {s} ({s}), players {d}/{d}\n",
        .{ info.name, info.version, info.players, info.maxPlayers },
    );

    const native = try nethernet.web_rtc.NativePeerConnection.init(init.io, init.gpa, .{ .profile = .http_full_ice });
    defer native.deinit();
    var peer = try nethernet.web_rtc.Peer.init(init.gpa, native.connectionSpi(), .{ .profile = .http_full_ice });
    defer peer.deinit(init.gpa);

    var provider = nethernet.identity.ServerProvider.init(init.io, .{});
    const offer = peer.startOffer() catch |err| {
        try stdout.interface.print("could not build an offer: {s}\n", .{@errorName(err)});
        try stdout.interface.flush();
        std.process.exit(1);
    };
    const signed_offer = try provider.addToSdp(init.gpa, offer.sdp);
    defer init.gpa.free(signed_offer);

    var submission = joiner.submitOffer(options.network_id, signed_offer) catch |err| {
        try stdout.interface.print("join refused: {s}\n", .{@errorName(err)});
        try stdout.interface.flush();
        std.process.exit(1);
    };
    defer submission.deinit(init.gpa);

    const pin_hex = std.fmt.bytesToHex(submission.identity.key_sha256, .lower);
    try stdout.interface.print(
        "answer verified: idp.domain={s}, anchored={s}\n  pinned sha-256={s}\n  pins file  : {s} ({d} pins)\n",
        .{
            submission.idp_domain,
            if (submission.anchored) "yes" else "no",
            pin_hex[0..],
            options.pins_path,
            store.count(),
        },
    );

    peer.acceptAnswer(.{ .kind = .answer, .sdp = submission.sdp }) catch |err| {
        try stdout.interface.print("the answer was refused by the backend: {s}\n", .{@errorName(err)});
        try stdout.interface.flush();
        std.process.exit(1);
    };

    const deadline = std.Io.Clock.Timestamp.fromNow(init.io, .{ .clock = .awake, .raw = .fromSeconds(10) });
    while (std.Io.Clock.Timestamp.now(init.io, .awake).compare(.lt, deadline)) {
        peer.tick() catch |err| {
            try stdout.interface.print("session failed: {s}\n", .{@errorName(err)});
            try stdout.interface.flush();
            std.process.exit(1);
        };
        while (peer.pollEvent()) |event| switch (event) {
            .state_changed => |state| try stdout.interface.print("state: {s}\n", .{@tagName(state)}),
            .failed => |err| {
                try stdout.interface.print("peer failed: {s}\n", .{@errorName(err)});
                try stdout.interface.flush();
                std.process.exit(1);
            },
            else => {},
        };
        if (peer.stateOf() == .connected) {
            try stdout.interface.print("connected: both data channels are up\n", .{});
            try stdout.interface.flush();
            std.process.exit(0);
        }
        std.Io.sleep(init.io, .fromMilliseconds(10), .awake) catch return;
    }
    try stdout.interface.print("no session within 10 s (state {s})\n", .{@tagName(peer.stateOf())});
    try stdout.interface.flush();
    std.process.exit(1);
}

fn writeServerDataShape(writer: *std.Io.Writer, data: []const u8) !void {
    const server_data = nethernet.discovery_protocol.ServerData.decode(data) catch |err| {
        try writer.print("  shape      : undecodable ({s})\n", .{@errorName(err)});
        return;
    };
    try writer.print(
        "  shape      : version={d} name=\"{s}\" protocol={d} gameVersion=\"{s}\" level=\"{s}\" " ++
            "players={d}/{d} gameType={d} editorWorld={d} hardcore={d} onlineAuth={d} " ++
            "selfSignedAuth={d} nonce={s} connectionType={d}\n",
        .{
            nethernet.discovery_protocol.ServerData.version,
            server_data.server_name,
            server_data.protocol,
            server_data.game_version,
            server_data.level_name,
            server_data.player_count,
            server_data.max_player_count,
            @intFromEnum(server_data.game_type),
            @intFromBool(server_data.editor_world),
            @intFromBool(server_data.hardcore),
            @intFromBool(server_data.accepts_online_auth),
            @intFromBool(server_data.accepts_self_signed_auth),
            server_data.nonce,
            server_data.connection_type,
        },
    );
}

fn parseIpv4(text: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var index: usize = 0;
    var parts = std.mem.splitScalar(u8, text, '.');
    while (parts.next()) |part| {
        if (index >= octets.len) return null;
        octets[index] = std.fmt.parseInt(u8, part, 10) catch return null;
        index += 1;
    }
    if (index != octets.len) return null;
    return std.mem.readInt(u32, &octets, .big);
}

fn runDiscover(init: std.process.Init, target: []const u8, port: u16) !void {
    var stdout_buffer: [16384]u8 = undefined;
    var stdout = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    defer stdout.interface.flush() catch {};

    const value = parseIpv4(target) orelse {
        try stdout.interface.print("Invalid IPv4 address: {s}\n", .{target});
        try stdout.interface.flush();
        std.process.exit(2);
    };
    var report = nethernet.probe.discover(init.io, init.gpa, std.mem.nativeToBig(u32, value), port, 3_000) catch |err| {
        try stdout.interface.print("LAN discovery probe failed: {s}\n", .{@errorName(err)});
        try stdout.interface.flush();
        std.process.exit(1);
    };
    defer report.deinit(init.gpa);
    if (report.response_bytes == 0) {
        try stdout.interface.print("No LAN discovery response from {s}:{d} within 3000 ms.\n", .{ target, port });
        try stdout.interface.flush();
        std.process.exit(1);
    }

    try stdout.interface.print(
        "LAN discovery response from {s}:{d}\n  senderId   : {d}\n  ServerData : {d} bytes\n  hex        : ",
        .{ target, port, report.sender_id, report.response_bytes },
    );
    for (report.server_data) |byte| try stdout.interface.print("{x:0>2}", .{byte});
    try stdout.interface.print("\n", .{});
    var preview: [256]u8 = undefined;
    const length = @min(report.server_data.len, preview.len);
    for (report.server_data[0..length], preview[0..length]) |byte, *out| {
        out.* = if (byte >= 0x20 and byte < 0x7f) byte else '.';
    }
    try stdout.interface.print("  ascii      : \"{s}\" ({d} bytes shown)\n", .{ preview[0..length], length });
    try writeServerDataShape(&stdout.interface, report.server_data);
    try stdout.interface.flush();
    std.process.exit(0);
}

fn writeMotdShape(writer: *std.Io.Writer, motd: []const u8) !void {
    var fields = [_][]const u8{""} ** 13;
    var iterator = std.mem.splitScalar(u8, motd, ';');
    var index: usize = 0;
    while (iterator.next()) |field| {
        if (index == fields.len) break;
        fields[index] = field;
        index += 1;
    }
    try writer.print(
        "  shape      : edition=\"{s}\" name=\"{s}\" protocol={s} version=\"{s}\" players={s}/{s} " ++
            "guid={s} level=\"{s}\" mode=\"{s}\" modeId={s} portIPv4={s} portIPv6={s}\n",
        .{ fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8], fields[9], fields[10], fields[11] },
    );
}

fn runPing(init: std.process.Init, target: []const u8, port: u16) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    defer stdout.interface.flush() catch {};

    const value = parseIpv4(target) orelse {
        try stdout.interface.print("Invalid IPv4 address: {s}\n", .{target});
        try stdout.interface.flush();
        std.process.exit(2);
    };
    var buffer: [2048]u8 = undefined;
    const pong = nethernet.server.queryPing(init.io, std.mem.nativeToBig(u32, value), port, 3_000, &buffer) orelse {
        try stdout.interface.print("No RakNet pong from {s}:{d} within 3000 ms.\n", .{ target, port });
        try stdout.interface.flush();
        std.process.exit(1);
    };
    try stdout.interface.print(
        "RakNet pong from {s}:{d}\n  bytes      : {d}\n  time echo  : {d}\n  motd       : \"{s}\"\n",
        .{ target, port, pong.bytes, pong.time, pong.motd },
    );
    try writeMotdShape(&stdout.interface, pong.motd);
    try stdout.interface.flush();
    std.process.exit(0);
}

fn identityStatus(report: nethernet.probe.Report) []const u8 {
    if (!report.answer_verified) return "not verified";
    return if (report.pinned) "verified, pinned" else "verified, accepted once";
}

fn runProbe(init: std.process.Init, options: nethernet.probe.Options) !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    const report = nethernet.probe.run(init.io, init.gpa, options) catch |err| {
        try stdout.interface.print("LAN probe could not run: {s}\n", .{@errorName(err)});
        try stdout.interface.flush();
        std.process.exit(1);
    };
    try stdout.interface.print(
        "LAN probe report\n" ++
            "  discovery        : {s} ({d} bytes)\n" ++
            "  offer sent       : {s}\n" ++
            "  CONNECTRESPONSE  : {s} ({d} bytes, identity={s}, candidates={s})\n" ++
            "  candidates (in/out): {d}/{d}\n" ++
            "  ICE/DTLS session : {s}\n" ++
            "  application echo : {s} ({d} bytes)\n",
        .{
            if (report.discovery_ok) "ok" else "missing",
            report.response_bytes,
            if (options.sign_offer) "signed (a=identity)" else "unsigned, as the LAN path sends it",
            if (report.connect_response_ok) "ok" else "missing",
            report.answer_bytes,
            identityStatus(report),
            if (report.answer_has_candidates) "embedded" else "stripped",
            report.remote_candidates,
            report.local_candidates,
            if (report.connected) "connected" else "not established",
            if (report.echo_ok) "ok" else "missing",
            report.echo_bytes,
        },
    );
    if (report.failure) |reason| try stdout.interface.print("  failure          : {s}\n", .{reason});
    const passed = report.passed();
    try stdout.interface.print("LAN probe: {s}\n", .{if (passed) "PASS" else if (report.signalingPassed()) "PARTIAL (signaling only)" else "FAIL"});
    try stdout.interface.flush();
    std.process.exit(if (passed) 0 else 1);
}

pub fn main(init: std.process.Init) !void {
    // `Args.Iterator.init` is a compile error on Windows.
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    if (args.next()) |mode| {
        if (std.mem.eql(u8, mode, "server")) {
            var options: ServerOptions = .{};
            while (args.next()) |flag| {
                if (std.mem.eql(u8, flag, "no-ping") or std.mem.eql(u8, flag, "--no-ping")) {
                    options.answer_ping = false;
                } else if (std.mem.eql(u8, flag, "cpk=base64_der")) {
                    options.cpk_encoding = .base64_der;
                } else if (std.mem.eql(u8, flag, "cpk=jwk")) {
                    options.cpk_encoding = .jwk;
                } else if (std.mem.startsWith(u8, flag, "key=")) {
                    options.key_path = flag["key=".len..];
                } else if (std.mem.startsWith(u8, flag, "--key=")) {
                    options.key_path = flag["--key=".len..];
                } else if (std.mem.startsWith(u8, flag, "--jwks=")) {
                    options.jwks_uri = flag["--jwks=".len..];
                } else if (std.mem.startsWith(u8, flag, "--jwks-document=")) {
                    options.jwks_document = flag["--jwks-document=".len..];
                } else if (std.mem.startsWith(u8, flag, "--domain=")) {
                    options.domain = flag["--domain=".len..];
                } else if (std.mem.startsWith(u8, flag, "--lifetime=")) {
                    options.lifetime = std.fmt.parseInt(i64, flag["--lifetime=".len..], 10) catch serverUsageAndExit();
                } else if (std.mem.startsWith(u8, flag, "--public-address=")) {
                    options.public_address = flag["--public-address=".len..];
                } else if (std.mem.startsWith(u8, flag, "--public-port=")) {
                    options.public_port = std.fmt.parseInt(u16, flag["--public-port=".len..], 10) catch serverUsageAndExit();
                } else if (std.mem.startsWith(u8, flag, "--public-base=")) {
                    const pair = flag["--public-base=".len..];
                    const colon = std.mem.lastIndexOfScalar(u8, pair, ':') orelse serverUsageAndExit();
                    options.public_base_address = pair[0..colon];
                    options.public_base_port = std.fmt.parseInt(u16, pair[colon + 1 ..], 10) catch serverUsageAndExit();
                } else if (std.mem.startsWith(u8, flag, "--stun=")) {
                    options.stun = flag["--stun=".len..];
                } else if (std.mem.eql(u8, flag, "--insecure")) {
                    options.insecure = true;
                } else {
                    serverUsageAndExit();
                }
            }
            if (options.jwks_uri != null and options.jwks_document != null) serverUsageAndExit();
            if ((options.public_address == null) != (options.public_port == 0)) serverUsageAndExit();
            if (options.jwks_uri == null and options.jwks_document == null and !options.insecure) {
                serverUsageAndExit();
            }
            return runServer(init, options);
        }
        if (std.mem.eql(u8, mode, "connect")) {
            const url = args.next() orelse {
                std.debug.print("usage: example-cli connect <url> [--pins=<path>] [--network=<id>] [--yes]\n", .{});
                std.process.exit(2);
            };
            var options: ConnectOptions = .{ .url = url };
            while (args.next()) |flag| {
                if (std.mem.startsWith(u8, flag, "--pins=")) {
                    options.pins_path = flag["--pins=".len..];
                } else if (std.mem.startsWith(u8, flag, "--network=")) {
                    options.network_id = flag["--network=".len..];
                } else if (std.mem.eql(u8, flag, "--yes")) {
                    options.assume_yes = true;
                } else {
                    std.debug.print("unknown connect flag: {s}\n", .{flag});
                    std.process.exit(2);
                }
            }
            return runConnect(init, options);
        }
        if (std.mem.eql(u8, mode, "discover")) {
            const target = if (args.next()) |value| value else "127.0.0.1";
            const port: u16 = if (args.next()) |value| std.fmt.parseInt(u16, value, 10) catch 7551 else 7551;
            return runDiscover(init, target, port);
        }
        if (std.mem.eql(u8, mode, "ping")) {
            const target = if (args.next()) |value| value else "127.0.0.1";
            const port: u16 = if (args.next()) |value| std.fmt.parseInt(u16, value, 10) catch 19132 else 19132;
            return runPing(init, target, port);
        }
        if (std.mem.eql(u8, mode, "probe")) {
            var options: nethernet.probe.Options = .{};
            while (args.next()) |flag| {
                if (std.mem.eql(u8, flag, "external")) {
                    options.start_server = false;
                } else if (std.mem.eql(u8, flag, "unsigned")) {
                    options.sign_offer = false;
                }
            }
            return runProbe(init, options);
        }
    }

    const session = try nethernet.sessionCreate(init.io, init.gpa, .{
        .network_id = "example",
    });
    defer nethernet.sessionDestroy(session);

    try nethernet.sessionSend(session, .reliable, "loopback-packet");
    const packet = (try nethernet.sessionPoll(session)).?;
    defer nethernet.sessionReleasePacket(session, packet);

    var stdout_buffer: [1024]u8 = undefined;
    var stdout = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    defer stdout.interface.flush() catch {};
    try stdout.interface.print(
        "NetherNet example ready: received {d} bytes on the reliable channel.\n",
        .{packet.data.len},
    );
}

test "the MOTD splitter names every field the client renders" {
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeMotdShape(&writer, "MCPE;My Server;2193;1.26.51;2;10;123;level;Creative;1;19132;19133;");
    const output = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "name=\"My Server\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "protocol=2193") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "players=2/10") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mode=\"Creative\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "portIPv6=19133") != null);
}

test "example composes the public session API" {
    const session = try nethernet.sessionCreate(std.testing.io, std.testing.allocator, .{
        .network_id = "example-test",
    });
    defer nethernet.sessionDestroy(session);

    try nethernet.sessionSend(session, .unreliable, "test");
    const packet = (try nethernet.sessionPoll(session)).?;
    defer nethernet.sessionReleasePacket(session, packet);
    try std.testing.expectEqual(nethernet.Reliability.unreliable, packet.reliability);
}
