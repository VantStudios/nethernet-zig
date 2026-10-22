const std = @import("std");
const nethernet = @import("nethernet");

pub const std_options: std.Options = nethernet.log.options;

const default_sessions: usize = 2000;
const default_shards: usize = 4;
const max_shards: usize = 16;

const advertisement: nethernet.discovery_protocol.ServerData = .{
    .server_name = "nethernet-zig example",
    .level_name = "example",
    .game_type = .creative,
    .max_player_count = 10,
};

const App = struct {
    reply: [512]u8 = undefined,

    fn onOpen(ctx: *anyopaque, session: *nethernet.web_rtc.PeerHandle) void {
        _ = ctx;
        std.debug.print("on_open: player {d} joined\n", .{session.id});
    }

    fn onMessage(ctx: *anyopaque, session: *nethernet.web_rtc.PeerHandle, kind: nethernet.web_rtc.ChannelKind, message: []const u8) ?[]const u8 {
        const self: *App = @ptrCast(@alignCast(ctx));
        const head = message[0..@min(message.len, 32)];
        std.debug.print(
            "on_message: player {d} {s} game packet {d} bytes, head {x}\n",
            .{ session.id, @tagName(kind), message.len, head },
        );
        return std.fmt.bufPrint(&self.reply, "echo:{s}", .{message}) catch null;
    }

    fn onClose(ctx: *anyopaque, session: *nethernet.web_rtc.PeerHandle) void {
        _ = ctx;
        std.debug.print("player {d} left\n", .{session.id});
    }
};

const Options = struct {
    sessions: usize = default_sessions,
    shards: usize = default_shards,
    key_path: []const u8 = "server.key",
    domain: []const u8 = "self",
    lifetime: i64 = 3600,
    jwks_uri: ?[]const u8 = null,
    jwks_document: ?[]const u8 = null,
    insecure: bool = false,
    answer_ping: bool = true,
    public_address: ?[]const u8 = null,
    public_port: u16 = 0,
    public_base_address: ?[]const u8 = null,
    public_base_port: ?u16 = null,
    stun: ?[]const u8 = null,
};

fn parseCount(text: ?[]const u8, fallback: usize, maximum: usize) usize {
    const value = std.fmt.parseInt(usize, text orelse return fallback, 10) catch return fallback;
    if (value == 0 or value > maximum) return fallback;
    return value;
}

fn usageAndExit() noreturn {
    std.debug.print(
        "usage: example-server [options]\n" ++
            "  --key=<path>            operator key, created 0600 on first run (default server.key)\n" ++
            "  --jwks=<url>            auth service JWKS used to verify client claims\n" ++
            "  --jwks-document=<path>  local JWKS document, for an offline deployment or a test\n" ++
            "  --insecure              LAB ONLY: admit claims nothing anchors\n" ++
            "  --domain=<name>         idp.domain of the answer (default self)\n" ++
            "  --lifetime=<seconds>    lifetime of the answer JWT, 60..604800 (default 3600)\n" ++
            "  --sessions=<n> --shards=<n>   session table and tick shards\n" ++
            "  --public-address=<ip>   reachable address announced as a srflx candidate\n" ++
            "  --public-port=<port>    port of that address (required with the address)\n" ++
            "  --public-base=<ip:port> local address the NAT maps, when it is not the first host candidate\n" ++
            "  --stun=<url>            STUN/TURN server the backend gathers from (stun:host:port)\n" ++
            "  --no-ping               do not answer the external server list\n" ++
            "One of --jwks, --jwks-document or --insecure is required: a deployment that cannot\n" ++
            "anchor a claim must not admit it.\n",
        .{},
    );
    std.process.exit(2);
}

fn parseOptions(args: *std.process.Args.Iterator) Options {
    var options: Options = .{};
    while (args.next()) |flag| {
        if (std.mem.startsWith(u8, flag, "--key=")) {
            options.key_path = flag["--key=".len..];
        } else if (std.mem.startsWith(u8, flag, "--jwks=")) {
            options.jwks_uri = flag["--jwks=".len..];
        } else if (std.mem.startsWith(u8, flag, "--jwks-document=")) {
            options.jwks_document = flag["--jwks-document=".len..];
        } else if (std.mem.startsWith(u8, flag, "--domain=")) {
            options.domain = flag["--domain=".len..];
        } else if (std.mem.startsWith(u8, flag, "--lifetime=")) {
            options.lifetime = std.fmt.parseInt(i64, flag["--lifetime=".len..], 10) catch usageAndExit();
        } else if (std.mem.startsWith(u8, flag, "--public-address=")) {
            options.public_address = flag["--public-address=".len..];
        } else if (std.mem.startsWith(u8, flag, "--public-port=")) {
            options.public_port = std.fmt.parseInt(u16, flag["--public-port=".len..], 10) catch usageAndExit();
        } else if (std.mem.startsWith(u8, flag, "--public-base=")) {
            const pair = flag["--public-base=".len..];
            const colon = std.mem.lastIndexOfScalar(u8, pair, ':') orelse usageAndExit();
            options.public_base_address = pair[0..colon];
            options.public_base_port = std.fmt.parseInt(u16, pair[colon + 1 ..], 10) catch usageAndExit();
        } else if (std.mem.startsWith(u8, flag, "--sessions=")) {
            options.sessions = parseCount(flag["--sessions=".len..], default_sessions, 100_000);
        } else if (std.mem.startsWith(u8, flag, "--shards=")) {
            options.shards = parseCount(flag["--shards=".len..], default_shards, max_shards);
        } else if (std.mem.eql(u8, flag, "--insecure")) {
            options.insecure = true;
        } else if (std.mem.eql(u8, flag, "--no-ping")) {
            options.answer_ping = false;
        } else {
            usageAndExit();
        }
    }
    if (options.jwks_uri != null and options.jwks_document != null) usageAndExit();
    if ((options.public_address == null) != (options.public_port == 0)) usageAndExit();
    if (options.jwks_uri == null and options.jwks_document == null and !options.insecure) usageAndExit();
    return options;
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const options = parseOptions(&args);

    var app: App = .{};
    const handler: nethernet.web_rtc.MessageHandler = .{
        .ctx = &app,
        .on_open = App.onOpen,
        .on_message = App.onMessage,
        .on_close = App.onClose,
    };

    const identity = try nethernet.identity.ServerProvider.loadOrCreateWith(init.io, init.gpa, options.key_path, .{
        .domain = options.domain,
        .lifetime_seconds = options.lifetime,
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
        .handler = handler,
        .identity = identity,
        .identity_verifier = if (verifier) |*value| value else null,
        .require_client_identity = true,
        .accept_unverified_identity = options.insecure,
        .ice_servers = ice_servers,
        .public_candidate = public_candidate,
        .http_config = .{ .max_sessions = options.sessions, .tick_shards = options.shards },
        .lan_config = .{ .max_pending_connections = options.sessions },
    }) catch |err| {
        std.debug.print("could not start the server: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer host.deinit();

    try host.start();

    const fingerprint = std.fmt.bytesToHex(host.keyFingerprint(), .lower);
    std.debug.print(
        "HTTP signaling on TCP 19132, external MOTD on UDP 19132, LAN discovery on UDP 7551\n" ++
            "capacity: {d} sessions over {d} tick shards\n" ++
            "identity: {s}, key {s} (sha-256 {s})\n",
        .{
            options.sessions,
            options.shards,
            if (options.insecure) "INSECURE, claims are not anchored" else "anchored to the configured JWKS",
            options.key_path,
            fingerprint[0..],
        },
    );
    if (options.insecure) {
        std.debug.print(
            "WARNING: --insecure admits a client claim that chains to nothing. Use it for a lab only;\n" ++
                "a public deployment needs --jwks or --jwks-document.\n",
            .{},
        );
    }
    if (options.public_address) |address| {
        std.debug.print("answer announces a srflx candidate at {s}:{d}\n", .{ address, options.public_port });
    }
    if (options.stun) |url| {
        std.debug.print("ICE gathering uses {s}\n", .{url});
    }
    if (!host.isLanBound()) {
        std.debug.print(
            "LAN discovery could not bind UDP 7551 (usually the Minecraft client owns it); joins by IP still work.\n",
            .{},
        );
    }

    while (true) {
        std.Io.sleep(init.io, .fromMilliseconds(1000), .awake) catch return;
    }
}
