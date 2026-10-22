const std = @import("std");
const builtin = @import("builtin");

const discovery = @import("../discovery.zig");
const framing = @import("../transport/framing.zig");
const sdp_edit = @import("../transport/sdp_edit.zig");
const peer_mod = @import("../webrtc/peer.zig");
const identity_mod = @import("../identity/server.zig");
const identity_verify = @import("../identity/verify.zig");
const udp = @import("../platform/udp.zig");
const log = @import("../log.zig");
const policy = @import("policy.zig");
const http_srv = @import("http.zig");
const lan_srv = @import("lan.zig");
const motd_srv = @import("motd.zig");

pub const Host = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config: Config,
    identity: identity_mod.Provider,
    http: ?http_srv.Server,
    lan: ?lan_srv.Server,
    motd: ?motd_srv.Server,
    stopping: std.atomic.Value(bool) = .init(false),
    run_thread: ?std.Thread = null,

    pub const Paths = struct {
        http: bool = true,
        lan: bool = true,
        motd: bool = true,
    };

    pub const Config = struct {
        server_data: discovery.ServerData = .{
            .server_name = "NetherNet Zig test server",
            .level_name = "nethernet-zig-test",
            .game_type = .creative,
        },
        paths: Paths = .{},
        handler: ?peer_mod.MessageHandler = null,
        echo_packets: bool = true,
        max_message_size: u32 = framing.default_message_size,
        max_packet_bytes: usize = framing.default_max_packet_bytes,
        http_config: http_srv.Config = .{},
        lan_config: lan_srv.Config = .{},
        motd_config: motd_srv.Config = .{},
        cpk_encoding: identity_mod.Provider.CpkEncoding = .jwk,
        identity_verifier: ?*identity_verify.Verifier = null,
        identity_policy: ?identity_verify.IdentityPolicy = null,
        accept_unverified_identity: bool = false,
        identity: ?identity_mod.Provider = null,
        identity_domain: []const u8 = "self",
        identity_lifetime_seconds: i64 = 3600,
        require_identity: bool = false,
        require_client_identity: ?bool = null,
        ice_servers: []const peer_mod.IceServer = &.{},
        public_candidate: ?sdp_edit.PublicCandidate = null,
    };

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config) !*Host {
        if (config.require_identity and config.identity == null) return error.IdentityRequired;

        const identity_config: identity_mod.Provider.Config = .{
            .domain = config.identity_domain,
            .lifetime_seconds = config.identity_lifetime_seconds,
            .cpk_encoding = config.cpk_encoding,
        };
        try identity_mod.Provider.validateConfig(identity_config);
        try peer_mod.validateIceServers(config.ice_servers);
        if (config.public_candidate) |candidate| {
            try sdp_edit.validateCandidate(candidate);
            std.log.info("announcing public ICE candidate {s}:{d}", .{ candidate.address, candidate.port });
        }
        if (config.identity != null and !std.mem.eql(u8, config.identity_domain, "self"))
            std.log.warn("identity_domain={s} is ignored because Config.identity is set", .{config.identity_domain});
        const identity = config.identity orelse identity_mod.Provider.init(io, identity_config);
        const fingerprint = std.fmt.bytesToHex(identity.keyFingerprint(), .lower);
        std.log.info("server identity: key sha-256={s}", .{fingerprint[0..]});

        const host = try allocator.create(Host);
        errdefer allocator.destroy(host);

        host.* = .{
            .io = io,
            .allocator = allocator,
            .config = config,
            .identity = identity,
            .http = null,
            .lan = null,
            .motd = null,
            .stopping = .init(false),
            .run_thread = null,
        };

        const occupancy = policy.PlayerSource{ .ctx = host, .count = countConnections };
        const players = policy.PlayerSource{ .ctx = host, .count = countPlayers };

        if (config.paths.http) host.http = try http_srv.Server.init(io, allocator, httpConfig(config, occupancy, identity));
        errdefer if (host.http) |*server| server.deinit();
        if (config.paths.lan) host.lan = try lan_srv.Server.init(io, allocator, lanConfig(config, occupancy, identity));
        errdefer if (host.lan) |*server| server.deinit();
        if (config.paths.motd) host.motd = try motd_srv.Server.init(io, allocator, motdConfig(config, players));
        errdefer if (host.motd) |*server| server.deinit();

        return host;
    }

    pub fn deinit(self: *Host) void {
        self.stop();
        if (self.http) |*server| server.deinit();
        if (self.lan) |*server| server.deinit();
        if (self.motd) |*server| server.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn tick(self: *Host) void {
        if (self.http) |*server| server.tick();
        if (self.lan) |*server| server.tick();
        if (self.motd) |*server| server.tick();
    }

    pub fn start(self: *Host) !void {
        self.stopping.store(false, .release);
        if (self.http) |*server| try server.start();
        errdefer self.stop();
        self.run_thread = try std.Thread.spawn(.{}, runLoop, .{self});
    }

    pub fn stop(self: *Host) void {
        self.stopping.store(true, .release);
        if (self.http) |*server| server.stop();
        if (self.run_thread) |thread| {
            thread.join();
            self.run_thread = null;
        }
    }

    fn runLoop(self: *Host) void {
        const interval = self.config.http_config.tick_interval_ms;
        while (!self.stopping.load(.acquire)) {
            self.tick();
            std.Io.sleep(self.io, .fromMilliseconds(interval), .awake) catch return;
        }
    }

    pub fn acceptLoop(self: *Host) void {
        self.stopping.store(false, .release);
        if (self.http) |*server| {
            server.start() catch |err| {
                std.log.err("could not start the signaling workers: {s}", .{@errorName(err)});
                return;
            };
        }
        runLoop(self);
    }

    pub fn playerCount(self: *const Host) usize {
        var count: usize = if (self.http) |*server| server.playerCount() else 0;
        if (self.lan) |*server| count += server.playerCount();
        return count;
    }

    pub fn connectionCount(self: *const Host) usize {
        var count: usize = if (self.http) |*server| server.sessionCount() else 0;
        if (self.lan) |*server| count += server.connectionCount();
        return count;
    }

    pub fn isLanBound(self: *const Host) bool {
        return if (self.lan) |*server| server.isBound() else false;
    }

    pub fn isLanDisabled(self: *const Host) bool {
        return if (self.lan) |*server| server.isDisabled() else false;
    }

    pub fn isMotdBound(self: *const Host) bool {
        return if (self.motd) |*server| server.isBound() else false;
    }

    pub fn keyFingerprint(self: *const Host) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
        return self.identity.keyFingerprint();
    }
};

fn httpConfig(config: Host.Config, occupancy: policy.PlayerSource, identity: identity_mod.Provider) http_srv.Config {
    return .{
        .bind_address = config.http_config.bind_address,
        .server_data = config.server_data,
        .occupancy = occupancy,
        .max_header_size = config.http_config.max_header_size,
        .max_body_size = config.http_config.max_body_size,
        .max_concurrent_requests = config.http_config.max_concurrent_requests,
        .request_timeout_ms = config.http_config.request_timeout_ms,
        .gather_timeout_ms = config.http_config.gather_timeout_ms,
        .establish_timeout_ms = config.http_config.establish_timeout_ms,
        .rate_limit = config.http_config.rate_limit,
        .max_network_id_bytes = config.http_config.max_network_id_bytes,
        .ice_servers = config.ice_servers,
        .public_candidate = config.public_candidate,
        .max_sessions = config.http_config.max_sessions,
        .tick_shards = config.http_config.tick_shards,
        .tick_interval_ms = config.http_config.tick_interval_ms,
        .handler = config.handler,
        .max_message_size = config.max_message_size,
        .max_packet_bytes = config.max_packet_bytes,
        .echo_packets = config.echo_packets,
        .cpk_encoding = config.cpk_encoding,
        .identity = identity,
        .identity_verifier = config.identity_verifier,
        .identity_policy = config.identity_policy,
        .accept_unverified_identity = config.accept_unverified_identity or config.http_config.accept_unverified_identity,
        .max_identity_bytes = config.http_config.max_identity_bytes,
        .require_identity = config.require_client_identity orelse config.http_config.require_identity,
    };
}

fn lanConfig(config: Host.Config, occupancy: policy.PlayerSource, identity: identity_mod.Provider) lan_srv.Config {
    return .{
        .bind_address = config.lan_config.bind_address,
        .port = config.lan_config.port,
        .network_id = config.lan_config.network_id,
        .server_data = config.server_data,
        .occupancy = occupancy,
        .max_datagrams_per_tick = config.lan_config.max_datagrams_per_tick,
        .max_pending_connections = config.lan_config.max_pending_connections,
        .negotiation_timeout_ms = config.lan_config.negotiation_timeout_ms,
        .idle_timeout_ms = config.lan_config.idle_timeout_ms,
        .echo_packets = config.echo_packets,
        .handler = config.handler,
        .max_message_size = config.max_message_size,
        .max_packet_bytes = config.max_packet_bytes,
        .bind_retry_ms = config.lan_config.bind_retry_ms,
        .max_bind_attempts = config.lan_config.max_bind_attempts,
        .discovery_replies_per_second = config.lan_config.discovery_replies_per_second,
        .cpk_encoding = config.cpk_encoding,
        .identity = identity,
        .identity_verifier = config.identity_verifier,
        .identity_policy = config.identity_policy,
        .require_identity = config.require_client_identity orelse config.lan_config.require_identity,
        .ice_servers = config.ice_servers,
        .public_candidate = config.public_candidate,
    };
}

fn motdConfig(config: Host.Config, players: policy.PlayerSource) motd_srv.Config {
    return .{
        .bind_address = config.motd_config.bind_address,
        .port = config.motd_config.port,
        .server_data = config.server_data,
        .server_guid = config.motd_config.server_guid,
        .players = players,
        .bind_retry_ms = config.motd_config.bind_retry_ms,
        .max_datagrams_per_tick = config.motd_config.max_datagrams_per_tick,
        .replies_per_second = config.motd_config.replies_per_second,
    };
}

fn countPlayers(ctx: *anyopaque) usize {
    const self: *Host = @ptrCast(@alignCast(ctx));
    return self.playerCount();
}

fn countConnections(ctx: *anyopaque) usize {
    const self: *Host = @ptrCast(@alignCast(ctx));
    return self.connectionCount();
}

test "one host brings up every path with the same advertisement" {
    const io = std.testing.io;
    const server_data: discovery.ServerData = .{
        .server_name = "host-test",
        .level_name = "host-level",
        .game_type = .adventure,
        .max_player_count = 3,
        .nonce = "hostnonce",
    };

    const host = try Host.init(io, std.testing.allocator, .{
        .accept_unverified_identity = true,
        .server_data = server_data,
        .http_config = .{ .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19941) } },
        .lan_config = .{ .port = 19942 },
        .motd_config = .{ .port = 19943 },
    });
    defer host.deinit();

    try std.testing.expectEqual(server_data.protocol, host.http.?.config.server_data.protocol);
    try std.testing.expectEqualStrings("host-test", host.lan.?.config.server_data.server_name);
    try std.testing.expectEqualStrings("host-level", host.motd.?.config.server_data.level_name);
    try std.testing.expectEqual(@as(i32, 3), host.motd.?.config.server_data.max_player_count);
    try std.testing.expect(host.isLanBound());
    try std.testing.expect(!host.isLanDisabled());
    try std.testing.expect(host.isMotdBound());
    try std.testing.expectEqual(@as(usize, 0), host.playerCount());
    try std.testing.expectEqual(@as(usize, 0), host.connectionCount());

    const source = host.motd.?.config.players.?;
    const http_occupancy = host.http.?.config.occupancy.?;
    const lan_occupancy = host.lan.?.config.occupancy.?;
    try std.testing.expect(source.count == countPlayers);
    try std.testing.expect(http_occupancy.count == countConnections);
    try std.testing.expect(lan_occupancy.count == countConnections);
    try std.testing.expect(@intFromPtr(source.ctx) == @intFromPtr(host));
    try std.testing.expectEqual(host.playerCount(), source.count(source.ctx));
    try std.testing.expectEqual(host.connectionCount(), http_occupancy.count(http_occupancy.ctx));
    try std.testing.expectEqual(host.connectionCount(), lan_occupancy.count(lan_occupancy.ctx));

    var pending = motd_srv.Query.open(io, std.mem.nativeToBig(u32, 0x7f000001), 19943, 2_000) orelse
        return error.SkipZigTest;
    defer pending.deinit();
    var buffer: [1024]u8 = undefined;
    var pong: ?motd_srv.Pong = null;
    var attempts: usize = 0;
    while (pong == null and attempts < 200) : (attempts += 1) {
        host.tick();
        pong = pending.poll(&buffer);
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    try std.testing.expect(pong != null);
    try std.testing.expect(std.mem.startsWith(u8, pong.?.motd, "MCPE;host-test;4422;1.26.60;0;3;"));
    try std.testing.expect(std.mem.indexOf(u8, pong.?.motd, ";host-level;Adventure;2;") != null);
}

const CountProbe = struct {
    host: *const Host,
    done: *std.atomic.Value(bool),
    players: usize = 0,
    connections: usize = 0,

    fn main(self: *CountProbe) void {
        self.players = self.host.playerCount();
        self.connections = self.host.connectionCount();
        self.done.store(true, .release);
    }
};

const count_probe_watchdog_ms: i64 = 2_000;

test "a handler counts without waiting for a signaling shard" {
    const io = std.testing.io;
    const host = try Host.init(io, std.testing.allocator, .{
        .accept_unverified_identity = true,
        .http_config = .{ .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19947) } },
        .lan_config = .{ .port = 19948 },
        .motd_config = .{ .port = 19949 },
    });
    defer host.deinit();

    host.http.?.shard_locks[0].lockUncancelable(io);
    var done = std.atomic.Value(bool).init(false);
    var probe = CountProbe{ .host = host, .done = &done };
    const worker = try std.Thread.spawn(.{}, CountProbe.main, .{&probe});
    const deadline = std.Io.Clock.real.now(io).toMilliseconds() + count_probe_watchdog_ms;
    var answered_in_time = true;
    while (!done.load(.acquire)) {
        if (std.Io.Clock.real.now(io).toMilliseconds() >= deadline) {
            answered_in_time = false;
            break;
        }
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    host.http.?.shard_locks[0].unlock(io);
    worker.join();

    try std.testing.expect(answered_in_time);
    try std.testing.expectEqual(@as(usize, 0), probe.players);
    try std.testing.expectEqual(@as(usize, 0), probe.connections);
}

test "every door of a host signs with the same operator identity" {
    const io = std.testing.io;
    const identity = identity_mod.Provider.init(io, .{});
    const fingerprint = identity.keyFingerprint();

    const host = try Host.init(io, std.testing.allocator, .{
        .accept_unverified_identity = true,
        .identity = identity,
        .paths = .{ .motd = false },
        .http_config = .{ .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19964) } },
        .lan_config = .{ .port = 19965 },
    });
    defer host.deinit();

    try std.testing.expectEqualSlices(u8, &fingerprint, &host.keyFingerprint());
    try std.testing.expectEqualSlices(u8, &fingerprint, &host.http.?.identity.keyFingerprint());
    try std.testing.expectEqualSlices(u8, &fingerprint, &host.lan.?.identity.keyFingerprint());
}

fn countNone(_: *anyopaque) usize {
    return 0;
}

test "the host's client identity requirement reaches both listeners" {
    const io = std.testing.io;
    var provider = identity_mod.Provider.init(io, .{});
    const occupancy = policy.PlayerSource{ .ctx = &provider, .count = countNone };

    var config: Host.Config = .{};
    try std.testing.expect(httpConfig(config, occupancy, provider).require_identity);
    try std.testing.expect(!lanConfig(config, occupancy, provider).require_identity);

    config.require_client_identity = true;
    try std.testing.expect(httpConfig(config, occupancy, provider).require_identity);
    try std.testing.expect(lanConfig(config, occupancy, provider).require_identity);

    config.require_client_identity = false;
    try std.testing.expect(!httpConfig(config, occupancy, provider).require_identity);
    try std.testing.expect(!lanConfig(config, occupancy, provider).require_identity);

    config = .{
        .require_identity = true,
        .http_config = .{ .require_identity = false },
        .lan_config = .{ .require_identity = true },
    };
    try std.testing.expect(config.require_client_identity == null);
    try std.testing.expect(!httpConfig(config, occupancy, provider).require_identity);
    try std.testing.expect(lanConfig(config, occupancy, provider).require_identity);

    try std.testing.expect(!httpConfig(.{}, occupancy, provider).accept_unverified_identity);
    try std.testing.expect(httpConfig(.{ .accept_unverified_identity = true }, occupancy, provider).accept_unverified_identity);
    try std.testing.expect(httpConfig(.{ .http_config = .{ .accept_unverified_identity = true } }, occupancy, provider).accept_unverified_identity);
    try std.testing.expectEqual(@as(usize, 1024), httpConfig(.{ .http_config = .{ .max_identity_bytes = 1024 } }, occupancy, provider).max_identity_bytes);
}

test "the host's http budget reaches the listener" {
    const io = std.testing.io;
    var provider = identity_mod.Provider.init(io, .{});
    const occupancy = policy.PlayerSource{ .ctx = &provider, .count = countNone };

    const defaults = httpConfig(.{}, occupancy, provider);
    try std.testing.expectEqual(@as(usize, 32), defaults.max_concurrent_requests);
    try std.testing.expectEqual(@as(i64, 10_000), defaults.request_timeout_ms);
    try std.testing.expectEqual(@as(i64, 8_000), defaults.gather_timeout_ms);
    try std.testing.expect(defaults.rate_limit == null);

    const configured = httpConfig(.{ .http_config = .{
        .max_concurrent_requests = 4,
        .request_timeout_ms = 5_000,
        .gather_timeout_ms = 3_000,
        .rate_limit = .{ .joins_per_minute = 30, .burst = 2 },
    } }, occupancy, provider);
    try std.testing.expectEqual(@as(usize, 4), configured.max_concurrent_requests);
    try std.testing.expectEqual(@as(i64, 5_000), configured.request_timeout_ms);
    try std.testing.expectEqual(@as(i64, 3_000), configured.gather_timeout_ms);
    try std.testing.expectEqual(@as(u32, 2), configured.rate_limit.?.burst);
}

test "a host that requires an identity refuses to start without one" {
    try std.testing.expectError(error.IdentityRequired, Host.init(std.testing.io, std.testing.allocator, .{
        .require_identity = true,
        .paths = .{ .http = false, .lan = false, .motd = false },
    }));
}

test "the host configures the identity domain and lifetime" {
    const io = std.testing.io;
    const host = try Host.init(io, std.testing.allocator, .{
        .accept_unverified_identity = true,
        .paths = .{ .lan = false, .motd = false },
        .http_config = .{ .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19971) } },
        .identity_domain = "partner.example",
        .identity_lifetime_seconds = 1200,
    });
    defer host.deinit();

    try std.testing.expectEqualStrings("partner.example", host.identity.domain);
    try std.testing.expectEqual(@as(i64, 1200), host.identity.lifetime_seconds);
    try std.testing.expectEqualStrings("partner.example", host.http.?.identity.domain);
}

test "the host refuses an identity domain or lifetime it cannot sign" {
    const rows = [_]struct { domain: []const u8 = "self", lifetime: i64 = 3600 }{
        .{ .domain = "" },
        .{ .domain = "partner.example." },
        .{ .domain = "partner\"example" },
        .{ .domain = "-partner.example" },
        .{ .domain = ("a" ** 64) ++ ".example" },
        .{ .lifetime = 59 },
        .{ .lifetime = 604_801 },
    };
    for (rows) |row| {
        try std.testing.expectError(error.InvalidIdentityConfig, Host.init(std.testing.io, std.testing.allocator, .{
            .identity_domain = row.domain,
            .identity_lifetime_seconds = row.lifetime,
        }));
    }
}

test "an explicit identity keeps its own domain" {
    const io = std.testing.io;
    const identity = identity_mod.Provider.init(io, .{ .domain = "own.example" });
    const host = try Host.init(io, std.testing.allocator, .{
        .accept_unverified_identity = true,
        .identity = identity,
        .identity_domain = "ignored.example",
        .paths = .{ .lan = false, .motd = false },
        .http_config = .{ .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19972) } },
    });
    defer host.deinit();

    try std.testing.expectEqualStrings("own.example", host.identity.domain);
}

test "a host without a verifier refuses to bring up HTTP signaling" {
    try std.testing.expectError(error.IdentityVerifierRequired, Host.init(std.testing.io, std.testing.allocator, .{
        .paths = .{ .lan = false, .motd = false },
        .http_config = .{ .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19970) } },
    }));
}

test "a host serves the paths it is told to serve" {
    const host = try Host.init(std.testing.io, std.testing.allocator, .{
        .paths = .{ .http = false, .motd = false },
        .lan_config = .{ .port = 19944 },
    });
    defer host.deinit();

    try std.testing.expect(host.http == null);
    try std.testing.expect(host.motd == null);
    try std.testing.expect(!host.isMotdBound());
    try std.testing.expect(host.isLanBound());
    host.tick();
    try std.testing.expectEqual(@as(usize, 0), host.playerCount());
    try std.testing.expectEqual(@as(usize, 0), host.connectionCount());
}

fn serveOneForTest(host: *Host) void {
    if (host.http) |*server| server.serveOne() catch |err|
        log.debug("test signaling transaction ended: {s}", .{@errorName(err)});
}

fn sendSignaling(
    io: std.Io,
    host: *Host,
    address: std.Io.net.IpAddress,
    request: []const u8,
    response_buffer: []u8,
) ![]const u8 {
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var write_buffer: [512]u8 = undefined;
    var stream_writer = std.Io.net.Stream.writer(stream, io, &write_buffer);
    try stream_writer.interface.writeAll(request);
    try stream_writer.interface.flush();

    const worker = try std.Thread.spawn(.{}, serveOneForTest, .{host});
    defer worker.join();
    var stream_reader = std.Io.net.Stream.reader(stream, io, response_buffer);
    while (stream_reader.interface.bufferedLen() < response_buffer.len)
        stream_reader.interface.fillMore() catch break;
    return stream_reader.interface.buffered();
}

fn signedRealOffer(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var provider = identity_mod.Provider.init(io, .{});
    return provider.addToSdp(allocator, lan_srv.real_offer);
}

test "signaling keeps accepting players while LAN discovery is disabled" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const lan_port: u16 = 19955;
    var occupier = udp.Socket.open(io, .{
        .address = std.mem.nativeToBig(u32, 0x7f000001),
        .port = lan_port,
        .reuse_address = false,
    }) catch |err| switch (err) {
        error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    defer occupier.close();

    const host = try Host.init(io, allocator, .{
        .accept_unverified_identity = true,
        .server_data = .{
            .server_name = "lan-off",
            .level_name = "lan-off",
            .max_player_count = 4,
        },
        .http_config = .{ .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19956) } },
        .lan_config = .{ .port = lan_port, .max_bind_attempts = 1 },
        .motd_config = .{ .port = 19957 },
    });
    var host_live = true;
    defer if (host_live) host.deinit();
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(!host.isLanDisabled());
        try std.testing.expect(host.isLanBound());
    } else {
        try std.testing.expect(host.isLanDisabled());
        try std.testing.expect(!host.isLanBound());
    }
    try std.testing.expect(host.isMotdBound());

    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19956) };
    var response_buffer: [16 * 1024]u8 = undefined;

    const status = try sendSignaling(
        io,
        host,
        address,
        "GET /v1/join HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n",
        &response_buffer,
    );
    try std.testing.expect(std.mem.startsWith(u8, status, "HTTP/1.1 200"));
    try std.testing.expect(std.mem.indexOf(u8, status, "\"name\":\"lan-off\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"players\":0") != null);

    const offer = try signedRealOffer(allocator, io);
    defer allocator.free(offer);
    var request_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&request_buffer);
    try writer.print(
        "POST /v1/join/off-0001 HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
            "content-length: {d}\r\nconnection: close\r\n\r\n",
        .{offer.len},
    );
    try writer.writeAll(offer);

    const join = try sendSignaling(io, host, address, writer.buffered(), &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, join, "HTTP/1.1 200"));
    try std.testing.expect(std.mem.indexOf(u8, join, "a=identity:") != null);
    try std.testing.expectEqual(@as(usize, 1), host.http.?.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), host.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), host.playerCount());

    host.tick();
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(!host.isLanDisabled());
        try std.testing.expect(host.isLanBound());
    } else {
        try std.testing.expect(host.isLanDisabled());
        try std.testing.expect(!host.isLanBound());
    }

    host.deinit();
    host_live = false;
}

const SessionCounter = struct {
    opened: usize = 0,
    closed: usize = 0,

    fn handler(self: *SessionCounter) peer_mod.MessageHandler {
        return .{
            .ctx = self,
            .on_open = onOpen,
            .on_message = onMessage,
            .on_close = onClose,
        };
    }

    fn onOpen(ctx: *anyopaque, _: *peer_mod.PeerHandle) void {
        const self: *SessionCounter = @ptrCast(@alignCast(ctx));
        self.opened += 1;
    }

    fn onMessage(_: *anyopaque, _: *peer_mod.PeerHandle, _: peer_mod.ChannelKind, _: []const u8) ?[]const u8 {
        return null;
    }

    fn onClose(ctx: *anyopaque, _: *peer_mod.PeerHandle) void {
        const self: *SessionCounter = @ptrCast(@alignCast(ctx));
        self.closed += 1;
    }
};

test "a rejoin with the same network id closes the session it replaces" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19960) };
    var counter = SessionCounter{};
    const host = try Host.init(io, allocator, .{
        .accept_unverified_identity = true,
        .server_data = .{ .server_name = "rejoin", .level_name = "rejoin", .max_player_count = 4 },
        .paths = .{ .lan = false, .motd = false },
        .http_config = .{ .bind_address = address },
        .handler = counter.handler(),
    });
    var host_live = true;
    defer if (host_live) host.deinit();

    var response_buffer: [16 * 1024]u8 = undefined;
    for (0..2) |_| {
        const offer = try signedRealOffer(allocator, io);
        defer allocator.free(offer);
        var request_buffer: [8192]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&request_buffer);
        try writer.print(
            "POST /v1/join/rejoin-0001 HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
                "content-length: {d}\r\nconnection: close\r\n\r\n",
            .{offer.len},
        );
        try writer.writeAll(offer);

        const answer = try sendSignaling(io, host, address, writer.buffered(), &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 200"));
        try std.testing.expect(std.mem.indexOf(u8, answer, "a=identity:") != null);
        try std.testing.expectEqual(@as(usize, 1), host.http.?.sessionCount());
    }
    try std.testing.expectEqual(@as(usize, 2), counter.opened);
    try std.testing.expectEqual(@as(usize, 1), counter.closed);

    host.deinit();
    host_live = false;
    try std.testing.expectEqual(@as(usize, 2), counter.closed);
}

fn cpkClaimFromAnswer(allocator: std.mem.Allocator, response: []const u8) ![]u8 {
    const prefix = "a=identity:";
    const start = std.mem.indexOf(u8, response, prefix) orelse return error.MissingIdentity;
    const end = std.mem.indexOfScalarPos(u8, response, start, '\r') orelse return error.MissingIdentity;
    const encoded = response[start + prefix.len .. end];

    const envelope_buffer = try allocator.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(encoded));
    defer allocator.free(envelope_buffer);
    try std.base64.standard.Decoder.decode(envelope_buffer, encoded);
    const parse_options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const Envelope = struct { assertion: []const u8 };
    const envelope = try std.json.parseFromSlice(Envelope, allocator, envelope_buffer, parse_options);
    defer envelope.deinit();

    const Assertion = struct { fingerprints: []const u8, token: []const u8 };
    const assertion = try std.json.parseFromSlice(Assertion, allocator, envelope.value.assertion, parse_options);
    defer assertion.deinit();
    var parts = std.mem.splitScalar(u8, assertion.value.token, '.');
    _ = parts.next().?;
    const claims_b64 = parts.next().?;

    const claims_buffer = try allocator.alloc(u8, try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(claims_b64));
    defer allocator.free(claims_buffer);
    try std.base64.url_safe_no_pad.Decoder.decode(claims_buffer, claims_b64);
    const key = "\"cpk\":";
    const claim_start = std.mem.indexOf(u8, claims_buffer, key) orelse return error.MissingCpkClaim;
    const claims_end = std.mem.lastIndexOfScalar(u8, claims_buffer, '}') orelse return error.MissingCpkClaim;
    if (claims_end <= claim_start + key.len) return error.MissingCpkClaim;
    return allocator.dupe(u8, claims_buffer[claim_start + key.len .. claims_end]);
}

test "the configured cpk encoding reaches the answered claim" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const rows = [_]struct { port: u16, encoding: identity_mod.Provider.CpkEncoding }{
        .{ .port = 19958, .encoding = .jwk },
        .{ .port = 19959, .encoding = .base64_der },
    };

    var response_buffer: [16 * 1024]u8 = undefined;
    for (rows) |row| {
        const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(row.port) };
        const host = try Host.init(io, allocator, .{
            .accept_unverified_identity = true,
            .server_data = .{ .server_name = "cpk", .level_name = "cpk", .max_player_count = 1 },
            .paths = .{ .lan = false, .motd = false },
            .http_config = .{ .bind_address = address },
            .cpk_encoding = row.encoding,
        });
        defer {
            host.deinit();
        }

        const offer = try signedRealOffer(allocator, io);
        defer allocator.free(offer);
        var request_buffer: [8192]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&request_buffer);
        try writer.print(
            "POST /v1/join/cpk-{s} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
                "content-length: {d}\r\nconnection: close\r\n\r\n",
            .{ @tagName(row.encoding), offer.len },
        );
        try writer.writeAll(offer);

        const answer = try sendSignaling(io, host, address, writer.buffered(), &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 200"));
        const claim = try cpkClaimFromAnswer(allocator, answer);
        defer allocator.free(claim);

        switch (row.encoding) {
            .jwk => {
                try std.testing.expectEqual(@as(u8, '{'), claim[0]);
                const Jwk = struct { crv: []const u8, kty: []const u8, x: []const u8, y: []const u8 };
                const parsed = try std.json.parseFromSlice(Jwk, allocator, claim, .{});
                defer parsed.deinit();
                try std.testing.expectEqualStrings("P-384", parsed.value.crv);
                try std.testing.expectEqualStrings("EC", parsed.value.kty);
                try std.testing.expectEqual(@as(usize, 64), parsed.value.x.len);
                try std.testing.expectEqual(@as(usize, 64), parsed.value.y.len);
            },
            .base64_der => {
                try std.testing.expectEqual(@as(u8, '"'), claim[0]);
                try std.testing.expectEqual(@as(usize, 162), claim.len);
                var der: [120]u8 = undefined;
                try std.base64.standard.Decoder.decode(&der, claim[1 .. claim.len - 1]);
                try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x76 }, der[0..2]);
            },
        }
    }
}
