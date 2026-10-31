const std = @import("std");
const builtin = @import("builtin");
const udp = @import("../platform/udp.zig");
const discovery = @import("../discovery.zig");
const log = @import("../log.zig");
const policy = @import("policy.zig");
const ratelimit = @import("ratelimit.zig");

pub const Error = error{
    SendFailed,
} || std.Io.Writer.Error;

const ping_id: u8 = 0x01;
const ping_open_connections_id: u8 = 0x02;
const pong_id: u8 = 0x1c;
const magic: [16]u8 = .{ 0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78 };
const ping_size: usize = 1 + 8 + 16 + 8;
const pong_prefix_size: usize = 1 + 8 + 8 + 16 + 2;
const query_client_guid: u64 = 0x6e65_7468_6572_7175;
const datagram_size: usize = 2048;
const pong_payload_size: usize = 1024;

pub const Config = struct {
    bind_address: u32 = 0,
    port: u16 = 19132,
    server_data: discovery.ServerData = .{
        .server_name = "NetherNet Zig test server",
        .level_name = "nethernet-zig-test",
        .game_type = .creative,
        .max_player_count = 1,
    },
    server_guid: u64 = 0x4e65_7468_6572_4e65,
    players: ?policy.PlayerSource = null,
    bind_retry_ms: i64 = 1_000,
    max_datagrams_per_tick: usize = 64,
    replies_per_second: u32 = 16,
};

const Ping = struct {
    time: i64,
    client_guid: u64,
};

pub const Server = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config: Config,
    socket: ?udp.Socket = null,
    bound: bool = false,
    next_bind_attempt_ms: i64 = 0,
    bind_failures: usize = 0,
    answered: usize = 0,
    replies: ratelimit.Limiter,
    closed: bool = false,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config) Error!Server {
        var server: Server = .{
            .io = io,
            .allocator = allocator,
            .config = config,
            .replies = ratelimit.Limiter.init(io, config.replies_per_second),
        };
        server.attemptBind();
        return server;
    }

    pub fn isBound(self: *const Server) bool {
        return self.bound;
    }

    pub fn answeredCount(self: *const Server) usize {
        return self.answered;
    }

    fn attemptBind(self: *Server) void {
        if (self.bound or self.closed) return;
        const opened = udp.Socket.open(self.io, .{
            .address = self.config.bind_address,
            .port = self.config.port,
            .reuse_address = true,
        }) catch |err| {
            if (self.bind_failures == 0) {
                std.log.warn("external server ping cannot bind UDP 0.0.0.0:{d}: {s}", .{ self.config.port, @errorName(err) });
                if (err == error.AddressInUse) {
                    std.log.warn(
                        "UDP {d} is held by another socket that does not share it: normally the Minecraft client with its server list " ++
                            "open, or a second Bedrock server. Retrying every {d} ms. A manual entry is painted only " ++
                            "by a pong this responder sends while the client is still asking, so start this server " ++
                            "before opening that list.",
                        .{ self.config.port, self.config.bind_retry_ms },
                    );
                }
            } else {
                log.debug("external server ping bind retry failed: {s}", .{@errorName(err)});
            }
            self.bind_failures += 1;
            self.next_bind_attempt_ms = self.nowMs() + self.config.bind_retry_ms;
            return;
        };
        self.socket = opened;
        self.bound = true;
        if (self.bind_failures == 0) {
            std.log.info(
                "external server ping listening on 0.0.0.0:{d} motd=\"{s}\"",
                .{ self.config.port, self.config.server_data.server_name },
            );
        } else {
            std.log.info("external server ping bound UDP {d} after {d} failed attempts", .{ self.config.port, self.bind_failures });
            self.bind_failures = 0;
        }
    }

    pub fn deinit(self: *Server) void {
        if (!self.closed) {
            if (self.socket) |*socket| socket.close();
            self.socket = null;
            self.closed = true;
        }
        self.* = undefined;
    }

    pub fn tick(self: *Server) void {
        if (self.closed) return;
        if (!self.bound) {
            if (self.nowMs() < self.next_bind_attempt_ms) return;
            self.attemptBind();
            if (!self.bound) return;
        }
        self.receiveDatagrams();
    }

    fn receiveDatagrams(self: *Server) void {
        const socket = if (self.socket) |*bound| bound else return;
        var count: usize = 0;
        while (count < self.config.max_datagrams_per_tick) : (count += 1) {
            var buffer: [datagram_size]u8 = undefined;
            const datagram = socket.receive(&buffer) catch |err| {
                std.log.warn("external server ping receive failed: {s}", .{@errorName(err)});
                return;
            } orelse return;
            self.answer(datagram.from, buffer[0..datagram.len]);
        }
    }

    fn answer(self: *Server, source: udp.Address, frame: []const u8) void {
        if (frame.len == 0) return;
        if (!self.replies.allow(source.addr)) {
            log.debug("external server ping dropped: source over its reply budget", .{});
            return;
        }
        var pong_buffer: [pong_payload_size]u8 = undefined;
        const pong = buildPong(self.config, frame, &pong_buffer) orelse {
            log.debug("external server ping ignored id=0x{x:0>2} bytes={d}", .{ frame[0], frame.len });
            return;
        };
        self.sendFrame(pong, source) catch |err| {
            std.log.warn("external server ping reply failed: {s}", .{@errorName(err)});
            return;
        };
        self.answered += 1;
        const address = std.mem.bigToNative(u32, source.addr);
        log.debug(
            "external server ping answered from {d}.{d}.{d}.{d}:{d} bytes={d} total={d}",
            .{
                (address >> 24) & 0xff,
                (address >> 16) & 0xff,
                (address >> 8) & 0xff,
                address & 0xff,
                std.mem.bigToNative(u16, source.port),
                pong.len,
                self.answered,
            },
        );
    }

    fn sendFrame(self: *Server, frame: []const u8, destination: udp.Address) Error!void {
        const socket = if (self.socket) |*bound| bound else return error.SendFailed;
        socket.send(destination, frame) catch return error.SendFailed;
    }

    fn nowMs(self: *Server) i64 {
        return std.Io.Clock.real.now(self.io).toMilliseconds();
    }
};

fn readBig(comptime T: type, bytes: []const u8) T {
    var value: T = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

fn decodePing(frame: []const u8) ?Ping {
    if (frame.len < ping_size) return null;
    if (frame[0] != ping_id and frame[0] != ping_open_connections_id) return null;
    if (!std.mem.eql(u8, frame[9..25], &magic)) return null;
    return .{
        .time = readBig(i64, frame[1..9]),
        .client_guid = readBig(u64, frame[25..33]),
    };
}

fn gameModeName(game_type: discovery.GameType) []const u8 {
    return switch (game_type) {
        .survival => "Survival",
        .creative => "Creative",
        .adventure => "Adventure",
    };
}

fn buildPong(config: Config, frame: []const u8, buffer: []u8) ?[]const u8 {
    const ping = decodePing(frame) orelse return null;
    const data = config.server_data;
    const players: i32 = if (config.players) |source|
        @intCast(@min(source.count(source.ctx), std.math.maxInt(i32)))
    else
        data.player_count;
    var writer: std.Io.Writer = .fixed(buffer);
    var motd_buffer: [512]u8 = undefined;
    var motd_writer: std.Io.Writer = .fixed(&motd_buffer);
    motd_writer.print("MCPE;{s};{d};{s};{d};{d};{d};{s};{s};{d};{d};{d};", .{
        data.server_name,
        data.protocol,
        data.game_version,
        players,
        data.max_player_count,
        config.server_guid,
        data.level_name,
        gameModeName(data.game_type),
        @intFromEnum(data.game_type),
        config.port,
        config.port,
    }) catch return null;
    const motd = motd_writer.buffered();

    writer.writeByte(pong_id) catch return null;
    writer.writeInt(i64, ping.time, .big) catch return null;
    writer.writeInt(u64, config.server_guid, .big) catch return null;
    writer.writeAll(&magic) catch return null;
    writer.writeInt(u16, @intCast(motd.len), .big) catch return null;
    writer.writeAll(motd) catch return null;
    return writer.buffered();
}

pub fn encodePing(buffer: []u8, time: i64, client_guid: u64, open_connections: bool) []const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    writer.writeByte(if (open_connections) ping_open_connections_id else ping_id) catch unreachable;
    writer.writeInt(i64, time, .big) catch unreachable;
    writer.writeAll(&magic) catch unreachable;
    writer.writeInt(u64, client_guid, .big) catch unreachable;
    return writer.buffered();
}

pub const Pong = struct {
    time: i64,
    motd: []const u8,
    bytes: usize,
};

pub fn decodePong(frame: []const u8) ?Pong {
    if (frame.len < pong_prefix_size) return null;
    if (frame[0] != pong_id) return null;
    if (!std.mem.eql(u8, frame[17..33], &magic)) return null;
    const motd_length = readBig(u16, frame[33..35]);
    if (35 + motd_length != frame.len) return null;
    return .{ .time = readBig(i64, frame[1..9]), .motd = frame[35..], .bytes = frame.len };
}

pub const Query = struct {
    io: std.Io,
    socket: udp.Socket,
    deadline_ms: i64,
    pub fn open(io: std.Io, address: u32, port: u16, budget_ms: i64) ?Query {
        var socket = udp.Socket.open(io, .{ .address = 0, .port = 0 }) catch return null;

        var ping_buffer: [ping_size]u8 = undefined;
        const ping = encodePing(&ping_buffer, nowMs(io), query_client_guid, false);
        const destination: udp.Address = .{ .port = std.mem.nativeToBig(u16, port), .addr = address };
        socket.send(destination, ping) catch {
            socket.close();
            return null;
        };
        return .{ .io = io, .socket = socket, .deadline_ms = nowMs(io) + budget_ms };
    }

    pub fn deinit(self: *Query) void {
        self.socket.close();
        self.* = undefined;
    }

    pub fn poll(self: *Query, buffer: []u8) ?Pong {
        const datagram = (self.socket.receive(buffer) catch return null) orelse return null;
        return decodePong(buffer[0..datagram.len]);
    }

    pub fn remainingMs(self: *const Query) i64 {
        return self.deadline_ms - nowMs(self.io);
    }
};

pub fn query(io: std.Io, address: u32, port: u16, budget_ms: i64, buffer: []u8) ?Pong {
    var pending = Query.open(io, address, port, budget_ms) orelse return null;
    defer pending.deinit();
    while (pending.remainingMs() > 0) {
        if (pending.poll(buffer)) |pong| return pong;
        io.sleep(.fromMilliseconds(2), .awake) catch return null;
    }
    return null;
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toMilliseconds();
}

test "RakNet pong echoes the ping time and carries the MOTD" {
    var ping_buffer: [64]u8 = undefined;
    const frame = encodePing(&ping_buffer, 0x0102_0304_0506_0708, 0xaabb_ccdd_eeff_0011, false);
    try std.testing.expectEqual(@as(usize, 33), frame.len);

    var pong_buffer: [pong_payload_size]u8 = undefined;
    const pong = buildPong(.{ .server_data = .{
        .server_name = "Motd test server",
        .protocol = discovery.advertised_build.protocol,
        .game_version = discovery.advertised_build.game_version,
        .level_name = "test-level",
        .player_count = 3,
        .max_player_count = 8,
        .game_type = .creative,
    } }, frame, &pong_buffer).?;
    try std.testing.expectEqual(@as(u8, pong_id), pong[0]);
    try std.testing.expectEqual(@as(i64, 0x0102_0304_0506_0708), readBig(i64, pong[1..9]));
    try std.testing.expectEqual((Config{}).server_guid, readBig(u64, pong[9..17]));
    try std.testing.expectEqualSlices(u8, &magic, pong[17..33]);
    const motd_length = readBig(u16, pong[33..35]);
    try std.testing.expectEqual(@as(usize, motd_length), pong.len - 35);
    const motd = pong[35..];
    try std.testing.expect(std.mem.startsWith(u8, motd, "MCPE;Motd test server;4422;1.26.60;3;8;"));
    try std.testing.expect(std.mem.endsWith(u8, motd, ";Creative;1;19132;19132;"));
    try std.testing.expectEqual(@as(usize, 12), std.mem.count(u8, motd, ";"));
}

test "the MOTD repeats its ServerData and prefers the live player count" {
    const server_data: discovery.ServerData = .{
        .server_name = "shared",
        .protocol = discovery.advertised_build.protocol,
        .game_version = discovery.advertised_build.game_version,
        .level_name = "shared-level",
        .game_type = .adventure,
        .player_count = 1,
        .max_player_count = 12,
    };
    const Counter = struct {
        fn total(_: *anyopaque) usize {
            return 7;
        }
    };
    var ctx: u8 = 0;
    var ping_buffer: [ping_size]u8 = undefined;
    const ping = encodePing(&ping_buffer, 1, 2, false);

    var configured_buffer: [pong_payload_size]u8 = undefined;
    const configured = buildPong(.{ .server_data = server_data }, ping, &configured_buffer).?;
    try std.testing.expect(std.mem.indexOf(u8, configured[35..], ";1;12;") != null);

    var live_buffer: [pong_payload_size]u8 = undefined;
    const live = buildPong(
        .{ .server_data = server_data, .players = .{ .ctx = &ctx, .count = Counter.total } },
        ping,
        &live_buffer,
    ).?;
    var expected_buffer: [256]u8 = undefined;
    const expected = try std.fmt.bufPrint(
        &expected_buffer,
        "MCPE;shared;{d};{s};7;12;{d};shared-level;Adventure;2;19132;19132;",
        .{
            discovery.advertised_build.protocol,
            discovery.advertised_build.game_version,
            (Config{}).server_guid,
        },
    );
    try std.testing.expectEqualStrings(expected, live[35..]);
}

test "RakNet ping decoding rejects foreign datagrams" {
    var ping_buffer: [64]u8 = undefined;
    const frame = encodePing(&ping_buffer, 1, 2, false);
    var pong_buffer: [pong_payload_size]u8 = undefined;
    try std.testing.expect(buildPong(.{}, frame, &pong_buffer) != null);
    const open = encodePing(&ping_buffer, 1, 2, true);
    try std.testing.expect(buildPong(.{}, open, &pong_buffer) != null);

    try std.testing.expect(buildPong(.{}, frame[0..32], &pong_buffer) == null);
    var wrong_id: [33]u8 = undefined;
    @memcpy(&wrong_id, frame[0..33]);
    wrong_id[0] = 0x05;
    try std.testing.expect(buildPong(.{}, &wrong_id, &pong_buffer) == null);
    var wrong_magic: [33]u8 = undefined;
    @memcpy(&wrong_magic, frame[0..33]);
    wrong_magic[9] = 0x42;
    try std.testing.expect(buildPong(.{}, &wrong_magic, &pong_buffer) == null);
    try std.testing.expect(buildPong(.{}, "", &pong_buffer) == null);
}

test "external server ping answers a real datagram end to end" {
    const port: u16 = 19937;
    var server = try Server.init(std.testing.io, std.testing.allocator, .{ .port = port, .server_data = .{ .server_name = "smoke", .level_name = "smoke" } });
    defer server.deinit();
    try std.testing.expect(server.isBound());

    var client = udp.Socket.open(std.testing.io, .{
        .address = std.mem.nativeToBig(u32, 0x7f000001),
        .port = 0,
    }) catch |err| switch (err) {
        error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    defer client.close();

    var ping_buffer: [64]u8 = undefined;
    const frame = encodePing(&ping_buffer, 4242, 7, false);
    const destination: udp.Address = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try client.send(destination, frame);

    var response: [pong_payload_size]u8 = undefined;
    var received: usize = 0;
    var attempts: usize = 0;
    while (attempts < 100 and received == 0) : (attempts += 1) {
        server.tick();
        if (try client.receive(&response)) |datagram| received = datagram.len;
        try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    try std.testing.expect(received != 0);
    try std.testing.expectEqual(@as(u8, pong_id), response[0]);
    try std.testing.expectEqual(@as(i64, 4242), readBig(i64, response[1..9]));
    const motd_length = readBig(u16, response[33..35]);
    try std.testing.expect(std.mem.startsWith(u8, response[35 .. 35 + motd_length], "MCPE;smoke;"));
    try std.testing.expectEqual(@as(usize, 1), server.answeredCount());
}

test "external server ping keeps retrying while UDP 19132 is taken" {
    const port: u16 = 19938;
    var occupier = udp.Socket.open(std.testing.io, .{
        .address = std.mem.nativeToBig(u32, 0x7f000001),
        .port = port,
        .reuse_address = false,
    }) catch |err| switch (err) {
        error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    var occupied = true;
    defer {
        if (occupied) occupier.close();
    }

    var server = try Server.init(std.testing.io, std.testing.allocator, .{ .port = port });
    defer server.deinit();
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(server.isBound());
        server.tick();
        try std.testing.expect(server.isBound());
    } else {
        try std.testing.expect(!server.isBound());
        server.tick();
        try std.testing.expect(!server.isBound());
    }

    occupier.close();
    occupied = false;
    server.next_bind_attempt_ms = 0;
    server.tick();
    try std.testing.expect(server.isBound());
}

test "RakNet pong decoding accepts the responder's answer and nothing else" {
    var ping_buffer: [ping_size]u8 = undefined;
    const ping = encodePing(&ping_buffer, 0x1234, 5, false);
    var pong_buffer: [pong_payload_size]u8 = undefined;
    const pong = buildPong(.{ .server_data = .{ .server_name = "motd-query", .level_name = "query" } }, ping, &pong_buffer).?;

    const decoded = decodePong(pong).?;
    try std.testing.expectEqual(@as(i64, 0x1234), decoded.time);
    try std.testing.expectEqual(pong.len, decoded.bytes);
    try std.testing.expect(std.mem.startsWith(u8, decoded.motd, "MCPE;motd-query;"));

    try std.testing.expect(decodePong(ping) == null);
    var wrong_magic: [pong_payload_size]u8 = undefined;
    @memcpy(wrong_magic[0..pong.len], pong);
    wrong_magic[17] = 0x42;
    try std.testing.expect(decodePong(wrong_magic[0..pong.len]) == null);
    try std.testing.expect(decodePong(pong[0 .. pong.len - 1]) == null);
}

test "RakNet query reaches a live responder" {
    const port: u16 = 19939;
    var server = try Server.init(std.testing.io, std.testing.allocator, .{ .port = port, .server_data = .{ .server_name = "query-smoke", .level_name = "query" } });
    defer server.deinit();
    try std.testing.expect(server.isBound());

    var pending = Query.open(std.testing.io, std.mem.nativeToBig(u32, 0x7f000001), port, 2_000) orelse return error.SkipZigTest;
    defer pending.deinit();

    var buffer: [pong_payload_size]u8 = undefined;
    var answer: ?Pong = null;
    var attempts: usize = 0;
    while (answer == null and attempts < 200) : (attempts += 1) {
        server.tick();
        answer = pending.poll(&buffer);
        try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    try std.testing.expect(answer != null);
    try std.testing.expect(std.mem.startsWith(u8, answer.?.motd, "MCPE;query-smoke;"));
    try std.testing.expect(answer.?.time != 0);
    try std.testing.expectEqual(@as(usize, 1), server.answeredCount());
}
