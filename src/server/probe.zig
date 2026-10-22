const std = @import("std");
const builtin = @import("builtin");
const udp = @import("../platform/udp.zig");

const discovery = @import("../discovery.zig");
const peer_mod = @import("../webrtc/peer.zig");
const identity_mod = @import("../identity/server.zig");
const sdp_identity = @import("../identity/sdp.zig");
const identity_verify = @import("../identity/verify.zig");
const log = @import("../log.zig");
const lan = @import("lan.zig");

pub const client_network_id: u64 = 0x0bad_f00d_cafe_babe;
const server_network_id: u64 = (lan.Config{}).network_id;
const discovery_port: u16 = (lan.Config{}).port;
pub const default_connection_id = "probe-0001";
const request_packet = [_]u8{ 0xc1, 0x01, 0x00, 0x00, 0x08, 0xa3 };
const request_wire = [_]u8{ 0x00, request_packet.len } ++ request_packet;
const probe_budget_ms: i64 = 20_000;
const discovery_retry_ms: i64 = 500;

pub const Error = error{
    SocketBindFailed,
    SendFailed,
    PeerSetupFailed,
    IdentityAssertionFailed,
    Canceled,
} || std.mem.Allocator.Error || discovery.Error || peer_mod.PeerError || lan.Error || identity_verify.PinStoreError;

pub const Report = struct {
    discovery_ok: bool = false,
    response_bytes: usize = 0,
    connect_response_ok: bool = false,
    answer_bytes: usize = 0,
    answer_verified: bool = false,
    pinned: bool = false,
    answer_has_candidates: bool = false,
    remote_candidates: usize = 0,
    local_candidates: usize = 0,
    connected: bool = false,
    echo_ok: bool = false,
    echo_bytes: usize = 0,
    failure: ?[]const u8 = null,
    pub fn passed(self: Report) bool {
        return self.signalingPassed() and self.answer_verified and self.connected and self.echo_ok;
    }

    pub fn signalingPassed(self: Report) bool {
        return self.discovery_ok and self.connect_response_ok;
    }
};

fn PinFirstContact(_: *anyopaque, _: []const u8, _: [32]u8) identity_verify.UnknownKey {
    return .pin_and_accept;
}

const client_peer_config: peer_mod.PeerConfig = .{
    .profile = .lan_trickle,
    .event_capacity = 128,
    .max_event_payload = 262144,
};

pub const Options = struct {
    start_server: bool = true,
    port: u16 = discovery_port,
    connection_id: []const u8 = default_connection_id,
    sign_offer: bool = true,
    hold_ms: i64 = 0,
    budget_ms: i64 = probe_budget_ms,
};

pub const DiscoverReport = struct {
    response_bytes: usize = 0,
    sender_id: u64 = 0,
    server_data: []u8 = &.{},

    pub fn deinit(self: *DiscoverReport, allocator: std.mem.Allocator) void {
        if (self.server_data.len != 0) allocator.free(self.server_data);
        self.* = undefined;
    }
};

pub fn discover(
    io: std.Io,
    allocator: std.mem.Allocator,
    address: u32,
    port: u16,
    budget_ms: i64,
) Error!DiscoverReport {
    var socket = try createClientSocket(io, 0);
    defer socket.close();
    {
        const frame = try discovery.encodeRequest(allocator, client_network_id);
        defer allocator.free(frame);
        try socket.send(.{ .port = std.mem.nativeToBig(u16, port), .addr = address }, frame);
    }

    var report = DiscoverReport{};
    const deadline = nowMs(io) + budget_ms;
    while (nowMs(io) < deadline) {
        if (receiveFrame(&socket, allocator)) |frame| {
            defer allocator.free(frame);
            var packet = discovery.decodePacket(allocator, frame) catch continue;
            defer packet.deinit(allocator);
            if (packet.kind != .response) continue;
            report.sender_id = packet.sender_id;
            report.response_bytes = packet.data.len;
            report.server_data = try allocator.dupe(u8, packet.data);
            return report;
        }
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    return report;
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, options: Options) Error!Report {
    var server: ?lan.Server = if (options.start_server) try lan.Server.init(io, allocator, .{}) else null;
    defer if (server) |*instance| instance.deinit();

    var socket = try createClientSocket(io, loopbackValue());
    defer socket.close();
    const server_address = loopbackAddress(options.port);

    var report = Report{};
    var native = peer_mod.NativePeerConnection.init(io, allocator, client_peer_config) catch |err| {
        std.log.warn("probe peer connection init failed: {s}", .{@errorName(err)});
        return error.PeerSetupFailed;
    };
    defer native.deinit();
    var client = try peer_mod.Peer.init(allocator, native.connectionSpi(), client_peer_config);
    defer client.deinit(allocator);
    var provider = identity_mod.Provider.init(io, .{});
    var pins = try identity_verify.PinStore.init(io, allocator, .{});
    defer pins.deinit();
    const tofu: identity_verify.ToFu = .{ .store = &pins, .on_unknown = PinFirstContact };

    var local_candidates: usize = 0;
    var remote_candidates: usize = 0;
    var candidate_buffer: [512]u8 = undefined;
    var offer_sent = false;
    var payload_sent = false;
    var failure: ?[]const u8 = null;

    {
        const frame = try discovery.encodeRequest(allocator, client_network_id);
        defer allocator.free(frame);
        try socket.send(server_address, frame);
    }

    var next_discovery_ms = nowMs(io) + discovery_retry_ms;
    const deadline = nowMs(io) + options.budget_ms;
    while (nowMs(io) < deadline) {
        if (!report.discovery_ok and nowMs(io) >= next_discovery_ms) {
            const frame = try discovery.encodeRequest(allocator, client_network_id);
            defer allocator.free(frame);
            try socket.send(server_address, frame);
            next_discovery_ms = nowMs(io) + discovery_retry_ms;
        }
        if (server) |*instance| instance.tick();

        while (receiveFrame(&socket, allocator)) |frame| {
            defer allocator.free(frame);
            var packet = discovery.decodePacket(allocator, frame) catch continue;
            defer packet.deinit(allocator);
            switch (packet.kind) {
                .response => {
                    report.discovery_ok = true;
                    report.response_bytes = packet.data.len;
                },
                .message => {
                    if (packet.recovered_bytes != 0) {
                        log.debug(
                            "probe recovered {d} bytes past an underdeclared signal length",
                            .{packet.recovered_bytes},
                        );
                    }
                    if (packet.recipient_id != client_network_id) continue;
                    var signal = discovery.Signal.parse(allocator, packet.data) catch continue;
                    defer signal.deinit(allocator);
                    switch (signal.kind) {
                        .connect_response => {
                            report.connect_response_ok = true;
                            report.answer_bytes = signal.data.len;
                            report.answer_has_candidates = std.mem.indexOf(u8, signal.data, "a=candidate:") != null;
                            var verified = identity_verify.verifyAnswer(io, allocator, signal.data, .{ .trust = .{ .tofu = tofu } }) catch |err| blk: {
                                failure = @errorName(err);
                                break :blk null;
                            };
                            if (verified) |*value| {
                                defer value.deinit(allocator);
                                report.answer_verified = true;
                                report.pinned = value.anchored;
                                client.acceptAnswer(.{ .kind = .answer, .sdp = value.clean_sdp }) catch |err| {
                                    failure = @errorName(err);
                                };
                            } else {
                                client.acceptAnswer(.{ .kind = .answer, .sdp = signal.data }) catch |err| {
                                    failure = @errorName(err);
                                };
                            }
                        },
                        .candidate_add => {
                            client.addRemoteCandidate(signal.data) catch continue;
                            remote_candidates += 1;
                        },
                        .connect_error => failure = "server replied CONNECTERROR",
                        .connect_request => {},
                    }
                },
                .request => {},
            }
        }

        if (report.discovery_ok and !offer_sent) {
            const raw_offer = client.startOffer() catch |err| {
                failure = @errorName(err);
                break;
            };
            const stripped = try sdp_identity.withoutCandidates(allocator, raw_offer.sdp);
            defer allocator.free(stripped);
            const signed_offer = if (options.sign_offer)
                provider.addToSdp(allocator, stripped) catch |err| {
                    std.log.warn("probe identity assertion failed: {s}", .{@errorName(err)});
                    return error.IdentityAssertionFailed;
                }
            else
                try allocator.dupe(u8, stripped);
            defer allocator.free(signed_offer);
            try sendSignal(allocator, &socket, server_address, options.connection_id, .connect_request, signed_offer);
            offer_sent = true;
        }

        if (offer_sent) {
            client.tick() catch |err| {
                if (client.stateOf() == .closed) failure = @errorName(err);
            };
            while (client.pollEvent()) |event| switch (event) {
                .binary => |message| {
                    if (std.mem.eql(u8, message.data, &request_wire) or framedReply(message.data) != null) {
                        report.echo_ok = true;
                        report.echo_bytes = message.data.len;
                    }
                },
                .failed => |err| failure = @errorName(err),
                .state_changed => |state| {
                    if (state == .failed) failure = "peer connection failed";
                },
                else => {},
            };
            if (client.stateOf() == .connected) report.connected = true;

            if (report.connected and !payload_sent) {
                client.send(.reliable, &request_wire) catch |err| {
                    failure = @errorName(err);
                };
                payload_sent = true;
            }

            while (true) {
                const candidate = (client.pollLocalCandidate(&candidate_buffer) catch break) orelse break;
                try sendCandidate(allocator, &socket, server_address, options.connection_id, candidate, &local_candidates);
            }
        }

        if (report.echo_ok or failure != null) break;
        try io.sleep(.fromMilliseconds(5), .awake);
    }

    if (options.hold_ms > 0 and report.connected and failure == null) {
        const hold_deadline = nowMs(io) + options.hold_ms;
        while (nowMs(io) < hold_deadline) {
            client.tick() catch {};
            while (client.pollEvent()) |_| {}
            try io.sleep(.fromMilliseconds(5), .awake);
        }
    }

    report.remote_candidates = remote_candidates;
    report.local_candidates = local_candidates;
    report.failure = failure;
    return report;
}

fn createClientSocket(io: std.Io, bind_address: u32) Error!udp.Socket {
    return udp.Socket.open(io, .{ .address = bind_address, .port = 0 }) catch return error.SocketBindFailed;
}

fn loopbackValue() u32 {
    return std.mem.nativeToBig(u32, 0x7f000001);
}

fn loopbackAddress(port: u16) udp.Address {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = loopbackValue() };
}

fn receiveFrame(socket: *const udp.Socket, allocator: std.mem.Allocator) ?[]u8 {
    var buffer: [65535]u8 = undefined;
    const datagram = (socket.receive(&buffer) catch return null) orelse return null;
    return allocator.dupe(u8, buffer[0..datagram.len]) catch null;
}

fn sendSignal(
    allocator: std.mem.Allocator,
    socket: *const udp.Socket,
    destination: udp.Address,
    connection_id: []const u8,
    kind: discovery.SignalType,
    data: []const u8,
) Error!void {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try (discovery.Signal{ .kind = kind, .connection_id = connection_id, .data = data }).write(&writer.writer);
    const frame = try discovery.encodeMessage(allocator, client_network_id, server_network_id, writer.written());
    defer allocator.free(frame);
    socket.send(destination, frame) catch return error.SendFailed;
}

fn sendCandidate(
    allocator: std.mem.Allocator,
    socket: *const udp.Socket,
    destination: udp.Address,
    connection_id: []const u8,
    candidate: []const u8,
    sent: *usize,
) Error!void {
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writer.print("{s} generation 0 network-id {d} network-cost 0", .{ candidate, sent.* });
    try sendSignal(allocator, socket, destination, connection_id, .candidate_add, writer.buffered());
    sent.* += 1;
}

fn framedReply(wire: []const u8) ?usize {
    if (wire.len < 3 or wire[0] != 0) return null;
    var value: u32 = 0;
    var index: usize = 1;
    var shift: u32 = 0;
    while (index < wire.len) : (index += 1) {
        value |= @as(u32, wire[index] & 0x7f) << @intCast(shift);
        if (wire[index] & 0x80 == 0) {
            index += 1;
            break;
        }
        shift += 7;
        if (shift >= 32) return null;
    }
    if (value != wire.len - index) return null;
    return value;
}

test "framed replies are length-checked" {
    try std.testing.expectEqual(@as(?usize, 6), framedReply(&request_wire));
    try std.testing.expectEqual(@as(?usize, 12), framedReply(&[_]u8{ 0x00, 0x0c, 0x8f, 0x01 } ++ [_]u8{0} ** 10));
    try std.testing.expect(framedReply(&[_]u8{ 0x01, 0x02, 0xaa, 0xbb }) == null);
    try std.testing.expect(framedReply(&[_]u8{ 0x00, 0xff, 0xaa }) == null);
    try std.testing.expect(framedReply(&[_]u8{ 0x00, 0x01 }) == null);
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toMilliseconds();
}

test "probe report distinguishes signaling from a full session" {
    const signaling_only = Report{ .discovery_ok = true, .connect_response_ok = true };
    try std.testing.expect(signaling_only.signalingPassed());
    try std.testing.expect(!signaling_only.passed());
    try std.testing.expect(!(Report{}).signalingPassed());
}

var concurrent_io_instance: std.Io.Threaded = undefined;

const ConcurrentProbe = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    port: u16,
    connection_id: []const u8,
    finished: *std.atomic.Value(usize),
    sign_offer: bool = true,
    report: Report = .{},
    failure: ?anyerror = null,

    fn main(self: *ConcurrentProbe) void {
        defer _ = self.finished.fetchAdd(1, .release);
        self.report = run(self.io, self.allocator, .{
            .start_server = false,
            .port = self.port,
            .connection_id = self.connection_id,
            .sign_offer = self.sign_offer,
        }) catch |err| {
            self.failure = err;
            return;
        };
    }
};

const CountingHandler = struct {
    server: ?*const lan.Server = null,
    calls: usize = 0,
    peak_connections: usize = 0,
    peak_players: usize = 0,

    fn handler(self: *CountingHandler) peer_mod.MessageHandler {
        return .{ .ctx = self, .on_message = onMessage };
    }

    fn onMessage(ctx: *anyopaque, session: *peer_mod.PeerHandle, kind: peer_mod.ChannelKind, message: []const u8) ?[]const u8 {
        _ = session;
        _ = kind;
        const self: *CountingHandler = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (self.server) |server| {
            self.peak_connections = @max(self.peak_connections, server.connectionCount());
            self.peak_players = @max(self.peak_players, server.playerCount());
        }
        return message;
    }
};

fn subtraction(measured: usize, baseline: usize) usize {
    return measured -| baseline;
}

fn processCpuMs() i64 {
    if (comptime builtin.os.tag != .linux) return 0;
    const usage = std.posix.getrusage(0);
    return usage.utime.sec * 1000 + @divTrunc(usage.utime.usec, 1000) +
        usage.stime.sec * 1000 + @divTrunc(usage.stime.usec, 1000);
}

const ProcessUsage = struct {
    rss_bytes: usize = 0,
    threads: usize = 0,
    fds: usize = 0,

    fn read(io: std.Io) ProcessUsage {
        var usage = ProcessUsage{};
        if (comptime builtin.os.tag != .linux) return usage;
        var status: [8192]u8 = undefined;
        const text = std.Io.Dir.readFile(.cwd(), io, "/proc/self/status", &status) catch status[0..0];
        if (statusValue(text, "VmRSS:")) |kb| usage.rss_bytes = kb * 1024;
        if (statusValue(text, "Threads:")) |threads| usage.threads = threads;
        if (std.Io.Dir.openDirAbsolute(io, "/proc/self/fd", .{ .iterate = true })) |dir| {
            defer dir.close(io);
            var it = dir.iterate();
            while (it.next(io) catch null) |entry| {
                if (entry.name.len != 0 and std.ascii.isDigit(entry.name[0])) usage.fds += 1;
            }
        } else |_| {}
        return usage;
    }
};

fn statusValue(text: []const u8, key: []const u8) ?usize {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        const rest = std.mem.trim(u8, line[key.len..], " \t");
        const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
        return std.fmt.parseInt(usize, rest[0..end], 10) catch null;
    }
    return null;
}

test "an established LAN session costs a bounded slice of memory" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    concurrent_io_instance = .init(std.heap.smp_allocator, .{});
    const io = concurrent_io_instance.io();

    const port: u16 = 19953;
    var counter = lan.CountingAllocator{ .child = std.heap.smp_allocator };
    const clients_len = 4;
    var counts = CountingHandler{};
    var server = try lan.Server.init(io, counter.allocator(), .{
        .port = port,
        .server_data = .{ .server_name = "capacity", .level_name = "capacity", .max_player_count = clients_len },
        .handler = counts.handler(),
    });
    counts.server = &server;
    defer server.deinit();
    if (!server.isBound()) return error.SkipZigTest;
    const baseline = counter.liveBytes();
    const process_baseline = ProcessUsage.read(io);
    const cpu_baseline = processCpuMs();

    var finished = std.atomic.Value(usize).init(0);
    var ids: [clients_len][16]u8 = undefined;
    var clients: [clients_len]ConcurrentProbe = undefined;
    var threads: [clients_len]std.Thread = undefined;
    for (&clients, 0..) |*client, index| {
        client.* = .{
            .io = io,
            .allocator = std.heap.smp_allocator,
            .port = port,
            .connection_id = try std.fmt.bufPrint(&ids[index], "capacity-{d:0>4}", .{index}),
            .finished = &finished,
            .sign_offer = false,
        };
        threads[index] = try std.Thread.spawn(.{}, ConcurrentProbe.main, .{client});
    }

    const deadline = nowMs(io) + probe_budget_ms;
    var established: usize = 0;
    var occupied: ?ProcessUsage = null;
    var admitted_cpu_ms: i64 = 0;
    while (nowMs(io) < deadline) {
        server.tick();
        established = @max(established, server.playerCount());
        if (established == clients_len and occupied == null) {
            occupied = ProcessUsage.read(io);
            admitted_cpu_ms = processCpuMs() - cpu_baseline;
        }
        if (finished.load(.acquire) == clients.len) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    for (&threads) |thread| thread.join();

    const drain_deadline = nowMs(io) + 2_000;
    while (server.connectionCount() != 0 and nowMs(io) < drain_deadline) {
        server.tick();
        try io.sleep(.fromMilliseconds(2), .awake);
    }

    try std.testing.expectEqual(clients_len, established);

    const per_session = (counter.liveBytes() - baseline) / clients_len;
    const connections = clients_len + 1;
    const process = occupied orelse ProcessUsage{};
    const threads_per = subtraction(process.threads, process_baseline.threads) / connections;
    const fds_per = subtraction(process.fds, process_baseline.fds) / connections;
    const rss_per = subtraction(process.rss_bytes, process_baseline.rss_bytes) / connections;
    const cpu_per = @divTrunc(admitted_cpu_ms, @as(i64, @intCast(connections)));
    const os_counters_note = if (comptime builtin.os.tag == .linux)
        ""
    else
        " (thread, descriptor, rss and cpu counters are Linux-only and read as zero here)";
    std.debug.print(
        "capacity: {d} bytes per established LAN session ({d} sessions); each connection costs {d} OS threads, {d} descriptors, {d} bytes of process rss and {d} ms of cpu to admit{s}\n",
        .{ per_session, clients_len, threads_per, fds_per, rss_per, cpu_per, os_counters_note },
    );
    if (comptime builtin.os.tag == .linux) {
        std.debug.print(
            "capacity: at {d} connections the process held {d} threads, {d} descriptors and {d} KiB rss\n",
            .{ connections, process.threads, process.fds, process.rss_bytes / 1024 },
        );
    }
    try std.testing.expect(per_session < 1024 * 1024);
}

test "two LAN clients hold two sessions at the same time" {
    // Windows SCTP never brings the data channels up; skip until upstream fixes `connect`.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    concurrent_io_instance = .init(std.heap.smp_allocator, .{});
    const io = concurrent_io_instance.io();
    const allocator = std.heap.smp_allocator;

    const port: u16 = 19940;
    var counts = CountingHandler{};
    var server = try lan.Server.init(io, allocator, .{
        .port = port,
        .server_data = .{ .server_name = "concurrent", .level_name = "concurrent", .max_player_count = 2 },
        .handler = counts.handler(),
    });
    counts.server = &server;
    defer server.deinit();
    if (!server.isBound()) return error.SkipZigTest;

    var finished = std.atomic.Value(usize).init(0);
    var clients = [_]ConcurrentProbe{
        .{ .io = io, .allocator = allocator, .port = port, .connection_id = "probe-0001", .finished = &finished, .sign_offer = false },
        .{ .io = io, .allocator = allocator, .port = port, .connection_id = "probe-0002", .finished = &finished },
    };
    var threads: [clients.len]std.Thread = undefined;
    for (&clients, 0..) |*client, index| {
        threads[index] = try std.Thread.spawn(.{}, ConcurrentProbe.main, .{client});
    }

    const deadline = nowMs(io) + probe_budget_ms;
    var peak_connections: usize = 0;
    var peak_players: usize = 0;
    while (nowMs(io) < deadline) {
        server.tick();
        peak_connections = @max(peak_connections, server.connectionCount());
        peak_players = @max(peak_players, server.playerCount());
        if (finished.load(.acquire) == clients.len) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    for (&threads) |thread| thread.join();

    const drain_deadline = nowMs(io) + 2_000;
    while (server.connectionCount() != 0 and nowMs(io) < drain_deadline) {
        server.tick();
        try io.sleep(.fromMilliseconds(2), .awake);
    }

    try std.testing.expectEqual(@as(?anyerror, null), clients[0].failure);
    try std.testing.expectEqual(@as(?anyerror, null), clients[1].failure);
    try std.testing.expect(clients[0].report.passed());
    try std.testing.expect(clients[1].report.passed());
    try std.testing.expect(clients[0].report.answer_verified);
    try std.testing.expect(clients[1].report.answer_verified);
    try std.testing.expect(clients[0].report.pinned);
    try std.testing.expectEqual(clients.len, peak_connections);
    try std.testing.expectEqual(clients.len, peak_players);

    try std.testing.expectEqual(clients.len, counts.calls);
    try std.testing.expect(counts.peak_connections >= 1);
    try std.testing.expect(counts.peak_players <= counts.peak_connections);
}
