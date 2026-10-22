const std = @import("std");
const nethernet = @import("nethernet");

pub const std_options: std.Options = nethernet.log.options;

const default_port: u16 = 31955;
const default_sessions: usize = 10;
const default_hold_ms: i64 = 300_000;
const default_attempts: usize = 4;
const attempt_budget_ms: i64 = 30_000;
const connect_budget_ms: i64 = 30_000;

fn logLine(comptime fmt: []const u8, args: anytype) void {
    if (comptime @import("builtin").os.tag != .linux) return std.debug.print(fmt, args);
    var buffer: [512]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, fmt ++ "\n", args) catch return;
    _ = std.posix.system.write(2, text.ptr, text.len);
}

const Client = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    port: u16,
    hold_ms: i64,
    prefix: u32,
    index: usize,
    id_buffer: [48]u8 = undefined,
    id_len: usize = 0,
    report: nethernet.probe.Report = .{},
    failure: ?anyerror = null,

    fn main(self: *Client) void {
        var attempt: usize = 0;
        while (attempt < default_attempts) : (attempt += 1) {
            const id = std.fmt.bufPrint(
                &self.id_buffer,
                "bench-{x:0>8}-{d:0>4}-{d}",
                .{ self.prefix, self.index, attempt },
            ) catch unreachable;
            self.id_len = id.len;
            self.report = nethernet.probe.run(self.io, self.gpa, .{
                .start_server = false,
                .port = self.port,
                .connection_id = self.id_buffer[0..self.id_len],
                .sign_offer = false,
                .hold_ms = self.hold_ms,
                .budget_ms = attempt_budget_ms,
            }) catch |err| {
                logLine("bench session attempt={d} id={s} error={s}", .{ attempt, self.id_buffer[0..self.id_len], @errorName(err) });
                if (attempt + 1 == default_attempts) self.failure = err;
                continue;
            };
            if (self.report.connected) {
                logLine("bench session established: {s}", .{self.id_buffer[0..self.id_len]});
                return;
            }
            logLine(
                "bench session attempt={d} not established: reason={s} disc={} resp={} cand={} remote={d} local={d} connected={}",
                .{
                    attempt,
                    self.report.failure orelse "budget-expired",
                    self.report.discovery_ok,
                    self.report.connect_response_ok,
                    self.report.answer_has_candidates,
                    self.report.remote_candidates,
                    self.report.local_candidates,
                    self.report.connected,
                },
            );
            if (attempt + 1 == default_attempts) self.failure = error.NotEstablished;
        }
    }
};

const HttpSession = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    url: []const u8,
    network_id: []const u8,
    hold_ms: i64,
    pins: *nethernet.identity.PinStore,
    connected: bool = false,
    failure: ?anyerror = null,

    fn acceptUnknown(_: *anyopaque, _: []const u8, _: [std.crypto.hash.sha2.Sha256.digest_length]u8) nethernet.identity.UnknownKey {
        return .accept_once;
    }

    fn main(self: *HttpSession) void {
        self.run() catch |err| {
            self.failure = err;
            logLine("bench http {s}: {s}", .{ self.network_id, @errorName(err) });
        };
    }

    fn run(self: *HttpSession) !void {
        var transport = try nethernet.signaling.ClientTransport.init(self.io, self.gpa, self.url);
        defer transport.deinit();

        var joiner = nethernet.signaling.Joiner.init(self.io, self.gpa, transport.transport(), "", .{
            .trust = .{ .tofu = .{ .store = self.pins, .on_unknown = acceptUnknown, .ctx = self } },
            .allow_key_change = true,
        });
        var info = try joiner.capability();
        defer joiner.deinitInfo(self.gpa, &info);

        const native = try nethernet.web_rtc.NativePeerConnection.init(self.io, self.gpa, .{ .profile = .http_full_ice });
        defer native.deinit();
        var peer = try nethernet.web_rtc.Peer.init(self.gpa, native.connectionSpi(), .{ .profile = .http_full_ice });
        defer peer.deinit(self.gpa);

        var provider = nethernet.identity.ServerProvider.init(self.io, .{});
        const offer = try peer.startOffer();
        const signed_offer = try provider.addToSdp(self.gpa, offer.sdp);
        defer self.gpa.free(signed_offer);

        var submission = try joiner.submitOffer(self.network_id, signed_offer);
        defer submission.deinit(self.gpa);
        try peer.acceptAnswer(.{ .kind = .answer, .sdp = submission.sdp });

        const connect_deadline = std.Io.Clock.real.now(self.io).toMilliseconds() + connect_budget_ms;
        while (peer.stateOf() != .connected) {
            if (std.Io.Clock.real.now(self.io).toMilliseconds() > connect_deadline) return error.NotConnected;
            try self.pump(&peer);
            try self.io.sleep(.fromMilliseconds(5), .awake);
        }
        self.connected = true;

        const hold_deadline = std.Io.Clock.real.now(self.io).toMilliseconds() + self.hold_ms;
        while (std.Io.Clock.real.now(self.io).toMilliseconds() < hold_deadline) {
            try self.pump(&peer);
            try self.io.sleep(.fromMilliseconds(5), .awake);
        }
    }

    fn pump(self: *HttpSession, peer: *nethernet.web_rtc.Peer) !void {
        _ = self;
        try peer.tick();
        while (peer.pollEvent()) |event| switch (event) {
            .failed => return error.PeerFailed,
            else => {},
        };
    }
};

fn runServer(init: std.process.Init, port: u16, max_sessions: usize) !void {
    var server = try nethernet.server.LanServer.init(init.io, init.gpa, .{
        .port = port,
        .max_pending_connections = max_sessions,
        .max_datagrams_per_tick = 1024,
        .discovery_replies_per_second = 0,
        .idle_timeout_ms = 600_000,
        .negotiation_timeout_ms = 120_000,
        .server_data = .{
            .server_name = "nethernet-zig bench",
            .level_name = "bench",
            .game_type = .creative,
            .max_player_count = @intCast(@min(max_sessions, std.math.maxInt(i32))),
        },
    });
    defer server.deinit();
    std.debug.print("bench server: port={d} max={d} bound={}\n", .{ port, max_sessions, server.isBound() });

    var last_report: i64 = 0;
    while (true) {
        server.tick();
        const now = std.Io.Clock.real.now(init.io).toMilliseconds();
        if (now - last_report >= 500) {
            last_report = now;
            std.debug.print("bench server: players={d} connections={d}\n", .{ server.playerCount(), server.connectionCount() });
        }
        try init.io.sleep(.fromMilliseconds(5), .awake);
    }
}

fn runClient(init: std.process.Init, port: u16, sessions: usize, hold_ms: i64, stagger_ms: usize) !void {
    const clients = try init.gpa.alloc(Client, sessions);
    defer init.gpa.free(clients);
    const threads = try init.gpa.alloc(std.Thread, sessions);
    defer init.gpa.free(threads);

    var prefix_bytes: [4]u8 = undefined;
    init.io.random(&prefix_bytes);
    const prefix = std.mem.readInt(u32, &prefix_bytes, .little);

    for (clients, 0..) |*client, index| {
        client.* = .{
            .io = init.io,
            .gpa = init.gpa,
            .port = port,
            .hold_ms = hold_ms,
            .prefix = prefix,
            .index = index,
        };
        threads[index] = std.Thread.spawn(.{}, Client.main, .{client}) catch |err| {
            std.debug.print("bench client: spawn failed at session {d}: {s}\n", .{ index, @errorName(err) });
            std.process.exit(2);
        };
        if (index + 1 < sessions) try init.io.sleep(.fromMilliseconds(@intCast(stagger_ms)), .awake);
    }
    for (threads) |thread| thread.join();

    var established: usize = 0;
    var passed: usize = 0;
    var failed: usize = 0;
    var shown: usize = 0;
    for (clients, 0..) |client, index| {
        if (client.failure) |err| {
            failed += 1;
            if (shown < 3) {
                shown += 1;
                logLine("bench client: session {d} error: {s}", .{ index, @errorName(err) });
            }
            continue;
        }
        if (client.report.connected) {
            established += 1;
        } else if (client.report.failure) |reason| {
            if (shown < 3) {
                shown += 1;
                logLine("bench client: session {d} not established: {s}", .{ index, reason });
            }
        }
        if (client.report.passed()) passed += 1;
    }
    logLine(
        "bench client: sessions={d} established={d} passed={d} failed={d}",
        .{ sessions, established, passed, failed },
    );
}

fn runHttpClient(init: std.process.Init, url: []const u8, sessions: usize, hold_ms: i64, stagger_ms: usize, tag: u32) !void {
    var pin_path_buffer: [96]u8 = undefined;
    const pin_path = std.fmt.bufPrint(
        &pin_path_buffer,
        "/tmp/nethernet-bench/http-pins-{d}.json",
        .{tag},
    ) catch return error.NameTooLong;
    var pins = try nethernet.identity.PinStore.init(init.io, init.gpa, .{ .path = pin_path });
    defer pins.deinit();
    pins.load() catch |err| logLine("bench http: no pins at {s}: {s}", .{ pin_path, @errorName(err) });

    const clients = try init.gpa.alloc(HttpSession, sessions);
    defer init.gpa.free(clients);
    const threads = try init.gpa.alloc(std.Thread, sessions);
    defer init.gpa.free(threads);
    const ids = try init.gpa.alloc([48]u8, sessions);
    defer init.gpa.free(ids);

    for (clients, 0..) |*client, index| {
        const id = try std.fmt.bufPrint(&ids[index], "load-{x:0>8}-{d:0>4}", .{ tag, index });
        client.* = .{
            .io = init.io,
            .gpa = init.gpa,
            .url = url,
            .network_id = id,
            .hold_ms = hold_ms,
            .pins = &pins,
        };
        threads[index] = std.Thread.spawn(.{}, HttpSession.main, .{client}) catch |err| {
            std.debug.print("bench http: spawn failed at session {d}: {s}\n", .{ index, @errorName(err) });
            std.process.exit(2);
        };
        if (index + 1 < sessions) try init.io.sleep(.fromMilliseconds(@intCast(stagger_ms)), .awake);
    }
    for (threads) |thread| thread.join();

    var established: usize = 0;
    var failed: usize = 0;
    var shown: usize = 0;
    for (clients) |client| {
        if (client.failure) |err| {
            failed += 1;
            if (shown < 3) {
                shown += 1;
                logLine("bench http: session error: {s}", .{@errorName(err)});
            }
            continue;
        }
        if (client.connected) established += 1;
    }
    logLine("bench http: sessions={d} established={d} failed={d}", .{ sessions, established, failed });
}

fn parseU16(text: ?[]const u8, fallback: u16) u16 {
    return std.fmt.parseInt(u16, text orelse return fallback, 10) catch fallback;
}

fn parseUsize(text: ?[]const u8, fallback: usize) usize {
    return std.fmt.parseInt(usize, text orelse return fallback, 10) catch fallback;
}

fn parseI64(text: ?[]const u8, fallback: i64) i64 {
    return std.fmt.parseInt(i64, text orelse return fallback, 10) catch fallback;
}

fn parseU32(text: ?[]const u8, fallback: u32) u32 {
    return std.fmt.parseInt(u32, text orelse return fallback, 10) catch fallback;
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next() orelse "";
    if (std.mem.eql(u8, mode, "server")) {
        var port = default_port;
        var max_sessions: usize = 1000;
        while (args.next()) |flag| {
            if (std.mem.eql(u8, flag, "--port")) {
                port = parseU16(args.next(), port);
            } else if (std.mem.eql(u8, flag, "--max")) {
                max_sessions = parseUsize(args.next(), max_sessions);
            }
        }
        return runServer(init, port, max_sessions);
    }
    if (std.mem.eql(u8, mode, "http-client")) {
        var url: []const u8 = "http://127.0.0.1:19132";
        var sessions = default_sessions;
        var hold_ms = default_hold_ms;
        var stagger_ms: usize = 50;
        var tag: u32 = 0;
        while (args.next()) |flag| {
            if (std.mem.eql(u8, flag, "--url")) {
                url = args.next() orelse url;
            } else if (std.mem.eql(u8, flag, "--sessions")) {
                sessions = parseUsize(args.next(), sessions);
            } else if (std.mem.eql(u8, flag, "--hold-ms")) {
                hold_ms = parseI64(args.next(), hold_ms);
            } else if (std.mem.eql(u8, flag, "--stagger-ms")) {
                stagger_ms = parseUsize(args.next(), stagger_ms);
            } else if (std.mem.eql(u8, flag, "--tag")) {
                tag = parseU32(args.next(), tag);
            }
        }
        return runHttpClient(init, url, sessions, hold_ms, stagger_ms, tag);
    }
    if (std.mem.eql(u8, mode, "client")) {
        var port = default_port;
        var sessions = default_sessions;
        var hold_ms = default_hold_ms;
        var stagger_ms: usize = 50;
        while (args.next()) |flag| {
            if (std.mem.eql(u8, flag, "--port")) {
                port = parseU16(args.next(), port);
            } else if (std.mem.eql(u8, flag, "--sessions")) {
                sessions = parseUsize(args.next(), sessions);
            } else if (std.mem.eql(u8, flag, "--hold-ms")) {
                hold_ms = parseI64(args.next(), hold_ms);
            } else if (std.mem.eql(u8, flag, "--stagger-ms")) {
                stagger_ms = parseUsize(args.next(), stagger_ms);
            }
        }
        return runClient(init, port, sessions, hold_ms, stagger_ms);
    }
    std.debug.print(
        "usage:\n  bench server --port {d} --max <sessions>\n  bench client --port {d} --sessions <n> --hold-ms <ms> --stagger-ms <ms>\n  bench http-client --url <http://host:port> --sessions <n> --hold-ms <ms> --stagger-ms <ms> --tag <n>\n",
        .{ default_port, default_port },
    );
}
