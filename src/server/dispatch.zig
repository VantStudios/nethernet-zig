const std = @import("std");
const framing = @import("../transport/framing.zig");
const peer_mod = @import("../webrtc/peer.zig");

pub fn openFor(handler: ?peer_mod.MessageHandler, session: *peer_mod.PeerHandle) void {
    const installed = handler orelse return;
    if (installed.on_open) |hook| hook(installed.ctx, session);
}

pub fn closeFor(handler: ?peer_mod.MessageHandler, session: *peer_mod.PeerHandle) void {
    const installed = handler orelse return;
    if (installed.on_close) |hook| hook(installed.ctx, session);
}

pub fn replyFor(
    handler: ?peer_mod.MessageHandler,
    session: *peer_mod.PeerHandle,
    kind: peer_mod.ChannelKind,
    message: []const u8,
    echo: bool,
) ?[]const u8 {
    if (handler) |installed| return installed.on_message(installed.ctx, session, kind, message);
    return if (echo) message else null;
}

pub fn sendPacket(
    scratch: framing.Scratch,
    max_message_size: usize,
    session: *peer_mod.PeerHandle,
    kind: peer_mod.ChannelKind,
    label: []const u8,
    packet: []const u8,
) framing.FramingError!void {
    const Sender = struct {
        session: *peer_mod.PeerHandle,
        kind: peer_mod.ChannelKind,
        label: []const u8,

        fn onSegment(ctx: *anyopaque, bytes: []const u8) framing.FramingError!void {
            const sender: *@This() = @ptrCast(@alignCast(ctx));
            sender.session.send(sender.kind, bytes) catch |err| {
                std.log.err("{s} send failed: {s}", .{ sender.label, @errorName(err) });
                return error.QueueFull;
            };
        }
    };

    const channel: framing.Channel = switch (kind) {
        .reliable => .reliable,
        .unreliable => .unreliable,
    };
    var sender = Sender{ .session = session, .kind = kind, .label = label };

    try framing.encodeMessage(packet, max_message_size, channel, scratch, .{
        .ctx = &sender,
        .on_segment = Sender.onSegment,
    });
}

const TestSink = struct {
    len: usize = 0,
    calls: usize = 0,
    opened: usize = 0,
    closed: usize = 0,
    last_id: u64 = 0,

    fn handler(self: *TestSink) peer_mod.MessageHandler {
        return .{ .ctx = self, .on_open = onOpen, .on_message = onMessage, .on_close = onClose };
    }

    fn onOpen(ctx: *anyopaque, session: *peer_mod.PeerHandle) void {
        const self: *TestSink = @ptrCast(@alignCast(ctx));
        self.opened += 1;
        self.last_id = session.id;
        session.user_data = self;
    }

    fn onClose(ctx: *anyopaque, session: *peer_mod.PeerHandle) void {
        const self: *TestSink = @ptrCast(@alignCast(ctx));
        self.closed += 1;
        _ = session;
    }

    fn onMessage(ctx: *anyopaque, session: *peer_mod.PeerHandle, kind: peer_mod.ChannelKind, message: []const u8) ?[]const u8 {
        const self: *TestSink = @ptrCast(@alignCast(ctx));
        _ = kind;
        self.calls += 1;
        self.len = message.len;
        self.last_id = session.id;
        return message;
    }
};

const GrowingScratch = struct {
    allocator: std.mem.Allocator,
    buffer: []u8 = &.{},
    grows: usize = 0,

    fn deinit(self: *GrowingScratch) void {
        self.allocator.free(self.buffer);
    }

    fn scratch(self: *GrowingScratch) framing.Scratch {
        return .{ .ctx = self, .ensure = ensure };
    }

    fn ensure(ctx: *anyopaque, needed: usize) framing.FramingError![]u8 {
        const self: *GrowingScratch = @ptrCast(@alignCast(ctx));
        if (self.buffer.len >= needed) return self.buffer;
        const grown = try self.allocator.alloc(u8, @max(needed, self.buffer.len *| 2));
        self.allocator.free(self.buffer);
        self.buffer = grown;
        self.grows += 1;
        return self.buffer;
    }
};

test "a packet larger than the scratch is segmented as the scratch grows" {
    const allocator = std.testing.allocator;
    var backend = peer_mod.MockPeerConnection{};
    var reliable = peer_mod.MockChannel{ .opened = true };
    var unreliable = peer_mod.MockChannel{ .opened = true };
    var connection = try peer_mod.Peer.init(allocator, backend.connection(), .{ .profile = .http_full_ice });
    defer connection.deinit(allocator);
    _ = try connection.startOffer();
    try connection.acceptAnswer(.{ .kind = .answer, .sdp = "answer" });
    try connection.attachChannel(.reliable, reliable.channel());
    try connection.attachChannel(.unreliable, unreliable.channel());
    reliable.push(.opened);
    unreliable.push(.opened);
    backend.push(.{ .state_changed = .connecting });
    try connection.tick();
    try std.testing.expectEqual(peer_mod.PeerState.connected, connection.stateOf());

    var session = peer_mod.PeerHandle{ .id = 11, .peer = &connection };
    var grower = GrowingScratch{ .allocator = allocator };
    defer grower.deinit();

    var payload: [5000]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    try sendPacket(grower.scratch(), 1024, &session, .reliable, "scratch test", &payload);

    try std.testing.expect(grower.grows > 0);
    try std.testing.expectEqual(payload.len + 5, reliable.sent_count);
    try std.testing.expectEqual(@as(usize, 1024), grower.buffer.len);
}

test "a handler answers and an absent one falls back to the echo" {
    var sink = TestSink{};
    var peer: peer_mod.Peer = undefined;
    var session = peer_mod.PeerHandle{ .id = 7, .peer = &peer };
    const message = "nethernet-zig-probe";

    openFor(sink.handler(), &session);
    try std.testing.expectEqual(@as(usize, 1), sink.opened);
    try std.testing.expectEqual(&sink, @as(*TestSink, @ptrCast(@alignCast(session.user_data.?))));

    try std.testing.expectEqualStrings(message, replyFor(sink.handler(), &session, .reliable, message, false).?);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqual(message.len, sink.len);
    try std.testing.expectEqual(@as(u64, 7), sink.last_id);

    closeFor(sink.handler(), &session);
    try std.testing.expectEqual(@as(usize, 1), sink.closed);

    try std.testing.expect(replyFor(null, &session, .reliable, message, false) == null);
    try std.testing.expectEqualStrings(message, replyFor(null, &session, .reliable, message, true).?);

    openFor(null, &session);
    closeFor(null, &session);
}
