const std = @import("std");

pub const FramingError = error{
    SegmentTooShort,
    InvalidCountdown,
    FragmentationNotAllowed,
    PayloadTooLarge,
    EmptyPayload,
    QueueFull,
    InvalidLength,
    OutOfMemory,
};

pub const FramingProfile = enum {
    mojang_http,
    reverse_engineered_10000,
    negotiated,
};

pub const EmitFn = *const fn (ctx: *anyopaque, header: u8, payload: []const u8) FramingError!void;

pub fn segment(
    payload: []const u8,
    max_message_size: usize,
    reliable: bool,
    emit: EmitFn,
    ctx: *anyopaque,
) FramingError!void {
    if (payload.len == 0) return error.EmptyPayload;
    if (max_message_size < 2) return error.PayloadTooLarge;

    const max_segment_payload = max_message_size - 1;
    const fragment_count = (payload.len + max_segment_payload - 1) / max_segment_payload;
    if (!reliable and fragment_count != 1) return error.FragmentationNotAllowed;
    if (fragment_count > max_segments) return error.PayloadTooLarge;

    var offset: usize = 0;
    var remaining: u8 = @intCast(fragment_count - 1);
    while (true) {
        const end = @min(offset + max_segment_payload, payload.len);
        try emit(ctx, remaining, payload[offset..end]);
        if (end == payload.len) break;
        offset = end;
        remaining -= 1;
    }
}

pub const Assembler = struct {
    buffer: []u8,
    max_payload: usize,
    reliable: bool,
    assembling: bool = false,
    expected_remaining: u8 = 0,
    used: usize = 0,

    pub fn init(buffer: []u8, max_payload: usize, reliable: bool) Assembler {
        return .{ .buffer = buffer, .max_payload = @min(max_payload, buffer.len), .reliable = reliable };
    }

    pub fn reset(self: *Assembler) void {
        self.assembling = false;
        self.expected_remaining = 0;
        self.used = 0;
    }

    pub fn push(self: *Assembler, wire: []const u8) FramingError!?[]u8 {
        if (wire.len < 2) return error.SegmentTooShort;
        return self.pushParts(wire[0], wire[1..]);
    }

    pub fn pushParts(self: *Assembler, remaining: u8, payload: []const u8) FramingError!?[]u8 {
        if (payload.len == 0) {
            self.reset();
            return error.SegmentTooShort;
        }
        if (!self.reliable and remaining != 0) {
            self.reset();
            return error.FragmentationNotAllowed;
        }

        if (!self.assembling) {
            if (remaining != 0) {
                self.assembling = true;
                self.expected_remaining = remaining;
                self.used = 0;
            }
        } else {
            if (remaining != self.expected_remaining - 1) {
                self.reset();
                return error.InvalidCountdown;
            }
            self.expected_remaining = remaining;
        }

        if (self.used + payload.len > self.max_payload) {
            self.reset();
            return error.PayloadTooLarge;
        }
        @memcpy(self.buffer[self.used .. self.used + payload.len], payload);
        self.used += payload.len;

        if (remaining == 0) {
            const result = self.buffer[0..self.used];
            self.reset();
            return result;
        }
        return null;
    }
};

pub const max_segments: usize = 256;

pub const default_max_packet_bytes: usize = 8 * 1024 * 1024;

pub const default_message_size: u32 = 262144;

pub const min_message_size: u32 = 1024;

/// RFC 8841: the limit a peer must assume when the attribute is absent. It is not
/// this side's ceiling, so assuming the ceiling makes the two ends disagree.
pub const default_peer_message_size: u32 = 64 * 1024;

pub fn negotiatedMaxMessageSize(advertised: ?u32, ceiling: u32) u32 {
    const value = advertised orelse default_peer_message_size;
    const effective = if (value < min_message_size) default_peer_message_size else value;
    return @min(effective, ceiling);
}

test "the peer's advertised segment limit is honored up to our ceiling" {
    try std.testing.expectEqual(@as(u32, 65536), negotiatedMaxMessageSize(null, 262144));
    try std.testing.expectEqual(@as(u32, 65536), negotiatedMaxMessageSize(65536, 262144));
    try std.testing.expectEqual(@as(u32, 262144), negotiatedMaxMessageSize(1_048_576, 262144));
    try std.testing.expectEqual(@as(u32, 65536), negotiatedMaxMessageSize(8, 262144));
    try std.testing.expectEqual(@as(u32, 4096), negotiatedMaxMessageSize(null, 4096));
    try std.testing.expectEqual(@as(u32, 32768), negotiatedMaxMessageSize(32768, 262144));
}

pub const Sink = struct {
    ctx: *anyopaque,
    on_message: *const fn (ctx: *anyopaque, message: []const u8) FramingError!void,
};

pub const SegmentSink = struct {
    ctx: *anyopaque,
    on_segment: *const fn (ctx: *anyopaque, bytes: []const u8) FramingError!void,
};

pub const Channel = enum { reliable, unreliable };

pub const Scratch = struct {
    ctx: *anyopaque,
    ensure: *const fn (*anyopaque, usize) FramingError![]u8,
};

pub const FixedScratch = struct {
    buffer: []u8,

    pub fn scratch(self: *FixedScratch) Scratch {
        return .{ .ctx = self, .ensure = ensure };
    }

    fn ensure(ctx: *anyopaque, needed: usize) FramingError![]u8 {
        const self: *FixedScratch = @ptrCast(@alignCast(ctx));
        if (self.buffer.len < needed) return error.PayloadTooLarge;
        return self.buffer;
    }
};

// One message is several segments of `[countdown: u8][payload]`; the SCTP message
// boundary delimits each payload, so there is no length prefix, and every segment but
// the last is filled to `max_message_size - 1`. Mojang: NetherNetOnboardingGuide §6.1.
pub fn encodeMessage(
    packet: []const u8,
    max_message_size: usize,
    channel: Channel,
    scratch: Scratch,
    sink: SegmentSink,
) FramingError!void {
    const Emitter = struct {
        scratch: Scratch,
        sink: SegmentSink,

        fn emit(ctx_ptr: *anyopaque, header: u8, payload: []const u8) FramingError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            const buffer = try self.scratch.ensure(self.scratch.ctx, payload.len + 1);
            buffer[0] = header;
            @memcpy(buffer[1 .. 1 + payload.len], payload);
            return self.sink.on_segment(self.sink.ctx, buffer[0 .. 1 + payload.len]);
        }
    };

    var emitter = Emitter{ .scratch = scratch, .sink = sink };
    return segment(packet, max_message_size, channel == .reliable, Emitter.emit, &emitter);
}

pub const MessageAssembler = struct {
    allocator: std.mem.Allocator,
    max_message_size: usize,
    channel: Channel,
    max_packet_bytes: usize = default_max_packet_bytes,
    buffer: []u8 = &.{},
    assembling: bool = false,
    expected_remaining: u8 = 0,
    used: usize = 0,
    retained_bytes: usize = default_retained_bytes,

    pub const default_retained_bytes: usize = 64 * 1024;

    pub fn init(
        allocator: std.mem.Allocator,
        max_message_size: usize,
        channel: Channel,
        max_packet_bytes: usize,
    ) MessageAssembler {
        return .{
            .allocator = allocator,
            .max_message_size = max_message_size,
            .channel = channel,
            .max_packet_bytes = max_packet_bytes,
        };
    }

    pub fn deinit(self: *MessageAssembler) void {
        if (self.buffer.len > 0) self.allocator.free(self.buffer);
        self.buffer = &.{};
        self.used = 0;
    }

    pub fn reset(self: *MessageAssembler) void {
        self.assembling = false;
        self.expected_remaining = 0;
        self.used = 0;
    }

    pub fn feed(self: *MessageAssembler, data: []const u8, sink: Sink) FramingError!void {
        if (data.len < 2) {
            self.reset();
            return error.SegmentTooShort;
        }
        const countdown = data[0];
        const payload = data[1..];
        if (payload.len == 0) {
            self.reset();
            return error.EmptyPayload;
        }
        if (self.channel == .unreliable and countdown != 0) {
            self.reset();
            return error.FragmentationNotAllowed;
        }
        if (self.max_message_size >= 2 and payload.len > self.max_message_size - 1) {
            self.reset();
            return error.PayloadTooLarge;
        }
        if (self.assembling) {
            if (countdown != self.expected_remaining - 1) {
                self.reset();
                return error.InvalidCountdown;
            }
        } else if (countdown != 0) {
            self.assembling = true;
        }

        if (self.used + payload.len > self.max_packet_bytes) {
            self.reset();
            return error.PayloadTooLarge;
        }
        if (self.buffer.len < self.used + payload.len) {
            const needed = self.used + payload.len;
            const target = @min(self.max_packet_bytes, @max(self.buffer.len *| 2, needed));
            self.buffer = self.allocator.realloc(self.buffer, target) catch {
                self.reset();
                return error.OutOfMemory;
            };
        }
        @memcpy(self.buffer[self.used .. self.used + payload.len], payload);
        self.used += payload.len;

        if (countdown == 0) {
            const message_len = self.used;
            const message = self.buffer[0..message_len];
            self.reset();
            try sink.on_message(sink.ctx, message);
            self.trimRetained(message_len);
        } else {
            self.expected_remaining = countdown;
        }
    }

    fn trimRetained(self: *MessageAssembler, message_len: usize) void {
        if (self.buffer.len <= self.retained_bytes) return;
        const target = @min(message_len, self.retained_bytes);
        self.buffer = self.allocator.realloc(self.buffer, target) catch return;
    }

    pub fn retainedBytes(self: *const MessageAssembler) usize {
        return self.buffer.len;
    }
};

pub const Channels = struct {
    reliable: MessageAssembler,
    unreliable: MessageAssembler,

    pub fn init(
        allocator: std.mem.Allocator,
        max_message_size: usize,
        max_packet_bytes: usize,
    ) Channels {
        return .{
            .reliable = MessageAssembler.init(allocator, max_message_size, .reliable, max_packet_bytes),
            .unreliable = MessageAssembler.init(allocator, max_message_size, .unreliable, max_packet_bytes),
        };
    }

    pub fn deinit(self: *Channels) void {
        self.reliable.deinit();
        self.unreliable.deinit();
    }

    pub fn assembler(self: *Channels, channel: Channel) *MessageAssembler {
        return switch (channel) {
            .reliable => &self.reliable,
            .unreliable => &self.unreliable,
        };
    }

    pub fn feed(self: *Channels, channel: Channel, data: []const u8, sink: Sink) FramingError!void {
        return self.assembler(channel).feed(data, sink);
    }
};

const EmitContext = struct {
    assembler: *Assembler,
    completed_len: usize = 0,

    fn emit(ctx_ptr: *anyopaque, header: u8, payload: []const u8) FramingError!void {
        const ctx: *EmitContext = @ptrCast(@alignCast(ctx_ptr));
        const result = try ctx.assembler.pushParts(header, payload);
        if (result) |message| ctx.completed_len = message.len;
    }
};

test "segment emits descending countdown and assembler round trips" {
    var buffer: [20]u8 = undefined;
    var assembler = Assembler.init(&buffer, buffer.len, true);
    var ctx = EmitContext{ .assembler = &assembler };
    const payload = "abcdefghijklmnop";

    try segment(payload, 7, true, EmitContext.emit, &ctx);
    try std.testing.expectEqual(payload.len, ctx.completed_len);
    try std.testing.expectEqualStrings(payload, buffer[0..ctx.completed_len]);
}

test "unreliable rejects fragmentation" {
    var buffer: [32]u8 = undefined;
    var assembler = Assembler.init(&buffer, buffer.len, false);
    var ctx = EmitContext{ .assembler = &assembler };
    try std.testing.expectError(error.FragmentationNotAllowed, segment("12345678", 4, false, EmitContext.emit, &ctx));
}

test "assembler rejects countdown gaps and recovers" {
    var buffer: [32]u8 = undefined;
    var assembler = Assembler.init(&buffer, buffer.len, true);
    try std.testing.expectEqual(@as(?[]u8, null), try assembler.pushParts(2, "ab"));
    try std.testing.expectError(error.InvalidCountdown, assembler.pushParts(0, "cd"));
    try std.testing.expectEqualStrings("ok", (try assembler.pushParts(0, "ok")).?);
}

test "a message split into the full 256 segments round trips" {
    var packet: [max_segments]u8 = undefined;
    for (&packet, 0..) |*byte, index| byte.* = @truncate(index);
    var scratch: [2]u8 = undefined;

    var assembler = MessageAssembler.init(std.testing.allocator, 2, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};
    var relay = RelaySink{ .assembler = &assembler, .sink = sink.sink() };

    var fixed = FixedScratch{ .buffer = &scratch };
    try encodeMessage(&packet, 2, .reliable, fixed.scratch(), relay.segments());

    try std.testing.expectEqual(max_segments, relay.count);
    for (relay.headers, 0..) |header, index| {
        try std.testing.expectEqual(@as(u8, @intCast(max_segments - 1 - index)), header);
    }
    try std.testing.expectEqual(@as(usize, 2), relay.sizes[max_segments - 1]);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqual(packet.len, sink.len);
    try std.testing.expectEqual(std.hash.Fnv1a_64.hash(&packet), sink.hash);
}

test "a message that needs 257 segments is refused" {
    var packet: [max_segments + 1]u8 = undefined;
    @memset(&packet, 0x5a);
    var scratch: [2]u8 = undefined;
    var fixed = FixedScratch{ .buffer = &scratch };

    try std.testing.expectError(
        error.PayloadTooLarge,
        encodeMessage(&packet, 2, .reliable, fixed.scratch(), .{ .ctx = undefined, .on_segment = RelaySink.onSegment }),
    );
}

test "segment supports the 255-fragment countdown" {
    var buffer: [255]u8 = undefined;
    var assembler = Assembler.init(&buffer, buffer.len, true);
    var ctx = EmitContext{ .assembler = &assembler };
    var payload: [255]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index);

    try segment(&payload, 2, true, EmitContext.emit, &ctx);
    try std.testing.expectEqual(payload.len, ctx.completed_len);
    try std.testing.expectEqualSlices(u8, &payload, buffer[0..ctx.completed_len]);
}

const TestSink = struct {
    len: usize = 0,
    calls: usize = 0,
    hash: u64 = 0,
    first: u8 = 0,
    last: u8 = 0,

    fn sink(self: *TestSink) Sink {
        return .{ .ctx = self, .on_message = onMessage };
    }

    fn onMessage(ctx: *anyopaque, message: []const u8) FramingError!void {
        const self: *TestSink = @ptrCast(@alignCast(ctx));
        self.len = message.len;
        self.calls += 1;
        self.first = message[0];
        self.last = message[message.len - 1];
        self.hash = std.hash.Fnv1a_64.hash(message);
    }
};

const RelaySink = struct {
    assembler: *MessageAssembler,
    sink: Sink,
    headers: [max_segments]u8 = undefined,
    sizes: [max_segments]usize = undefined,
    count: usize = 0,

    fn segments(self: *RelaySink) SegmentSink {
        return .{ .ctx = self, .on_segment = onSegment };
    }

    fn onSegment(ctx: *anyopaque, bytes: []const u8) FramingError!void {
        const self: *RelaySink = @ptrCast(@alignCast(ctx));
        if (self.count == max_segments) {
            self.count += 1;
            return error.PayloadTooLarge;
        }
        self.headers[self.count] = bytes[0];
        self.sizes[self.count] = bytes.len;
        self.count += 1;
        return self.assembler.feed(bytes, self.sink);
    }
};

test "the captured retail pre-login bytes reassemble from one message" {
    const wire = [_]u8{ 0x00, 0x06, 0xc1, 0x01, 0x00, 0x00, 0x08, 0xa3 };
    var assembler = MessageAssembler.init(std.testing.allocator, 262144, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};

    try assembler.feed(&wire, sink.sink());

    // The `06` is the packet's own length prefix, not part of the framing.
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqual(@as(usize, 7), sink.len);
    try std.testing.expectEqual(@as(u8, 0x06), sink.first);
    try std.testing.expectEqual(@as(u8, 0xa3), sink.last);
    try std.testing.expect(!assembler.assembling);
}

test "a login split the way the retail client splits it reassembles" {
    const packet_len = 588046;
    const packet = try std.testing.allocator.alloc(u8, packet_len);
    defer std.testing.allocator.free(packet);
    for (packet, 0..) |*byte, index| byte.* = @truncate(index *% 251);

    const scratch = try std.testing.allocator.alloc(u8, 262144);
    defer std.testing.allocator.free(scratch);

    var assembler = MessageAssembler.init(std.testing.allocator, 262144, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};
    var relay = RelaySink{ .assembler = &assembler, .sink = sink.sink() };

    var fixed = FixedScratch{ .buffer = scratch };
    try encodeMessage(packet, 262144, .reliable, fixed.scratch(), relay.segments());

    try std.testing.expectEqual(@as(usize, 3), relay.count);
    try std.testing.expectEqual(@as(usize, 262144), relay.sizes[0]);
    try std.testing.expectEqual(@as(usize, 262144), relay.sizes[1]);
    try std.testing.expectEqual(@as(usize, 63761), relay.sizes[2]);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqual(packet_len, sink.len);
    try std.testing.expectEqual(std.hash.Fnv1a_64.hash(packet), sink.hash);
}

test "a message split across several segments round trips" {
    var packet: [600]u8 = undefined;
    for (&packet, 0..) |*byte, index| byte.* = @truncate(index);
    const scratch = try std.testing.allocator.alloc(u8, 100);
    defer std.testing.allocator.free(scratch);

    var assembler = MessageAssembler.init(std.testing.allocator, 100, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};
    var relay = RelaySink{ .assembler = &assembler, .sink = sink.sink() };

    var fixed = FixedScratch{ .buffer = scratch };
    try encodeMessage(&packet, 100, .reliable, fixed.scratch(), relay.segments());

    try std.testing.expectEqual(@as(usize, 7), relay.count);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqual(packet.len, sink.len);
    try std.testing.expectEqual(std.hash.Fnv1a_64.hash(&packet), sink.hash);
}

test "a fragmented message with a skipped countdown is rejected" {
    var assembler = MessageAssembler.init(std.testing.allocator, 262144, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};

    try assembler.feed(&[_]u8{ 0x02, 'a', 'b' }, sink.sink());
    try std.testing.expectEqual(@as(usize, 0), sink.calls);
    try std.testing.expectError(error.InvalidCountdown, assembler.feed(&[_]u8{ 0x00, 'c', 'd' }, sink.sink()));
    try std.testing.expectEqual(@as(usize, 0), sink.calls);
}

test "unreliable channels refuse a fragmented message in both directions" {
    var packet: [4000]u8 = undefined;
    for (&packet, 0..) |*byte, index| byte.* = @truncate(index);
    const scratch = try std.testing.allocator.alloc(u8, 262144);
    defer std.testing.allocator.free(scratch);

    var assembler = MessageAssembler.init(std.testing.allocator, 64, .unreliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};
    var fixed = FixedScratch{ .buffer = scratch };

    try std.testing.expectError(
        error.FragmentationNotAllowed,
        encodeMessage(&packet, 64, .unreliable, fixed.scratch(), .{ .ctx = undefined, .on_segment = RelaySink.onSegment }),
    );
    const fragment = [_]u8{ 0x02, 0x8e, 0xf2, 0x23, 0x01, 0x00, 0x00, 0x08, 0xa3 };
    try std.testing.expectError(error.FragmentationNotAllowed, assembler.feed(&fragment, sink.sink()));
    try std.testing.expectEqual(@as(usize, 0), sink.calls);
}

test "a segment larger than the announced limit is refused before allocating" {
    var assembler = MessageAssembler.init(std.testing.allocator, 8, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};

    try assembler.feed(&[_]u8{ 1, 'a', 'b', 'c', 'd', 'e', 'f', 'g' }, sink.sink());
    try std.testing.expectEqual(@as(usize, 7), assembler.used);

    const retained = assembler.retainedBytes();
    try std.testing.expectError(error.PayloadTooLarge, assembler.feed(&[_]u8{ 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' }, sink.sink()));
    try std.testing.expectEqual(retained, assembler.retainedBytes());
    try std.testing.expectEqual(@as(usize, 0), assembler.used);
    try std.testing.expectEqual(@as(usize, 0), sink.calls);
}

test "an oversized message is delivered and then gives its room back" {
    var packet: [200_000]u8 = undefined;
    for (&packet, 0..) |*byte, index| byte.* = @truncate(index);
    const scratch = try std.testing.allocator.alloc(u8, 262144);
    defer std.testing.allocator.free(scratch);

    var assembler = MessageAssembler.init(std.testing.allocator, 262144, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};
    var relay = RelaySink{ .assembler = &assembler, .sink = sink.sink() };

    var fixed = FixedScratch{ .buffer = scratch };
    try encodeMessage(&packet, 262144, .reliable, fixed.scratch(), relay.segments());
    try std.testing.expectEqual(std.hash.Fnv1a_64.hash(&packet), sink.hash);

    try std.testing.expectEqual(MessageAssembler.default_retained_bytes, assembler.retainedBytes());

    try assembler.feed(&[_]u8{ 0, 'h', 'i' }, sink.sink());
    try std.testing.expectEqual(MessageAssembler.default_retained_bytes, assembler.retainedBytes());
    try std.testing.expectEqual(@as(usize, 2), sink.len);
}

test "a message beyond the packet cap is refused before allocating" {
    var assembler = MessageAssembler.init(std.testing.allocator, 262144, .reliable, 4);
    defer assembler.deinit();
    var sink = TestSink{};
    try std.testing.expectError(error.PayloadTooLarge, assembler.feed(&[_]u8{ 0x00, 'a', 'b', 'c', 'd', 'e' }, sink.sink()));
    try std.testing.expectEqual(@as(usize, 0), assembler.buffer.len);
}

test "small single-segment messages round trip through both halves" {
    const payload = "nethernet-zig-probe";
    var scratch: [64]u8 = undefined;
    var assembler = MessageAssembler.init(std.testing.allocator, 64, .reliable, default_max_packet_bytes);
    defer assembler.deinit();
    var sink = TestSink{};
    var relay = RelaySink{ .assembler = &assembler, .sink = sink.sink() };

    var fixed = FixedScratch{ .buffer = &scratch };
    try encodeMessage(payload, 64, .reliable, fixed.scratch(), relay.segments());

    try std.testing.expectEqual(@as(usize, 1), relay.count);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqual(payload.len, sink.len);
    try std.testing.expectEqual(std.hash.Fnv1a_64.hash(payload), sink.hash);
}

test "empty and header-only segments are rejected" {
    var buffer: [8]u8 = undefined;
    var assembler = Assembler.init(&buffer, buffer.len, true);
    try std.testing.expectError(error.EmptyPayload, segment("", 8, true, EmitContext.emit, undefined));
    try std.testing.expectError(error.SegmentTooShort, assembler.push(&[_]u8{0}));
}
