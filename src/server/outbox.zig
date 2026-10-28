const std = @import("std");

pub const Kind = enum { reliable, unreliable };

pub const EnqueueError = error{ Closed, Backpressure, PayloadTooLarge };

/// Per-session send queue.
///
/// A producer on any thread copies a whole message into a fixed slab and returns; the
/// transport thread pops one message at a time and frames it. Nothing here touches
/// SCTP, so a producer never waits on the network and a stalled peer only fills its own
/// queue.
///
/// The slab is linear: messages are appended and the whole slab is reclaimed whenever
/// the queue empties, plus a compaction pass once the high-water mark passes half. A
/// popped slice stays valid until the next `pop`, which is all the drain loop needs.
///
/// The slab is allocated on the first send, so a session that never sends costs only
/// its ring.
pub const Outbox = struct {
    pub const Entry = struct {
        kind: Kind = .reliable,
        bytes: []const u8 = &.{},
        close: bool = false,
    };

    const Message = struct {
        kind: Kind,
        offset: usize,
        len: usize,
    };

    pub const descriptor_bytes: usize = @sizeOf(Message);

    io: std.Io,
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    slab: []u8 = &.{},
    capacity: usize,
    used: usize = 0,
    messages: []Message,
    head: usize = 0,
    count: usize = 0,
    close_deadline_ms: i64,
    closing: bool = false,
    aborting: bool = false,
    close_started_ms: i64 = 0,
    close_sent: bool = false,
    dropped: usize = 0,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, slots: usize, max_bytes: usize, close_deadline_ms: i64) !Outbox {
        if (slots == 0 or max_bytes == 0) return error.InvalidArgument;
        const messages = try allocator.alloc(Message, slots);
        return .{
            .io = io,
            .allocator = allocator,
            .capacity = max_bytes,
            .messages = messages,
            .close_deadline_ms = @max(close_deadline_ms, 0),
        };
    }

    pub fn deinit(self: *Outbox) void {
        if (self.slab.len != 0) self.allocator.free(self.slab);
        self.allocator.free(self.messages);
        self.* = undefined;
    }

    /// Copies `payload` and queues it. Never blocks on the transport.
    pub fn enqueue(self: *Outbox, kind: Kind, payload: []const u8, max_payload: usize) EnqueueError!void {
        if (payload.len > max_payload) return error.PayloadTooLarge;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.closing or self.aborting or self.close_sent) return error.Closed;
        if (self.count == self.messages.len) return error.Backpressure;
        if (payload.len > self.capacity) return error.Backpressure;
        if (self.slab.len == 0) {
            self.slab = self.allocator.alloc(u8, self.capacity) catch return error.Backpressure;
        }
        if (self.used + payload.len > self.slab.len) return error.Backpressure;

        @memcpy(self.slab[self.used..][0..payload.len], payload);
        const slot = (self.head + self.count) % self.messages.len;
        self.messages[slot] = .{ .kind = kind, .offset = self.used, .len = payload.len };
        self.used += payload.len;
        self.count += 1;
    }

    /// Asks for an orderly close: what is already queued is delivered first, then one
    /// `close` entry. Idempotent.
    pub fn requestClose(self: *Outbox, now_ms: i64) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closing or self.aborting or self.close_sent) return;
        self.closing = true;
        self.close_started_ms = now_ms;
    }

    /// Drops everything queued and refuses further sends.
    pub fn requestAbort(self: *Outbox) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.aborting or self.close_sent) return;
        self.aborting = true;
        self.dropped += self.count;
        self.clearLocked();
    }

    /// Transport thread only. Returns the next message, the close marker, or nothing.
    pub fn pop(self: *Outbox, now_ms: i64) ?Entry {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.close_sent) return null;
        if (self.aborting) {
            // An abort still has to reach the transport, which is what closes the peer.
            self.clearLocked();
            self.close_sent = true;
            return .{ .close = true };
        }
        if (self.closing and now_ms - self.close_started_ms >= self.close_deadline_ms) {
            // A peer that cannot drain must not hold the close open.
            self.dropped += self.count;
            self.clearLocked();
            self.close_sent = true;
            return .{ .close = true };
        }
        if (self.count == 0) {
            if (!self.closing) return null;
            self.close_sent = true;
            self.clearLocked();
            return .{ .close = true };
        }

        const message = self.messages[self.head];
        self.head = (self.head + 1) % self.messages.len;
        self.count -= 1;
        if (self.count == 0) {
            self.clearLocked();
        } else if (self.used >= self.slab.len / 2) {
            self.compactLocked();
        }
        return .{ .kind = message.kind, .bytes = self.slab[message.offset..][0..message.len] };
    }

    /// True once a close or an abort has been asked for, even if nothing can be sent yet.
    pub fn closeRequested(self: *Outbox) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.closing or self.aborting;
    }

    pub fn isEmpty(self: *Outbox) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.count == 0;
    }

    pub fn pendingCount(self: *Outbox) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.count;
    }

    pub fn pendingBytes(self: *Outbox) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.used;
    }

    pub fn droppedCount(self: *Outbox) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.dropped;
    }

    fn clearLocked(self: *Outbox) void {
        self.head = 0;
        self.count = 0;
        self.used = 0;
    }

    /// Moves the queued messages down to offset 0, in pop order, so a long-lived queue
    /// does not walk off the end of the slab.
    fn compactLocked(self: *Outbox) void {
        var write: usize = 0;
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            const slot = (self.head + index) % self.messages.len;
            const message = &self.messages[slot];
            if (write != message.offset) {
                std.mem.copyForwards(u8, self.slab[write..][0..message.len], self.slab[message.offset..][0..message.len]);
            }
            message.offset = write;
            write += message.len;
        }
        self.used = write;
    }
};

const testing = std.testing;

fn testOutbox(allocator: std.mem.Allocator, slots: usize, max_bytes: usize) !Outbox {
    return Outbox.init(testing.io, allocator, slots, max_bytes, 1_000);
}

test "an outbox that never sends allocates no payload slab" {
    const allocator = testing.allocator;
    var outbox = try Outbox.init(testing.io, allocator, 8, 1024, 1_000);
    defer outbox.deinit();

    try testing.expectEqual(@as(usize, 0), outbox.slab.len);
    try testing.expect(outbox.isEmpty());
}

test "messages pop in the order they were queued" {
    var outbox = try testOutbox(testing.allocator, 8, 256);
    defer outbox.deinit();

    try outbox.enqueue(.reliable, "first", 64);
    try outbox.enqueue(.unreliable, "second", 64);
    try outbox.enqueue(.reliable, "third", 64);

    try testing.expectEqual(@as(usize, 3), outbox.pendingCount());

    const first = outbox.pop(0).?;
    try testing.expectEqualStrings("first", first.bytes);
    try testing.expectEqual(Kind.reliable, first.kind);

    const second = outbox.pop(0).?;
    try testing.expectEqualStrings("second", second.bytes);
    try testing.expectEqual(Kind.unreliable, second.kind);

    const third = outbox.pop(0).?;
    try testing.expectEqualStrings("third", third.bytes);
    try testing.expect(outbox.pop(0) == null);
    try testing.expect(outbox.isEmpty());
}

test "a full queue refuses without dropping what it holds" {
    var outbox = try testOutbox(testing.allocator, 2, 256);
    defer outbox.deinit();

    try outbox.enqueue(.reliable, "one", 64);
    try outbox.enqueue(.reliable, "two", 64);
    try testing.expectError(error.Backpressure, outbox.enqueue(.reliable, "three", 64));
    try testing.expectEqual(@as(usize, 2), outbox.pendingCount());

    _ = outbox.pop(0);
    try outbox.enqueue(.reliable, "three", 64);
    try testing.expectEqualStrings("two", outbox.pop(0).?.bytes);
    try testing.expectEqualStrings("three", outbox.pop(0).?.bytes);
}

test "a payload past the session limit is refused before it touches the slab" {
    var outbox = try testOutbox(testing.allocator, 4, 256);
    defer outbox.deinit();

    var large: [64]u8 = undefined;
    @memset(&large, 0x41);
    try testing.expectError(error.PayloadTooLarge, outbox.enqueue(.reliable, &large, 32));
    try testing.expectEqual(@as(usize, 0), outbox.pendingBytes());
}

test "a close request is visible before anything can be sent" {
    var outbox = try testOutbox(testing.allocator, 4, 64);
    defer outbox.deinit();

    try testing.expect(!outbox.closeRequested());
    outbox.requestAbort();
    try testing.expect(outbox.closeRequested());
}

test "the slab reclaims space as messages leave, keeping order" {
    var outbox = try testOutbox(testing.allocator, 16, 64);
    defer outbox.deinit();

    var round: usize = 0;
    var expected: [3]u8 = undefined;
    while (round < 40) : (round += 1) {
        for (0..3) |index| {
            expected[index] = @intCast((round * 3 + index) % 250 + 1);
            try outbox.enqueue(.reliable, &.{expected[index]}, 8);
        }
        for (0..3) |index| {
            try testing.expectEqual(expected[index], outbox.pop(0).?.bytes[0]);
        }
    }
    try testing.expectEqual(@as(usize, 0), outbox.pendingBytes());
}

test "close drains what is queued and then hands out one close marker" {
    var outbox = try testOutbox(testing.allocator, 8, 256);
    defer outbox.deinit();

    try outbox.enqueue(.reliable, "payload", 64);
    outbox.requestClose(10);
    outbox.requestClose(20);

    const message = outbox.pop(10).?;
    try testing.expectEqualStrings("payload", message.bytes);
    try testing.expect(!message.close);

    const marker = outbox.pop(10).?;
    try testing.expect(marker.close);
    try testing.expect(outbox.pop(10) == null);
    try testing.expectError(error.Closed, outbox.enqueue(.reliable, "late", 64));
}

test "a close that never drains is forced at the deadline" {
    var outbox = try testOutbox(testing.allocator, 8, 256);
    defer outbox.deinit();

    for (0..4) |_| try outbox.enqueue(.reliable, "stuck", 64);
    outbox.requestClose(100);

    try testing.expectEqualStrings("stuck", outbox.pop(600).?.bytes);
    const marker = outbox.pop(1_200).?;
    try testing.expect(marker.close);
    try testing.expectEqual(@as(usize, 3), outbox.droppedCount());
    try testing.expectEqual(@as(usize, 0), outbox.pendingCount());
}

test "abort drops everything at once, signals the close and refuses further sends" {
    var outbox = try testOutbox(testing.allocator, 8, 256);
    defer outbox.deinit();

    try outbox.enqueue(.reliable, "one", 64);
    try outbox.enqueue(.reliable, "two", 64);
    outbox.requestAbort();

    try testing.expect(outbox.pop(0).?.close);
    try testing.expect(outbox.pop(0) == null);
    try testing.expectEqual(@as(usize, 2), outbox.droppedCount());
    try testing.expectError(error.Closed, outbox.enqueue(.reliable, "three", 64));
}

test "concurrent producers lose nothing and the consumer sees every message" {
    const allocator = testing.allocator;
    var outbox = try Outbox.init(testing.io, allocator, 512, 512 * 32, 1_000);
    defer outbox.deinit();

    const producers = 8;
    const per_producer = 1_000;
    const Worker = struct {
        fn run(queue: *Outbox, tag: u8) void {
            for (0..per_producer) |index| {
                var message: [8]u8 = undefined;
                message[0] = tag;
                std.mem.writeInt(u32, message[1..5], @intCast(index), .little);
                while (true) {
                    queue.enqueue(.reliable, &message, 8) catch |err| switch (err) {
                        error.Backpressure => continue,
                        else => return,
                    };
                    break;
                }
            }
        }
    };

    var threads: [producers]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &outbox, @as(u8, @intCast(index + 1)) });
    }

    var counts = [_]usize{0} ** producers;
    var drained: usize = 0;
    const total = producers * per_producer;
    while (drained < total) {
        if (outbox.pop(0)) |entry| {
            const tag = entry.bytes[0];
            try testing.expect(tag >= 1 and tag <= producers);
            counts[tag - 1] += 1;
            drained += 1;
        } else {
            std.Thread.yield() catch {};
        }
    }
    for (threads) |thread| thread.join();

    for (counts) |count| try testing.expectEqual(per_producer, count);
    try testing.expect(outbox.isEmpty());
}
