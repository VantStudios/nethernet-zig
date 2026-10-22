const std = @import("std");

pub const Limiter = struct {
    pub const capacity: usize = 1024;

    const Entry = struct {
        address: u32 = 0,
        tokens: u32 = 0,
        last_ms: i64 = 0,
    };

    io: std.Io,
    per_second: u32,
    entries: [capacity]Entry = @splat(.{}),

    pub fn init(io: std.Io, per_second: u32) Limiter {
        return .{ .io = io, .per_second = per_second, .entries = @splat(.{}) };
    }

    pub fn allow(self: *Limiter, address: u32) bool {
        if (self.per_second == 0) return true;
        const now = nowMs(self.io);
        const index = @as(usize, address *% 0x9e37_79b1) % capacity;
        const entry = &self.entries[index];
        if (entry.address != address or entry.last_ms == 0) {
            entry.* = .{ .address = address, .tokens = self.per_second - 1, .last_ms = now };
            return true;
        }
        const elapsed = @max(now - entry.last_ms, 0);
        const refilled = @divTrunc(elapsed * @as(i64, self.per_second), 1000);
        entry.tokens = @intCast(@min(@as(i64, entry.tokens) + refilled, self.per_second));
        entry.last_ms = now;
        if (entry.tokens == 0) return false;
        entry.tokens -= 1;
        return true;
    }
};

pub fn nowMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

test "a source is capped per second and another keeps its own budget" {
    var limiter = Limiter.init(std.testing.io, 4);
    const source: u32 = 0x7f00_0001;
    const other: u32 = 0x7f00_0002;

    for (0..4) |_| try std.testing.expect(limiter.allow(source));
    try std.testing.expect(!limiter.allow(source));
    try std.testing.expect(limiter.allow(other));
}

test "the cap can be turned off" {
    var limiter = Limiter.init(std.testing.io, 0);
    for (0..64) |_| try std.testing.expect(limiter.allow(0x0102_0304));
}
