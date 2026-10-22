const std = @import("std");

pub const Config = struct {
    joins_per_minute: u32 = 60,
    burst: u32 = 10,
    /// Fixed slots. When they are all taken the round-robin slot is recycled, so
    /// the table never grows and a flood of addresses cannot become an attack.
    capacity: usize = 4096,
};

pub const Key = [16]u8;

const token_scale: u32 = 1000;
const max_probes: usize = 8;

const Slot = struct {
    key: Key = @splat(0),
    tokens: u32 = 0,
    refilled_at_ms: i64 = 0,
    seen_at_ms: i64 = 0,
    occupied: bool = false,
};

pub const Decision = struct {
    allowed: bool,
    retry_after_seconds: u32 = 1,
};

pub const Limiter = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    slots: []Slot,
    hand: usize = 0,
    mutex: std.Io.Mutex = .init,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config) !Limiter {
        if (config.capacity == 0 or config.joins_per_minute == 0 or config.burst == 0) {
            return error.InvalidArgument;
        }
        const slots = try allocator.alloc(Slot, config.capacity);
        @memset(slots, .{});
        return .{ .allocator = allocator, .io = io, .config = config, .slots = slots };
    }

    pub fn deinit(self: *Limiter) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn check(self: *Limiter, key: Key, now_ms: i64) Decision {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const slot = self.slotFor(key);
        if (!slot.occupied) {
            slot.* = .{
                .key = key,
                .tokens = self.config.burst * token_scale,
                .refilled_at_ms = now_ms,
                .seen_at_ms = now_ms,
                .occupied = true,
            };
        } else {
            self.refill(slot, now_ms);
        }
        slot.seen_at_ms = now_ms;

        if (slot.tokens >= token_scale) {
            slot.tokens -= token_scale;
            return .{ .allowed = true };
        }
        const missing = token_scale - slot.tokens;
        const wait_ms = (@as(u64, missing) * 60) / self.config.joins_per_minute;
        return .{ .allowed = false, .retry_after_seconds = @intCast(@max(wait_ms / 1000, 1)) };
    }

    fn refill(self: *Limiter, slot: *Slot, now_ms: i64) void {
        const elapsed = now_ms - slot.refilled_at_ms;
        if (elapsed <= 0) return;
        const gain = (@as(u64, @intCast(elapsed)) * self.config.joins_per_minute) / 60;
        if (gain == 0) return;
        const limit = @as(u64, self.config.burst) * token_scale;
        slot.tokens = @intCast(@min(@as(u64, slot.tokens) + gain, limit));
        slot.refilled_at_ms = now_ms;
    }

    fn slotFor(self: *Limiter, key: Key) *Slot {
        const start = std.hash.Wyhash.hash(0, &key) % self.slots.len;
        var index = start;
        for (0..max_probes) |_| {
            const slot = &self.slots[index];
            if (!slot.occupied or std.mem.eql(u8, &slot.key, &key)) return slot;
            index = (index + 1) % self.slots.len;
        }
        const recycled = &self.slots[self.hand];
        self.hand = (self.hand + 1) % self.slots.len;
        recycled.* = .{};
        return recycled;
    }

    pub fn tracked(self: *const Limiter) usize {
        var count: usize = 0;
        for (self.slots) |slot| {
            if (slot.occupied) count += 1;
        }
        return count;
    }
};

test "an address spends its burst and refills over time" {
    const allocator = std.testing.allocator;
    var limiter = try Limiter.init(std.testing.io, allocator, .{ .joins_per_minute = 60, .burst = 2, .capacity = 8 });
    defer limiter.deinit();

    const key: Key = @splat(0xaa);
    try std.testing.expect(limiter.check(key, 0).allowed);
    try std.testing.expect(limiter.check(key, 0).allowed);
    const denied = limiter.check(key, 0);
    try std.testing.expect(!denied.allowed);
    try std.testing.expectEqual(@as(u32, 1), denied.retry_after_seconds);

    try std.testing.expect(!limiter.check(key, 400).allowed);
    try std.testing.expect(limiter.check(key, 1000).allowed);
    try std.testing.expect(!limiter.check(key, 1000).allowed);
    try std.testing.expect(limiter.check(key, 2000).allowed);
}

test "another address has its own budget" {
    const allocator = std.testing.allocator;
    var limiter = try Limiter.init(std.testing.io, allocator, .{ .joins_per_minute = 60, .burst = 1, .capacity = 8 });
    defer limiter.deinit();

    const first: Key = @splat(1);
    const second: Key = @splat(2);
    try std.testing.expect(limiter.check(first, 0).allowed);
    try std.testing.expect(!limiter.check(first, 0).allowed);
    try std.testing.expect(limiter.check(second, 0).allowed);
    try std.testing.expectEqual(@as(usize, 2), limiter.tracked());
}

test "the table is fixed and recycles its oldest slot" {
    const allocator = std.testing.allocator;
    var limiter = try Limiter.init(std.testing.io, allocator, .{ .joins_per_minute = 60, .burst = 1, .capacity = 2 });
    defer limiter.deinit();

    var key: Key = @splat(0);
    for (0..64) |round| {
        key[0] = @intCast(round);
        _ = limiter.check(key, @intCast(round));
    }
    try std.testing.expectEqual(@as(usize, 2), limiter.tracked());
    try std.testing.expectEqual(@as(usize, 2), limiter.slots.len);
}

test "a limiter with no budget or no slots is refused" {
    try std.testing.expectError(error.InvalidArgument, Limiter.init(std.testing.io, std.testing.allocator, .{ .capacity = 0 }));
    try std.testing.expectError(error.InvalidArgument, Limiter.init(std.testing.io, std.testing.allocator, .{ .joins_per_minute = 0 }));
    try std.testing.expectError(error.InvalidArgument, Limiter.init(std.testing.io, std.testing.allocator, .{ .burst = 0 }));
}
