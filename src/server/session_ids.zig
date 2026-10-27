const std = @import("std");

/// One counter shared by every listener a host runs, so an id names exactly one
/// session no matter which door the client came through.
///
/// Ids are opaque: they are not dense and they are never reused.
pub const SessionIds = struct {
    next: std.atomic.Value(u64) = .init(0),

    pub fn allocate(self: *SessionIds) u64 {
        return self.next.fetchAdd(1, .monotonic) +% 1;
    }
};

test "a shared source hands out distinct ids in order" {
    var ids = SessionIds{};
    const first = ids.allocate();
    const second = ids.allocate();
    const third = ids.allocate();

    try std.testing.expectEqual(@as(u64, 1), first);
    try std.testing.expect(second > first);
    try std.testing.expect(third > second);
}

test "concurrent allocation never repeats an id" {
    var ids = SessionIds{};
    const Worker = struct {
        fn run(source: *SessionIds, out: []u64) void {
            for (out) |*slot| slot.* = source.allocate();
        }
    };

    var first: [256]u64 = undefined;
    var second: [256]u64 = undefined;
    const a = try std.Thread.spawn(.{}, Worker.run, .{ &ids, &first });
    const b = try std.Thread.spawn(.{}, Worker.run, .{ &ids, &second });
    a.join();
    b.join();

    var seen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer seen.deinit();
    for ([_][]u64{ &first, &second }) |batch| {
        for (batch) |id| {
            try std.testing.expect(id != 0);
            const entry = try seen.getOrPut(id);
            try std.testing.expect(!entry.found_existing);
        }
    }
    try std.testing.expectEqual(@as(usize, 512), seen.count());
}

test "standalone counters keep their own sequence" {
    var one = SessionIds{};
    var other = SessionIds{};
    try std.testing.expectEqual(one.allocate(), other.allocate());
}
