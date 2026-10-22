pub const PlayerSource = struct {
    ctx: *anyopaque,
    count: *const fn (ctx: *anyopaque) usize,
};
