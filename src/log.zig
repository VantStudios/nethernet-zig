const std = @import("std");
const builtin = @import("builtin");

pub const options: std.Options = .{
    .log_level = if (builtin.mode == .debug) .debug else .info,
};

test "the log policy follows the build mode" {
    try std.testing.expectEqual(if (builtin.mode == .debug) std.log.Level.debug else std.log.Level.info, options.log_level);
}
