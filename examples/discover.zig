const std = @import("std");

const nethernet = @import("nethernet");

pub const std_options: std.Options = nethernet.log.options;

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const host = args.next() orelse "127.0.0.1";
    const port: u16 = if (args.next()) |text| std.fmt.parseInt(u16, text, 10) catch 7551 else 7551;

    const parsed = parseIpv4(host) orelse {
        std.debug.print("invalid IPv4 address: {s}\n", .{host});
        return error.InvalidAddress;
    };

    var report = try nethernet.probe.discover(init.io, init.gpa, std.mem.nativeToBig(u32, parsed), port, 3_000);
    defer report.deinit(init.gpa);
    if (report.response_bytes == 0) {
        std.debug.print("no LAN discovery response from {s}:{d}\n", .{ host, port });
        return;
    }

    const server_data = nethernet.discovery_protocol.ServerData.decode(report.server_data) catch {
        std.debug.print("not a ServerData this build understands ({d} bytes)\n", .{report.response_bytes});
        return;
    };
    std.debug.print(
        "senderId={d} name=\"{s}\" protocol={d} version=\"{s}\" level=\"{s}\" players={d}/{d} connectionType={d}\n",
        .{
            report.sender_id,
            server_data.server_name,
            server_data.protocol,
            server_data.game_version,
            server_data.level_name,
            server_data.player_count,
            server_data.max_player_count,
            server_data.connection_type,
        },
    );
}

fn parseIpv4(text: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var index: usize = 0;
    var parts = std.mem.splitScalar(u8, text, '.');
    while (parts.next()) |part| {
        if (index >= octets.len) return null;
        octets[index] = std.fmt.parseInt(u8, part, 10) catch return null;
        index += 1;
    }
    if (index != octets.len) return null;
    return std.mem.readInt(u32, &octets, .big);
}
