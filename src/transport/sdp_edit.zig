const std = @import("std");

pub const Error = error{ InvalidSdp, InvalidPublicCandidate } || std.mem.Allocator.Error;

pub const EditOptions = struct {
    max_message_size: u32,
    public_candidate: ?PublicCandidate = null,
};

pub const PublicCandidate = struct {
    address: []const u8,
    port: u16,
    base_address: ?[]const u8 = null,
    base_port: ?u16 = null,
};

pub const srflx_priority: u32 = (100 << 24) | (65535 << 8) | 255;

pub fn validateCandidate(candidate: PublicCandidate) error{InvalidPublicCandidate}!void {
    if (candidate.port == 0 or candidate.address.len == 0 or candidate.address.len > 45) {
        return error.InvalidPublicCandidate;
    }
    _ = std.Io.net.IpAddress.parse(candidate.address, candidate.port) catch return error.InvalidPublicCandidate;
    if (candidate.base_address) |base| {
        if (base.len == 0 or base.len > 45) return error.InvalidPublicCandidate;
        _ = std.Io.net.IpAddress.parse(base, candidate.base_port orelse 0) catch
            return error.InvalidPublicCandidate;
    }
    if (candidate.base_address == null and candidate.base_port != null) return error.InvalidPublicCandidate;
}

const Line = struct {
    start: usize,
    next: usize,
    text: []const u8,
};

fn nextLine(sdp: []const u8, index: usize) ?Line {
    if (index >= sdp.len) return null;
    const newline = std.mem.indexOfScalarPos(u8, sdp, index, '\n');
    const end = newline orelse sdp.len;
    const text_end = if (newline != null and end > index and sdp[end - 1] == '\r') end - 1 else end;
    return .{ .start = index, .next = @min(end + 1, sdp.len), .text = sdp[index..text_end] };
}

fn trimmedLine(line: Line) []const u8 {
    return std.mem.trim(u8, line.text, " \t");
}

fn isDataMedia(trimmed: []const u8) bool {
    return std.mem.startsWith(u8, trimmed, "m=application ") and
        std.mem.indexOf(u8, trimmed, "webrtc-datachannel") != null;
}

const Media = struct {
    start: usize,
    end: usize,
};

fn dataMedia(sdp: []const u8) ?Media {
    var start: ?usize = null;
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        const trimmed = trimmedLine(line);
        if (!std.mem.startsWith(u8, trimmed, "m=")) continue;
        if (start) |value| return .{ .start = value, .end = line.start };
        if (isDataMedia(trimmed)) start = line.start;
    }
    return if (start) |value| .{ .start = value, .end = sdp.len } else null;
}

/// After `a=sctp-port:` of the same media, else before `a=end-of-candidates`, else at
/// the end of the media: always a line boundary, so the rest survives byte for byte.
fn insertionOffset(sdp: []const u8, media: Media) usize {
    var after_sctp_port: ?usize = null;
    var end_of_candidates: ?usize = null;
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        if (line.start < media.start or line.start >= media.end) continue;
        const trimmed = trimmedLine(line);
        if (after_sctp_port == null and std.mem.startsWith(u8, trimmed, "a=sctp-port:")) {
            after_sctp_port = line.next;
        }
        if (end_of_candidates == null and std.mem.eql(u8, trimmed, "a=end-of-candidates")) {
            end_of_candidates = line.start;
        }
    }
    return after_sctp_port orelse end_of_candidates orelse media.end;
}

fn lineEnding(sdp: []const u8) []const u8 {
    return if (std.mem.indexOf(u8, sdp, "\r\n") != null) "\r\n" else "\n";
}

pub fn rewriteMaxMessageSize(allocator: std.mem.Allocator, sdp: []const u8, value: u32) Error![]u8 {
    const media = dataMedia(sdp) orelse return allocator.dupe(u8, sdp);

    var number_buffer: [16]u8 = undefined;
    const number = std.fmt.bufPrint(&number_buffer, "{d}", .{value}) catch unreachable;
    const eol = lineEnding(sdp);
    const insert_at = insertionOffset(sdp, media);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, sdp.len + 32);

    var written = false;
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        if (!written and line.start == insert_at) {
            try writeMaxMessageSize(allocator, &out, number, eol);
            written = true;
        }
        const inside = line.start >= media.start and line.start < media.end;
        if (inside and std.mem.startsWith(u8, trimmedLine(line), "a=max-message-size:")) {
            if (!written) {
                try writeMaxMessageSize(allocator, &out, number, eol);
                written = true;
            }
            continue;
        }
        try out.appendSlice(allocator, sdp[line.start..line.next]);
    }
    if (!written) {
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try out.appendSlice(allocator, eol);
        try writeMaxMessageSize(allocator, &out, number, eol);
    }
    return out.toOwnedSlice(allocator);
}

fn writeMaxMessageSize(allocator: std.mem.Allocator, out: *std.ArrayList(u8), number: []const u8, eol: []const u8) Error!void {
    try out.appendSlice(allocator, "a=max-message-size:");
    try out.appendSlice(allocator, number);
    try out.appendSlice(allocator, eol);
}

pub fn editAnswer(allocator: std.mem.Allocator, sdp: []const u8, options: EditOptions) Error![]u8 {
    const sized = try rewriteMaxMessageSize(allocator, sdp, options.max_message_size);
    errdefer allocator.free(sized);
    const candidate = options.public_candidate orelse return sized;
    const injected = try injectPublicCandidate(allocator, sized, candidate);
    allocator.free(sized);
    return injected;
}

const Candidate = struct {
    address: []const u8,
    port: u16,
};

fn parseCandidateAddress(trimmed: []const u8) ?Candidate {
    const prefix = "a=candidate:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    var fields = std.mem.tokenizeAny(u8, trimmed[prefix.len..], " \t");
    _ = fields.next() orelse return null;
    _ = fields.next() orelse return null;
    _ = fields.next() orelse return null;
    _ = fields.next() orelse return null;
    const address = fields.next() orelse return null;
    const port_text = fields.next() orelse return null;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return null;
    return .{ .address = address, .port = port };
}

fn sameCandidate(candidate: Candidate, address: []const u8, port: u16) bool {
    return candidate.port == port and std.mem.eql(u8, candidate.address, address);
}

fn mediaIceUfrag(sdp: []const u8, media: Media) ?[]const u8 {
    const prefix = "a=ice-ufrag:";
    var session_value: ?[]const u8 = null;
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        const trimmed = trimmedLine(line);
        if (!std.mem.startsWith(u8, trimmed, prefix)) continue;
        const value = std.mem.trim(u8, trimmed[prefix.len..], " \t");
        if (value.len == 0) continue;
        if (line.start >= media.start and line.start < media.end) return value;
        if (line.start < media.start and session_value == null) session_value = value;
    }
    return session_value;
}

fn candidateInsertionOffset(sdp: []const u8, media: Media) usize {
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        if (line.start < media.start or line.start >= media.end) continue;
        if (std.mem.eql(u8, trimmedLine(line), "a=end-of-candidates")) return line.start;
    }
    return media.end;
}

pub fn injectPublicCandidate(
    allocator: std.mem.Allocator,
    sdp: []const u8,
    candidate: PublicCandidate,
) Error![]u8 {
    try validateCandidate(candidate);
    const media = dataMedia(sdp) orelse return error.InvalidSdp;
    const ufrag = mediaIceUfrag(sdp, media) orelse return error.InvalidSdp;

    var base_address: []const u8 = "0.0.0.0";
    var base_port: u16 = 0;
    var has_host = false;
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        if (line.start < media.start or line.start >= media.end) continue;
        const trimmed = trimmedLine(line);
        const parsed = parseCandidateAddress(trimmed) orelse continue;
        if (sameCandidate(parsed, candidate.address, candidate.port)) return allocator.dupe(u8, sdp);
        if (!has_host and std.mem.indexOf(u8, trimmed, " typ host") != null) {
            has_host = true;
            base_address = parsed.address;
            base_port = parsed.port;
        }
    }
    if (candidate.base_address) |address| base_address = address;
    if (candidate.base_port) |port| base_port = port;

    var foundation_buffer: [16]u8 = undefined;
    var scratch_buffer: [64]u8 = undefined;
    var priority_buffer: [16]u8 = undefined;
    const seed = std.fmt.bufPrint(&scratch_buffer, "{s}:{d}", .{ candidate.address, candidate.port }) catch unreachable;
    const foundation = std.fmt.bufPrint(&foundation_buffer, "{d}", .{std.hash.Crc32.hash(seed)}) catch unreachable;
    const priority = std.fmt.bufPrint(&priority_buffer, "{d}", .{srflx_priority}) catch unreachable;
    var port_buffer: [8]u8 = undefined;
    const port_text = std.fmt.bufPrint(&port_buffer, "{d}", .{candidate.port}) catch unreachable;
    var base_port_buffer: [8]u8 = undefined;
    const base_port_text = std.fmt.bufPrint(&base_port_buffer, "{d}", .{base_port}) catch unreachable;

    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(allocator);
    try line.appendSlice(allocator, "a=candidate:");
    try line.appendSlice(allocator, foundation);
    try line.appendSlice(allocator, " 1 udp ");
    try line.appendSlice(allocator, priority);
    try line.appendSlice(allocator, " ");
    try line.appendSlice(allocator, candidate.address);
    try line.appendSlice(allocator, " ");
    try line.appendSlice(allocator, port_text);
    try line.appendSlice(allocator, " typ srflx raddr ");
    try line.appendSlice(allocator, base_address);
    try line.appendSlice(allocator, " rport ");
    try line.appendSlice(allocator, base_port_text);
    try line.appendSlice(allocator, " ufrag ");
    try line.appendSlice(allocator, ufrag);

    const eol = lineEnding(sdp);
    const insert_at = candidateInsertionOffset(sdp, media);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, sdp.len + line.items.len + eol.len * 2);

    var written = false;
    index = 0;
    while (nextLine(sdp, index)) |current| : (index = current.next) {
        if (!written and current.start == insert_at) {
            try out.appendSlice(allocator, line.items);
            try out.appendSlice(allocator, eol);
            written = true;
        }
        try out.appendSlice(allocator, sdp[current.start..current.next]);
    }
    if (!written) {
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try out.appendSlice(allocator, eol);
        try out.appendSlice(allocator, line.items);
        try out.appendSlice(allocator, eol);
    }
    return out.toOwnedSlice(allocator);
}

test "the answer announces the negotiated limit instead of the peer's" {
    const sdp = "v=0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=max-message-size:1048576\r\n" ++
        "a=setup:passive\r\n";
    const edited = try rewriteMaxMessageSize(std.testing.allocator, sdp, 262144);
    defer std.testing.allocator.free(edited);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
            "a=sctp-port:5000\r\n" ++
            "a=max-message-size:262144\r\n" ++
            "a=setup:passive\r\n",
        edited,
    );
}

test "a missing limit is inserted after sctp-port and duplicates collapse" {
    const missing = "v=0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=setup:passive\r\n";
    const edited = try rewriteMaxMessageSize(std.testing.allocator, missing, 65536);
    defer std.testing.allocator.free(edited);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
            "a=sctp-port:5000\r\n" ++
            "a=max-message-size:65536\r\n" ++
            "a=setup:passive\r\n",
        edited,
    );

    const duplicated = "v=0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=max-message-size:1048576\r\n" ++
        "a=max-message-size:2048\r\n" ++
        "a=setup:passive\r\n";
    const collapsed = try rewriteMaxMessageSize(std.testing.allocator, duplicated, 65536);
    defer std.testing.allocator.free(collapsed);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
            "a=sctp-port:5000\r\n" ++
            "a=max-message-size:65536\r\n" ++
            "a=setup:passive\r\n",
        collapsed,
    );
}

test "without sctp-port the limit goes before end-of-candidates" {
    const sdp = "v=0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=ice-ufrag:u\r\n" ++
        "a=candidate:1 1 udp 1 127.0.0.1 5000 typ host\r\n" ++
        "a=end-of-candidates\r\n";
    const edited = try rewriteMaxMessageSize(std.testing.allocator, sdp, 32768);
    defer std.testing.allocator.free(edited);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
            "a=ice-ufrag:u\r\n" ++
            "a=candidate:1 1 udp 1 127.0.0.1 5000 typ host\r\n" ++
            "a=max-message-size:32768\r\n" ++
            "a=end-of-candidates\r\n",
        edited,
    );
}

test "a description with no data media is copied unchanged" {
    const sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";
    const edited = try rewriteMaxMessageSize(std.testing.allocator, sdp, 65536);
    defer std.testing.allocator.free(edited);
    try std.testing.expectEqualStrings(sdp, edited);
}

test "a limit is not added to a second media section" {
    const sdp = "v=0\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "a=max-message-size:1\r\n";
    const edited = try rewriteMaxMessageSize(std.testing.allocator, sdp, 65536);
    defer std.testing.allocator.free(edited);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
            "a=sctp-port:5000\r\n" ++
            "a=max-message-size:65536\r\n" ++
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
            "a=max-message-size:1\r\n",
        edited,
    );
}

test "line endings are preserved and a missing final newline still yields a line" {
    const lf = "v=0\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=sctp-port:5000\n";
    const edited_lf = try rewriteMaxMessageSize(std.testing.allocator, lf, 4096);
    defer std.testing.allocator.free(edited_lf);
    try std.testing.expectEqualStrings(
        "v=0\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=sctp-port:5000\na=max-message-size:4096\n",
        edited_lf,
    );

    const open = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=sctp-port:5000";
    const edited_open = try rewriteMaxMessageSize(std.testing.allocator, open, 4096);
    defer std.testing.allocator.free(edited_open);
    try std.testing.expectEqualStrings(
        "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=sctp-port:5000\r\na=max-message-size:4096\r\n",
        edited_open,
    );
}

const answer_with_host = "v=0\r\n" ++
    "a=ice-ufrag:sessionFrag\r\n" ++
    "a=fingerprint:sha-256 AA:BB\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "a=ice-ufrag:mediaFrag\r\n" ++
    "a=candidate:1 1 udp 2130706431 192.168.1.20 50000 typ host\r\n" ++
    "a=end-of-candidates\r\n";

test "a public candidate is announced with the session ufrag" {
    const edited = try injectPublicCandidate(std.testing.allocator, answer_with_host, .{
        .address = "203.0.113.10",
        .port = 19132,
    });
    defer std.testing.allocator.free(edited);
    const candidate_at = std.mem.indexOf(u8, edited, " 1 udp 1694498815 203.0.113.10 19132 typ srflx raddr 192.168.1.20 rport 50000 ufrag mediaFrag\r\n") orelse
        return error.TestUnexpectedResult;
    const line_start = std.mem.lastIndexOf(u8, edited[0..candidate_at], "a=candidate:") orelse return error.TestUnexpectedResult;
    try std.testing.expect(line_start > std.mem.indexOf(u8, edited, "typ host").?);
    try std.testing.expect(candidate_at < std.mem.indexOf(u8, edited, "a=end-of-candidates").?);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, edited, "typ srflx"));
}

test "a session-level ufrag is used when the media has none" {
    const sdp = "v=0\r\n" ++
        "a=ice-ufrag:sessionOnly\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n";
    const edited = try editAnswer(std.testing.allocator, sdp, .{
        .max_message_size = 65536,
        .public_candidate = .{ .address = "2001:db8::1", .port = 19132 },
    });
    defer std.testing.allocator.free(edited);
    try std.testing.expect(std.mem.indexOf(u8, edited, "typ srflx raddr 0.0.0.0 rport 0 ufrag sessionOnly") != null);
}

test "the base address of the public candidate can be chosen" {
    const edited = try injectPublicCandidate(std.testing.allocator, answer_with_host, .{
        .address = "203.0.113.10",
        .port = 19132,
        .base_address = "10.0.0.5",
        .base_port = 60000,
    });
    defer std.testing.allocator.free(edited);
    try std.testing.expect(std.mem.indexOf(u8, edited, "typ srflx raddr 10.0.0.5 rport 60000 ufrag mediaFrag") != null);
}

test "injecting the same candidate twice changes nothing" {
    const once = try injectPublicCandidate(std.testing.allocator, answer_with_host, .{
        .address = "203.0.113.10",
        .port = 19132,
    });
    defer std.testing.allocator.free(once);
    const twice = try injectPublicCandidate(std.testing.allocator, once, .{
        .address = "203.0.113.10",
        .port = 19132,
    });
    defer std.testing.allocator.free(twice);
    try std.testing.expectEqualStrings(once, twice);
}

test "a candidate that would inject a line or a bad address is refused" {
    const cases = [_]PublicCandidate{
        .{ .address = "", .port = 19132 },
        .{ .address = "203.0.113.10", .port = 0 },
        .{ .address = "203.0.113.10\r\na=x", .port = 19132 },
        .{ .address = "example.com", .port = 19132 },
        .{ .address = "1.2.3.4", .port = 19132, .base_port = 5000 },
        .{ .address = "1.2.3.4", .port = 19132, .base_address = "bad base" },
    };
    for (cases) |candidate| {
        try std.testing.expectError(
            error.InvalidPublicCandidate,
            injectPublicCandidate(std.testing.allocator, answer_with_host, candidate),
        );
    }
}

test "a description with no data media cannot take a public candidate" {
    try std.testing.expectError(
        error.InvalidSdp,
        injectPublicCandidate(std.testing.allocator, "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n", .{
            .address = "203.0.113.10",
            .port = 19132,
        }),
    );
}

test "editing an answer keeps fingerprints and identity out of the way" {
    const sdp = "v=0\r\n" ++
        "a=fingerprint:sha-256 AA:BB\r\n" ++
        "a=identity:kept\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n";
    const edited = try editAnswer(std.testing.allocator, sdp, .{ .max_message_size = 65536 });
    defer std.testing.allocator.free(edited);
    try std.testing.expect(std.mem.indexOf(u8, edited, "a=fingerprint:sha-256 AA:BB\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, edited, "a=identity:kept\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, edited, "a=max-message-size:65536\r\n") != null);
}
