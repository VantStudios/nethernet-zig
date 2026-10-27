# Nethernet

NetherNet transport for Minecraft Bedrock servers, written in Zig 0.16. It provides
LAN discovery, Partner HTTP signaling and a reliable/unreliable data-channel pair
over ICE, DTLS and SCTP.

Messages arrive reassembled and framing-free; Bedrock's own layer
(`RequestNetworkSettings`, `Login`, compression, encryption) is built on top.

## Requirements

- Zig 0.16.0 or later.
- Linux, Windows, macOS or a BSD.
- Network access on the first build (WebRTC, SCTP and mbedTLS are fetched or built).
- A system linker on native Linux and macOS: GCC 16 emits `.sframe` relocations that
  Zig's bundled linker rejects, and LLD cannot link Mach-O.

## Install

```bash
zig fetch --save=nethernet git+https://github.com/VantStudios/nethernet-zig.git
```

```zig
const nethernet_dep = b.dependency("nethernet", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("nethernet", nethernet_dep.module("nethernet-zig"));
```

## Server

`server.Host` starts every path together:

| Path                            | Socket     |
| ------------------------------- | ---------- |
| Partner signaling               | TCP 19132  |
| LAN discovery and trickle ICE   | UDP 7551   |
| External server list MOTD       | UDP 19132  |

```zig
const std = @import("std");
const nethernet = @import("nethernet");

pub const std_options: std.Options = nethernet.log.options;

const App = struct {
    reply: [512]u8 = undefined,

    fn onOpen(_: *anyopaque, session: *nethernet.web_rtc.PeerHandle) void {
        std.debug.print("player {d} connected\n", .{session.id});
    }

    fn onMessage(
        ctx: *anyopaque,
        _: *nethernet.web_rtc.PeerHandle,
        _: nethernet.web_rtc.ChannelKind,
        message: []const u8,
    ) ?[]const u8 {
        const self: *App = @ptrCast(@alignCast(ctx));
        return std.fmt.bufPrint(&self.reply, "echo:{s}", .{message}) catch null;
    }

    fn onClose(_: *anyopaque, session: *nethernet.web_rtc.PeerHandle) void {
        std.debug.print("player {d} disconnected\n", .{session.id});
    }
};

pub fn main(init: std.process.Init) !void {
    var app: App = .{};
    const handler: nethernet.web_rtc.MessageHandler = .{
        .ctx = &app,
        .on_open = App.onOpen,
        .on_message = App.onMessage,
        .on_close = App.onClose,
    };

    const identity = try nethernet.identity.ServerProvider.loadOrCreate(
        init.io,
        init.gpa,
        "server.key",
    );

    var verifier = try nethernet.identity.Verifier.init(init.io, init.gpa, .{
        .jwks_uri = "https://authorization.franchise.minecraft-services.net/.well-known/keys",
    });
    defer verifier.deinit();

    const host = try nethernet.server.Host.init(init.io, init.gpa, .{
        .server_data = .{
            .server_name = "My server",
            .level_name = "world",
            .max_player_count = 10,
        },
        .handler = handler,
        .identity = identity,
        .identity_verifier = &verifier,
        .require_client_identity = true,
        .http_config = .{ .max_sessions = 2000, .tick_shards = 4 },
        .lan_config = .{ .max_pending_connections = 2000 },
    });
    defer host.deinit();

    try host.start();
    defer host.stop();

    const fingerprint = std.fmt.bytesToHex(host.keyFingerprint(), .lower);
    std.debug.print("key sha-256: {s}\n", .{fingerprint[0..]});

    while (true) {
        try std.Io.sleep(init.io, .fromMilliseconds(1000), .awake);
    }
}
```

`Host.init` refuses to start without `identity_verifier` unless
`accept_unverified_identity` is set; that flag is for a lab only.
`require_client_identity = true` also requires an `a=identity` envelope on LAN;
`null` keeps the per-transport defaults (HTTP requires one, LAN does not).

`server.key` is created with `0600` on first start and reused afterwards.
`host.keyFingerprint()` is the SHA-256 clients pin; a new key invalidates every pin.

### Sending to a session

```zig
try host.send(session.id, .reliable, packet);
host.closeSession(session.id); // flushes the queue, then closes
host.abortSession(session.id); // drops the queue and closes at once

if (host.sessionMaxMessageSize(session.id)) |limit| { ... }
if (host.sessionClaims(session.id)) |claims| {
    if (claims.xuid) |xuid| { ... }
}
```

Ids are unique across every listener of a host, so an id from the HTTP path and one
from the LAN path never collide. The claims are borrowed: they live and die with the
session.

### Threading contract

| Call | Runs on | Waits on |
| ---- | ------- | -------- |
| `on_message` | the listener's tick, with that shard lock held | nothing: copy what you need and return |
| `on_open` / `on_close` | a signaling or LAN thread | nothing: a slow handler stalls that socket |
| `Host.send` | any thread | a copy into the session's outbox |
| `Host.closeSession` / `abortSession` | any thread | the same outbox |
| `Host.tick` | its own ticker, or the caller when `spawn_ticker = false` | each shard in turn |

`Host.send` never touches SCTP: it copies the message into the session's outbox and
returns, and the tick that owns the session drains it. `PeerHandle.send` has no such
protection — it writes to the transport directly, so it belongs to the tick thread
(inside `on_message`, for example). A slice returned from `on_message` is framed on the
tick thread too.

Lock order is `shard lock → session index → outbox`. Sending takes only the last two,
which is why a game thread can enqueue while a shard is busy with a peer.

`spawn_ticker = false` hands the clock to the caller: `start` opens the listeners and
starts no thread, and the caller runs `host.tick()` from its own loop.

The session table is allocated at `init`; `http_config.max_sessions` defaults to 256
and `tick_shards` splits its locks across threads. An established session costs about
41 KB and no thread of its own. On Linux, start the server before the Minecraft client
on the same machine: the client holds UDP 7551 without sharing it, and the LAN
listener then gives up after a few retries. Joins by IP keep working.

Behind NAT, set `public_candidate` (a fixed public address and port) or `ice_servers`
(STUN/TURN) so the answer carries a reachable candidate.

## Client session

```zig
const session = try nethernet.Session.create(init.io, init.gpa, .{ .network_id = "lobby" });
defer session.destroy();

try session.send(.reliable, "hello nethernet");
try session.send(.unreliable, "fire and forget");

while (try session.poll()) |packet| {
    defer session.release(packet);
    std.debug.print("{s}: {s}\n", .{ @tagName(packet.reliability), packet.data });
}
```

With a real peer, create the offer, send it through your signaling, then accept the
answer:

```zig
try session.attachPeer(&peer);
const offer = try session.createOffer();
// send offer.sdp through your signaling

try session.acceptAnswer(answer_sdp, .{ .trust = .transport_authenticated });
try session.tick();
```

`acceptAnswer` verifies the server's `a=identity` before the backend sees the SDP.
The trust anchor is explicit:

- `.transport_authenticated` — HTTPS with a certificate that was actually validated.
- `.pinned = &pins` — only keys already in the `PinStore`.
- `.tofu = .{ .store = &pins, .on_unknown = decide }` — plain HTTP; a new key is
  pinned only if `decide` allows it (`null` means reject).

`session.peerIdentity()` returns the anchored key; `acceptAnswerRaw` skips the check.

Two files are secrets and do not belong in a repository:

- `server.key` — the operator's P-384 key; back it up and share it across instances.
- `pins.json` — the client's `PinStore`; deleting it resets trust.

## API overview

| Type | Purpose |
| --- | --- |
| `server.Host` | All three listeners plus one advertisement and one player budget. `start()` spawns the workers and ticker; `acceptLoop()` is the caller-owned-thread variant. |
| `server.Server` | Partner signaling alone: `init`, `start`, `stop`, `tick`, `tickShard`, `sessionCount`, `playerCount`, `deinit`. |
| `server.LanServer` | UDP 7551 discovery and ICE signaling: `init`, `tick`, `isBound`, `isDisabled`, `deinit`. |
| `server.PingResponder` | RakNet MOTD on UDP 19132; `server.queryPing` asks another host. |
| `Session` | Framing and reassembly without a network: `create`, `send`, `poll`, `release`, `attachPeer`, `createOffer`, `acceptAnswer`, `tick`, `close`. |
| `signaling.Joiner` | HTTP side of a join: `capability()`, `submitOffer()`, `submitOfferRaw()`. |
| `identity.Verifier` | Anchors client claims against the auth service's JWKS. |
| `identity.PinStore` | Persistent TOFU/pin store for operator keys. |
| `probe` | End-to-end LAN client: `discover()` and `run()`. |

A `Host` is configured with `server_data`, `handler`, `identity`,
`identity_verifier`, `require_client_identity`, `paths` (`.http`, `.lan`, `.motd`),
`http_config`, `lan_config`, `motd_config`, `ice_servers`, `public_candidate` and
`accept_unverified_identity`. See `src/server/host.zig` for the full set and defaults.

```zig
pub const MessageHandler = struct {
    ctx: *anyopaque,
    on_open: ?*const fn (ctx: *anyopaque, session: *PeerHandle) void = null,
    on_message: *const fn (ctx: *anyopaque, session: *PeerHandle, kind: ChannelKind, message: []const u8) ?[]const u8,
    on_close: ?*const fn (ctx: *anyopaque, session: *PeerHandle) void = null,
};

pub const PeerHandle = struct {
    id: u64,
    peer: *Peer,
    user_data: ?*anyopaque = null,
    pub fn send(self: *PeerHandle, kind: ChannelKind, payload: []const u8) PeerError!void;
};
```

Store per-player state in `user_data` and free it in `on_close`. The slice returned by
`on_message` must stay valid until the next call. With `tick_shards > 1` the same
`ctx` can be called from several threads.

## Examples

| Example | Shows |
| --- | --- |
| `example-session` | `Session` with no network: framing, send, poll. |
| `example-server` | `Host` serving all three paths, echoing every message. |
| `example-discover` | Requesting and decoding a LAN `ServerData`. |
| `example-cli` | `server`, `connect`, `discover`, `ping` and `probe`. |

```bash
zig build run-session
zig build run-server -- --jwks=https://auth.example/jwks
zig build run-discover -- 127.0.0.1 7551
zig build run -- probe
```

`run-server` requires `--jwks=<url>`, `--jwks-document=<path>` or `--insecure`. Other
flags include `--key=<path>`, `--sessions=<n>`, `--shards=<n>`,
`--public-address=<ip> --public-port=<port>`, `--stun=<url>` and `--no-ping`.

## Building

```bash
zig build                          # library and examples in the inferred mode
zig build -Doptimize=ReleaseSafe   # recommended for a long-lived server
zig build test                     # library and example tests
zig build examples                 # examples only
```

A Debug build keeps the per-packet and per-candidate logs; release builds omit them.

## Protocol support

- **Discovery**: UDP 7551, encrypted `ServerData` v7, recovery of underdeclared signal lengths.
- **Signaling**: trickle ICE (`CONNECTREQUEST`, `CONNECTRESPONSE`, `CANDIDATEADD`,
  `CONNECTERROR`) and Partner HTTP with SDP plus an ES384 identity assertion.
- **Transport**: ICE, DTLS, SCTP, one reliable ordered and one unreliable unordered channel.
- **Framing**: one countdown byte per segment, no length prefix; segmentation and
  reassembly follow the negotiated `max-message-size`.
- **MOTD**: RakNet `Unconnected Ping`/`Pong` for the entry added by IP.

## License

MIT.

- Mojang's [NetherNetOnboardingGuide.md](https://github.com/Mojang/bedrock-protocol-docs/blob/main/additional_docs/NetherNetOnboardingGuide.md).
- [`df-mc/nethernet-spec`](https://github.com/df-mc/nethernet-spec) for the LAN datagrams and signals.
