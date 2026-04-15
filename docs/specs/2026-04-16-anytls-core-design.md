# AnyTLS Core - Rust Implementation Design

## Overview

Rust implementation of the AnyTLS server core, porting the server side of [anytls/anytls-go](https://github.com/anytls/anytls-go). Goal: optimize performance over the Go implementation using async I/O (tokio) and zero-cost abstractions.

Scope: standalone proxy server core only. No panel integration, no gRPC node registration, no user management — those are future extensions via hooks traits.

## Technical Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Async runtime | tokio | Most mature Rust async ecosystem |
| TLS | tokio-rustls (rustls) | Pure Rust, no OpenSSL dependency, cross-compile friendly |
| Frame buffering | bytes | Zero-copy buffer management |
| Password hashing | sha2 | SHA-256 for authentication |
| Randomness | rand | Padding size randomization |
| Logging | tracing | Async ecosystem standard |
| Error handling | thiserror | Typed errors |

## Project Structure

```
src/
├── lib.rs              # Public API exports
├── error.rs            # Unified error types
├── core/
│   ├── mod.rs          # Core module exports
│   ├── hooks.rs        # Extension point traits
│   ├── server.rs       # Server builder + accept loop
│   ├── session.rs      # Frame protocol recv_loop, Stream management
│   ├── stream.rs       # Stream: AsyncRead + AsyncWrite
│   ├── frame.rs        # Frame header constants, serialization
│   └── padding.rs      # PaddingFactory parsing and generation
├── handler.rs          # Connection processing: TLS → auth → Session → dispatch
└── outbound.rs         # TCP / UDP-over-TCP outbound proxy
```

## Hooks Traits

Extension points for future panel integration (pattern from server-trojan-rs):

### Authenticator

```rust
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, password_hash: &[u8; 32]) -> Option<UserId>;
}
```

Default: `SinglePasswordAuth` — single password, returns fixed UserId. Matches original anytls-go behavior.

### StatsCollector

```rust
pub trait StatsCollector: Send + Sync {
    fn record_upload(&self, user_id: UserId, bytes: u64);
    fn record_download(&self, user_id: UserId, bytes: u64);
}
```

Default: `NoopStatsCollector` — discards stats.

### OutboundRouter

```rust
pub trait OutboundRouter: Send + Sync {
    async fn route(&self, target: &Address) -> OutboundType;
}
```

Default: `DirectRouter` — all connections go direct.

## Server API

```rust
pub struct Server {
    authenticator: Arc<dyn Authenticator>,
    stats: Arc<dyn StatsCollector>,
    router: Arc<dyn OutboundRouter>,
    tls_config: Arc<rustls::ServerConfig>,
    padding: PaddingFactory,
}

impl Server {
    pub fn builder() -> ServerBuilder;
    pub async fn run(&self, listener: TcpListener, shutdown: CancellationToken) -> Result<()>;
}
```

Builder pattern assembles hooks. `run()` accepts a TcpListener and CancellationToken, blocking until shutdown. Caller controls listener binding and shutdown signal.

## Protocol Implementation

### Authentication (first packet after TLS handshake)

```
| sha256(password) [32 bytes] | padding0 length [u16 BE] | padding0 [variable] |
```

Read 32 bytes → authenticate via hook → read 2-byte padding length → skip padding → create Session.

### Frame Format (7-byte header)

```
| command [u8] | streamId [u32 BE] | data length [u16 BE] | data [variable] |
```

### Commands

| Value | Name | Direction | Purpose |
|-------|------|-----------|---------|
| 0 | Waste | both | Padding (discard) |
| 1 | SYN | client→server | Open stream |
| 2 | PSH | both | Push data |
| 3 | FIN | both | Close stream |
| 4 | Settings | client→server | Client config |
| 5 | Alert | server→client | Error text |
| 6 | UpdatePaddingScheme | server→client | New padding config |
| 7 | SYNACK | server→client | Ack stream open (v2+) |
| 8 | HeartRequest | both | Keepalive request |
| 9 | HeartResponse | both | Keepalive response |
| 10 | ServerSettings | server→client | Server config (v2+) |

### Version Negotiation

Client sends `v=2` in Settings. If server supports v2, replies with ServerSettings `v=2`. Otherwise operates at v1. V2 enables SYNACK for handshake status reporting.

## Session Architecture

### recv_loop (server side)

Runs as the main task for each connection. Reads frames sequentially:

- **SYN**: Create new Stream, spawn handler task for outbound proxy
- **PSH**: Write data into target Stream's pipe
- **FIN**: Close target Stream locally
- **Waste**: Read and discard padding bytes
- **Settings**: Version negotiation + padding scheme sync
- **HeartRequest**: Reply with HeartResponse

### Stream

Each Stream implements `AsyncRead + AsyncWrite`:

- **Read side**: Bounded `tokio::sync::mpsc` channel (capacity 32) receives data from recv_loop
- **Write side**: Acquires Session write lock, sends PSH frame on the shared connection
- Supports `HandshakeSuccess` / `HandshakeFailure` (sends SYNACK, v2 only)
- Deadline support via tokio timeouts

**Difference from Go**: Go uses a synchronous unbuffered pipe — recv_loop blocks until the stream consumer reads. Rust uses a bounded mpsc channel, which decouples recv_loop from individual stream consumers. This avoids the Go deadlock risk where one slow stream blocks all streams on the session, at the cost of buffering up to `capacity` messages per stream in memory. Channel backpressure kicks in when the buffer is full.

### Write Path

Session holds an `AsyncMutex` for the underlying TLS connection. All streams share this write lock. Frame payload capped at 65535 bytes (u16 max).

Server does NOT apply padding to outgoing writes (padding is client-side only). Server only pushes padding configuration to clients.

## Padding

Parses scheme format:

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

Note: each packet number is an individual key. Range keys like `3-7=` are NOT supported — each must be listed separately.

`PaddingFactory` stores parsed ranges. `generate_record_payload_sizes(pkt)` returns sizes list for given packet number. `c` = CheckMark (-1) = stop padding if user data exhausted.

Server loads default or custom scheme, sends to clients whose `padding-md5` differs via `UpdatePaddingScheme` command.

## Outbound Proxy

### TCP

1. Parse SOCKS address from stream
2. Route via `OutboundRouter`
3. `TcpStream::connect` to target (with timeout)
4. Report handshake success/failure (v2)
5. `tokio::io::copy_bidirectional(stream, target)`

### UDP-over-TCP

1. Detect via target address containing `udp-over-tcp.arpa`
2. Read UoT v2 request
3. `UdpSocket::bind` + connect
4. Bidirectional packet relay

## Connection Flow

```
TCP Accept
  → TLS Handshake (tokio-rustls)
  → Read 32-byte SHA256 password hash
  → Authenticator::authenticate()
  → Skip padding0
  → Create Session (recv_loop as main task)
     → For each SYN: spawn Stream handler
        → Parse SOCKS address
        → Route + connect outbound
        → Bidirectional relay
        → FIN on close
  → Session ends when connection drops
```

## Performance Considerations

- **tokio tasks** instead of OS threads: hundreds of bytes vs 8MB per connection
- **Single recv_loop per connection**: no per-stream read goroutines needed
- **Shared write lock**: `tokio::sync::Mutex` (async-aware, no thread blocking)
- **Zero-copy where possible**: `bytes::BytesMut` for frame parsing
- **Atomic counters** for traffic stats (lock-free)
- **No padding on server writes**: reduces CPU and bandwidth overhead
