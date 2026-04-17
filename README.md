# server-anytls-rs

A high-performance [AnyTLS](https://github.com/anytls/anytls-go) proxy server implementation in Rust.

## Features

- Multiplexed TLS connections with virtual stream support
- SHA-256 password authentication with constant-time comparison
- Per-user traffic statistics and reporting
- Optional ACL-based traffic routing
- Connection management with user kick-off and graceful shutdown
- Dynamic padding scheme support
- Panel integration for node configuration and user management
- jemalloc allocator for optimized memory performance

## Build

```bash
cargo build --release
```

## Usage

```bash
server-anytls \
  --api https://panel.example.com/api \
  --token <api-token> \
  --node <node-id> \
  --cert_file /path/to/server.crt \
  --key_file /path/to/server.key
```

All arguments support environment variables with `X_PANDA_ANYTLS_` prefix.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--api` | (required) | Panel API endpoint |
| `--token` | (required) | API authentication token |
| `--node` | (required) | Node ID |
| `--cert_file` | `/root/.cert/server.crt` | TLS certificate path |
| `--key_file` | `/root/.cert/server.key` | TLS private key path |
| `--fetch_users_interval` | `60s` | User list refresh interval |
| `--report_traffics_interval` | `80s` | Traffic stats reporting interval |
| `--heartbeat_interval` | `180s` | Heartbeat interval |
| `--api_timeout` | `30s` | API call timeout |
| `--log_mode` | `error` | Log level (`error`, `info`, `debug`) |
| `--data_dir` | `/var/lib/anytls-node` | Data directory |
| `--acl_conf_file` | (none) | ACL rules YAML file |
| `--block_private_ip` | `true` | Block private IP connections |
| `--max_connections` | `10000` | Global connection limit |
| `--refresh_geodata` | `false` | Force refresh ACL geodata |

## Benchmark: Rust vs Go

Tested on macOS Darwin 24.6.0 (MacBook Pro), using [anytls-go](https://github.com/anytls/anytls-go) client v0.0.12 as SOCKS5 proxy, with a mock panel API and Go HTTP target server on localhost.

### Throughput (RPS)

| Concurrency | Go | Rust | Delta |
|-------------|--------|----------|-------|
| c=1 | 11,066 | 10,729 | -3% |
| c=50 | 63,132 | 61,897 | -2% |
| c=100 | 64,783 | 64,344 | -1% |
| c=200 | 64,853 | 63,732 | -2% |
| c=500 | 61,613 | 62,003 | +1% |

> RPS roughly equal — bottlenecked by the shared anytls-go client.

### Tail Latency (p99)

| Concurrency | Go p99 | Rust p99 | Improvement |
|-------------|--------|----------|-------------|
| c=50 | 2.02ms | 1.55ms | **1.3x better** |
| c=100 | 5.24ms | 3.06ms | **1.7x better** |
| c=200 | 12.39ms | 7.38ms | **1.7x better** |
| c=500 | 24.4ms | 17.8ms | **1.4x better** |

### Bandwidth (large payload transfer)

| Payload | Go | Rust | Delta |
|---------|-----------|-----------|-------|
| 10KB c=50 | 497 MB/s | 535 MB/s | **+7.6%** |
| 1MB c=20 | 2,832 MB/s | 3,393 MB/s | **+19.8%** |
| 10MB c=10 | 2,847 MB/s | 2,915 MB/s | **+2.4%** |

### Resource Usage (under sustained load)

| Metric | Go | Rust | Notes |
|--------|---------|---------|-------|
| Avg CPU | 240.7% | 203.1% | **Rust 16% less CPU** |
| Avg RSS | 122.6 MB | 163.8 MB | Go 33% less memory (jemalloc preallocation) |

### Key Takeaways

- **p99 latency 1.3-1.7x lower** — no GC pauses, more predictable under load
- **Large transfer throughput up to 20% higher** — zero-copy IO advantage
- **16% less CPU** for same workload
- Go uses less memory due to jemalloc's arena preallocation in Rust build

Full results: see `benchmarks/` directory or run `~/code/test/anytls-bench/deep_bench.sh`.

## License

MIT
