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

## License

MIT
