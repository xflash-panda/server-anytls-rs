use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::core::hooks::{Address, OutboundType, UserId};
use crate::core::server::Server;
use crate::core::session::Session;
use crate::core::stream::Stream;
use crate::error::{Error, Result};

/// Parse a SOCKS5-style address from the given byte slice.
/// Returns `(Address, bytes_consumed)` on success.
pub(crate) fn parse_socks_address(data: &[u8]) -> Result<(Address, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidFrame("address type byte missing".into()));
    }
    match data[0] {
        0x01 => {
            // IPv4: 1 + 4 + 2 = 7 bytes
            if data.len() < 7 {
                return Err(Error::InvalidFrame("truncated IPv4 address".into()));
            }
            let ip: [u8; 4] = data[1..5].try_into().unwrap();
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((Address::IPv4(ip, port), 7))
        }
        0x03 => {
            // Domain: type(1) + len(1) + N + port(2); consumed = total
            if data.len() < 2 {
                return Err(Error::InvalidFrame("truncated domain length".into()));
            }
            let name_len = data[1] as usize;
            let total = 1 + 1 + name_len + 2;
            if data.len() < total {
                return Err(Error::InvalidFrame("truncated domain address".into()));
            }
            let domain = std::str::from_utf8(&data[2..2 + name_len])
                .map_err(|_| Error::InvalidFrame("domain is not valid UTF-8".into()))?
                .to_string();
            let port = u16::from_be_bytes([data[2 + name_len], data[2 + name_len + 1]]);
            // consumed = type(1) + len_byte(1) + name(N) + port(2)
            Ok((Address::Domain(domain, port), total))
        }
        0x04 => {
            // IPv6: 1 + 16 + 2 = 19 bytes
            if data.len() < 19 {
                return Err(Error::InvalidFrame("truncated IPv6 address".into()));
            }
            let ip: [u8; 16] = data[1..17].try_into().unwrap();
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((Address::IPv6(ip, port), 19))
        }
        t => Err(Error::InvalidFrame(format!(
            "unknown address type: 0x{:02x}",
            t
        ))),
    }
}

/// Returns true when the address is a UDP-over-TCP pseudo-domain.
pub(crate) fn is_udp_over_tcp(addr: &Address) -> bool {
    match addr {
        Address::Domain(domain, _) => domain.contains("udp-over-tcp.arpa"),
        _ => false,
    }
}

/// Main entry point called by the session handler for each new stream.
pub(crate) async fn handle_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    session: Arc<Session<T>>,
    mut stream: Stream,
    user_id: UserId,
) -> Result<()> {
    // Read the first chunk from the stream to get the SOCKS5 destination address.
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(Error::StreamClosed);
    }

    let (target, consumed) = parse_socks_address(&buf[..n])?;

    if is_udp_over_tcp(&target) {
        info!(
            "UDP-over-TCP requested for {}, not implemented — closing stream",
            target
        );
        return Ok(());
    }

    let trailing = buf[consumed..n].to_vec();
    let outbound = server.router.route(&target).await;
    match outbound {
        OutboundType::Direct => {
            proxy_tcp(server, session, stream, &target, trailing, user_id).await
        }
        OutboundType::Reject => {
            warn!("rejecting connection to {}", target);
            let stream_id = stream.id();
            session.handshake_failure(stream_id, "rejected").await?;
            Ok(())
        }
    }
}

/// Connect to `target` and bidirectionally relay data between `stream` and the
/// remote TCP connection.  `trailing` holds any bytes that were read from the
/// stream beyond the SOCKS address (e.g. the start of the HTTP request or TLS
/// ClientHello) and must be forwarded to the remote before bidirectional copy.
async fn proxy_tcp<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    session: Arc<Session<T>>,
    mut stream: Stream,
    target: &Address,
    trailing: Vec<u8>,
    user_id: UserId,
) -> Result<()> {
    let stream_id = stream.id();
    let addr_str = target.to_socket_string();

    let connect_result =
        tokio::time::timeout(server.config.tcp_connect_timeout, connect_target(target)).await;

    let mut remote = match connect_result {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            warn!("failed to connect to {}: {}", addr_str, e);
            session.handshake_failure(stream_id, &e.to_string()).await?;
            return Err(Error::Io(e));
        }
        Err(_elapsed) => {
            warn!("connect timeout to {}", addr_str);
            session
                .handshake_failure(stream_id, "connect timeout")
                .await?;
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            )));
        }
    };

    session.handshake_success(stream_id).await?;

    // Forward any application data that was read alongside the SOCKS address.
    let trailing_len = trailing.len() as u64;
    if !trailing.is_empty() {
        remote.write_all(&trailing).await?;
    }

    let relay_result =
        tokio::io::copy_bidirectional_with_sizes(&mut stream, &mut remote, 65536, 65536).await;

    if let Ok((up, down)) = relay_result {
        server.stats.record_upload(user_id, up + trailing_len);
        server.stats.record_download(user_id, down);
    }

    session.send_fin(stream_id).await?;

    Ok(())
}

/// Resolve and connect to the target address.
async fn connect_target(target: &Address) -> std::io::Result<TcpStream> {
    let stream = match target {
        Address::IPv4(ip, port) => {
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(*ip), *port));
            TcpStream::connect(addr).await?
        }
        Address::IPv6(ip, port) => {
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(*ip), *port, 0, 0));
            TcpStream::connect(addr).await?
        }
        Address::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await?,
    };
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hooks::Address;

    #[test]
    fn test_parse_socks_addr_ipv4() {
        let data = &[0x01, 127, 0, 0, 1, 0x00, 0x50];
        let (addr, consumed) = parse_socks_address(data).unwrap();
        assert!(matches!(addr, Address::IPv4([127, 0, 0, 1], 80)));
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_socks_addr_ipv6() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&[0x01, 0xBB]);
        let (addr, consumed) = parse_socks_address(&data).unwrap();
        assert!(matches!(addr, Address::IPv6(_, 443)));
        assert_eq!(consumed, 19);
    }

    #[test]
    fn test_parse_socks_addr_domain() {
        let mut data = vec![0x03];
        data.push(11);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x00, 0x50]);
        let (addr, consumed) = parse_socks_address(&data).unwrap();
        if let Address::Domain(domain, port) = addr {
            assert_eq!(domain, "example.com");
            assert_eq!(port, 80);
        } else {
            panic!("expected Domain address");
        }
        assert_eq!(consumed, 15);
    }

    #[test]
    fn test_parse_socks_addr_invalid_type() {
        let data = &[0xFF, 0, 0, 0, 0, 0, 0];
        let result = parse_socks_address(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_udp_over_tcp() {
        let addr = Address::Domain("sp.v2.udp-over-tcp.arpa".to_string(), 443);
        assert!(is_udp_over_tcp(&addr));
        let addr = Address::Domain("example.com".to_string(), 80);
        assert!(!is_udp_over_tcp(&addr));
        let addr = Address::IPv4([1, 2, 3, 4], 80);
        assert!(!is_udp_over_tcp(&addr));
    }

    #[tokio::test]
    async fn test_handle_stream_records_traffic_stats() {
        use crate::core::hooks::{DirectRouter, SinglePasswordAuth, StatsCollector, UserId};
        use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
        use crate::core::server::Server;
        use crate::core::session::{Session, SessionConfig};
        use crate::core::stream::{Stream, WriteCommand};
        use std::sync::atomic::{AtomicU64, Ordering};

        struct RecordingStats {
            upload: AtomicU64,
            download: AtomicU64,
        }
        impl StatsCollector for RecordingStats {
            fn record_upload(&self, _uid: UserId, bytes: u64) {
                self.upload.fetch_add(bytes, Ordering::Relaxed);
            }
            fn record_download(&self, _uid: UserId, bytes: u64) {
                self.download.fetch_add(bytes, Ordering::Relaxed);
            }
        }

        // Echo server
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo.accept().await {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });

        let recording = Arc::new(RecordingStats {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        });

        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new("test")))
                .stats(recording.clone() as Arc<dyn StatsCollector>)
                .router(Arc::new(DirectRouter))
                .build(),
        );

        // Session over duplex
        let (_client_io, server_io) = tokio::io::duplex(65536);
        let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));

        // Drain write commands from the session writer
        let (write_cmd_tx, mut write_cmd_rx) = tokio::sync::mpsc::channel::<WriteCommand>(256);
        tokio::spawn(async move { while write_cmd_rx.recv().await.is_some() {} });
        let (data_tx, stream) = Stream::new(1, write_cmd_tx);

        // SOCKS5 IPv4 address pointing to echo server (no trailing data)
        let ip = match echo_addr {
            std::net::SocketAddr::V4(v4) => v4.ip().octets(),
            _ => panic!("expected v4"),
        };
        let port = echo_addr.port();
        let mut addr_data = vec![0x01];
        addr_data.extend_from_slice(&ip);
        addr_data.extend_from_slice(&port.to_be_bytes());
        data_tx.send(bytes::Bytes::from(addr_data)).await.unwrap();

        // Payload that goes through copy_bidirectional
        let payload = b"hello world test data";
        data_tx
            .send(bytes::Bytes::from_static(payload))
            .await
            .unwrap();
        drop(data_tx); // EOF → copy_bidirectional finishes

        let _ = handle_stream(server, session, stream, 42).await;

        let up = recording.upload.load(Ordering::Relaxed);
        let down = recording.download.load(Ordering::Relaxed);
        assert!(up > 0, "expected upload bytes to be recorded, got 0");
        assert!(down > 0, "expected download bytes to be recorded, got 0");
    }
}
