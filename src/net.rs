use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Bind a TCP listener on the given port with IPv4+IPv6 dual-stack support.
///
/// Creates an IPv6 socket with `IPV6_V6ONLY` disabled so it accepts both
/// IPv4 (mapped) and IPv6 connections. Falls back to IPv4-only (`0.0.0.0`)
/// if the dual-stack bind fails.
pub fn bind_dual_stack(port: u16) -> Result<TcpListener> {
    match try_bind_dual_stack(port) {
        Ok(listener) => Ok(listener),
        Err(e) => {
            tracing::warn!(error = %e, "dual-stack bind failed, falling back to IPv4-only");
            bind_socket(Domain::IPV4, ([0, 0, 0, 0], port).into())
        }
    }
}

fn try_bind_dual_stack(port: u16) -> Result<TcpListener> {
    let socket = new_tcp_socket(Domain::IPV6)?;
    socket.set_only_v6(false)?;

    let addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 0u16], port).into();
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn bind_socket(domain: Domain, addr: SocketAddr) -> Result<TcpListener> {
    let socket = new_tcp_socket(domain)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn new_tcp_socket(domain: Domain) -> Result<Socket> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_dual_stack_accepts_ipv4() {
        let listener = bind_dual_stack(0).expect("bind failed");
        let port = listener.local_addr().unwrap().port();

        let connect = TcpStream::connect(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        let accept = listener.accept();

        let (connect_result, accept_result) = tokio::join!(connect, accept);
        let mut client = connect_result.expect("IPv4 connect failed");
        let (_, peer_addr) = accept_result.expect("IPv4 accept failed");

        match peer_addr {
            SocketAddr::V4(v4) => assert!(v4.ip().is_loopback()),
            SocketAddr::V6(v6) => {
                let ip = v6.ip();
                assert!(
                    ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
                    "unexpected peer addr: {peer_addr}"
                );
            }
        }
        client.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_dual_stack_accepts_ipv6() {
        let listener = bind_dual_stack(0).expect("bind failed");
        let port = listener.local_addr().unwrap().port();

        let connect = TcpStream::connect(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port));
        let accept = listener.accept();

        let (connect_result, accept_result) = tokio::join!(connect, accept);
        let mut client = connect_result.expect("IPv6 connect failed");
        let (_, peer_addr) = accept_result.expect("IPv6 accept failed");

        assert!(peer_addr.ip().is_loopback(), "expected loopback, got: {peer_addr}");
        client.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_dual_stack_local_addr_is_ipv6() {
        let listener = bind_dual_stack(0).expect("bind failed");
        let local_addr = listener.local_addr().unwrap();
        assert!(
            local_addr.is_ipv6(),
            "expected IPv6 local addr for dual-stack, got: {local_addr}"
        );
    }
}
