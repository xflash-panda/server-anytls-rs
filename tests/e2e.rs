//! End-to-end integration test for the AnyTLS protocol.
//!
//! Flow:
//! 1. Start a TCP echo server on a random port.
//! 2. Start the AnyTLS server (TLS + auth + session) on another random port.
//! 3. A simulated client connects via TLS, authenticates, exchanges settings,
//!    opens a stream (SYN) with SOCKS5 address pointing to the echo server,
//!    sends data (PSH), and reads back the echoed response.

use std::sync::{Arc, Once};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use rustls::HandshakeKind;
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::{DirectRouter, Server, SinglePasswordAuth};
use std::sync::atomic::{AtomicUsize, Ordering};

const PASSWORD: &str = "test-password-e2e";

static INIT_CRYPTO: Once = Once::new();

fn install_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install CryptoProvider");
    });
}

/// Generate a self-signed TLS certificate and return (server_config, client_config).
fn make_tls_configs() -> (rustls::ServerConfig, Arc<rustls::ClientConfig>) {
    install_crypto_provider();
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    // Server config
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    // Client config — trust the self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (server_config, Arc::new(client_config))
}

/// Start a simple TCP echo server. Returns the listening port.
async fn start_echo_server() -> (u16, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                result = listener.accept() => {
                    if let Ok((mut stream, _)) = result {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    (port, cancel)
}

fn encode_frame(cmd: Command, stream_id: u32, data: &[u8]) -> Vec<u8> {
    let header = FrameHeader {
        command: cmd,
        stream_id,
        length: data.len() as u16,
    };
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);
    let mut out = hdr_buf.to_vec();
    out.extend_from_slice(data);
    out
}

fn make_auth_packet(password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let mut packet = Vec::new();
    packet.extend_from_slice(&hash);
    // padding length = 0
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet
}

/// Build a SOCKS5-style IPv4 address: type(0x01) + ip(4) + port(2)
fn socks5_ipv4_addr(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut data = vec![0x01];
    data.extend_from_slice(&ip);
    data.extend_from_slice(&port.to_be_bytes());
    data
}

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> Option<(FrameHeader, Vec<u8>)> {
    let mut hdr_buf = [0u8; HEADER_SIZE];
    match tokio::time::timeout(Duration::from_secs(3), reader.read_exact(&mut hdr_buf)).await {
        Ok(Ok(_)) => {}
        _ => return None,
    }
    let header = FrameHeader::decode(&hdr_buf);
    let mut data = vec![0u8; header.length as usize];
    if header.length > 0 {
        reader.read_exact(&mut data).await.ok()?;
    }
    Some((header, data))
}

#[tokio::test]
async fn test_full_e2e_echo() {
    // 1. Start echo server
    let (echo_port, echo_cancel) = start_echo_server().await;

    // 2. Build AnyTLS server
    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let server_handle = tokio::spawn(async move {
        server.run(listener, shutdown_clone).await.unwrap();
    });

    // 3. Client connects
    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    let connector = TlsConnector::from(tls_client_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // 4. Send auth
    let auth_packet = make_auth_packet(PASSWORD);
    tls.write_all(&auth_packet).await.unwrap();

    // 5. Send Settings frame
    let settings_data = format!("v=2\npadding-md5={}", padding_md5);
    let settings_frame = encode_frame(Command::Settings, 0, settings_data.as_bytes());
    tls.write_all(&settings_frame).await.unwrap();

    // 6. Read server responses (ServerSettings, possibly UpdatePaddingScheme)
    // We just drain any control frames until we're ready to send SYN
    let mut got_server_settings = false;
    for _ in 0..5 {
        if let Some((hdr, _data)) = read_frame(&mut tls).await {
            if hdr.command == Command::ServerSettings {
                got_server_settings = true;
                break;
            }
        } else {
            break;
        }
    }
    assert!(got_server_settings, "did not receive ServerSettings");

    // 7. Send SYN to open stream 1
    let syn_frame = encode_frame(Command::Syn, 1, &[]);
    tls.write_all(&syn_frame).await.unwrap();

    // 8. Send PSH with SOCKS5 address (127.0.0.1:echo_port) + trailing payload
    let mut psh_payload = socks5_ipv4_addr([127, 0, 0, 1], echo_port);
    let test_data = b"Hello, AnyTLS!";
    psh_payload.extend_from_slice(test_data);
    let psh_frame = encode_frame(Command::Psh, 1, &psh_payload);
    tls.write_all(&psh_frame).await.unwrap();
    tls.flush().await.unwrap();

    // 9. Read back: expect SynAck (v2 handshake success) then PSH with echoed data
    let mut got_synack = false;
    let mut echoed_data = Vec::new();

    for _ in 0..10 {
        if let Some((hdr, data)) = read_frame(&mut tls).await {
            match hdr.command {
                Command::SynAck => {
                    got_synack = true;
                    // Empty SynAck = success
                    assert!(data.is_empty(), "SynAck should be empty for success");
                }
                Command::Psh if hdr.stream_id == 1 => {
                    echoed_data.extend_from_slice(&data);
                    if echoed_data.len() >= test_data.len() {
                        break;
                    }
                }
                _ => {
                    // skip other frames
                }
            }
        } else {
            break;
        }
    }

    assert!(got_synack, "did not receive SynAck");
    assert_eq!(
        &echoed_data[..test_data.len()],
        test_data,
        "echoed data mismatch"
    );

    // 10. Cleanup
    shutdown.cancel();
    echo_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn test_auth_failure() {
    let (tls_server_config, tls_client_config) = make_tls_configs();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    let connector = TlsConnector::from(tls_client_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // Send wrong password
    let auth_packet = make_auth_packet("wrong-password");
    tls.write_all(&auth_packet).await.unwrap();
    tls.flush().await.unwrap();

    // Server should close the connection — reading should return EOF or error
    let mut buf = [0u8; 128];
    let result = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Expected: connection closed or error
        }
        Ok(Ok(n)) => {
            panic!(
                "expected connection close after auth failure, got {} bytes",
                n
            );
        }
    }

    shutdown.cancel();
}

#[tokio::test]
async fn test_heartbeat() {
    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    let connector = TlsConnector::from(tls_client_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // Auth
    tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();

    // Settings
    let settings_data = format!("v=2\npadding-md5={}", padding_md5);
    tls.write_all(&encode_frame(
        Command::Settings,
        0,
        settings_data.as_bytes(),
    ))
    .await
    .unwrap();

    // Drain ServerSettings
    for _ in 0..3 {
        if let Some((hdr, _)) = read_frame(&mut tls).await
            && hdr.command == Command::ServerSettings
        {
            break;
        }
    }

    // Send HeartRequest
    tls.write_all(&encode_frame(Command::HeartRequest, 0, &[]))
        .await
        .unwrap();
    tls.flush().await.unwrap();

    // Expect HeartResponse
    let mut got_heart = false;
    for _ in 0..5 {
        if let Some((hdr, _)) = read_frame(&mut tls).await {
            if hdr.command == Command::HeartResponse {
                got_heart = true;
                break;
            }
        } else {
            break;
        }
    }
    assert!(got_heart, "did not receive HeartResponse");

    shutdown.cancel();
}

#[tokio::test]
async fn test_tls_session_resumption() {
    let (tls_server_config, tls_client_config) = make_tls_configs();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let connector = TlsConnector::from(tls_client_config.clone());
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    // First connection — must be a full handshake.
    // We send auth + settings and read back ServerSettings so the client
    // receives the server's NewSessionTicket post-handshake message.
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();
    {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .await
            .unwrap();
        let mut tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "first connection should be a full handshake"
        );

        // Complete the protocol handshake so session ticket is received
        tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();
        let settings_data = format!("v=2\npadding-md5={}", padding_md5);
        tls.write_all(&encode_frame(
            Command::Settings,
            0,
            settings_data.as_bytes(),
        ))
        .await
        .unwrap();
        tls.flush().await.unwrap();

        // Read ServerSettings (this also processes any queued NewSessionTicket)
        for _ in 0..5 {
            if let Some((hdr, _)) = read_frame(&mut tls).await
                && hdr.command == Command::ServerSettings
            {
                break;
            }
        }
    }

    // Brief pause so the server processes the session ticket
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second connection — should resume via session ticket
    {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .await
            .unwrap();
        let tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "second connection should use TLS session resumption"
        );
    }

    shutdown.cancel();
}

/// Verify that the accept loop is not blocked when all semaphore permits are held.
/// The semaphore is acquired after TLS handshake + auth (inside the handler),
/// so new connections can still complete TLS handshake even at max capacity.
///
/// Creates a server with max_connections=2, holds 2 connections, then verifies
/// a 3rd connection can complete TLS handshake within 500ms.
#[tokio::test]
async fn test_accept_loop_not_blocked_by_semaphore() {
    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    // Server with max_connections=2
    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .max_connections(2)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let connector = TlsConnector::from(tls_client_config.clone());
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    // Open 2 connections that complete handshake and hold permits
    let mut held_connections = Vec::new();
    for _ in 0..2 {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .await
            .unwrap();
        let mut tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        // Complete auth + settings so the connection is fully established
        tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();
        let settings_data = format!("v=2\npadding-md5={}", padding_md5);
        tls.write_all(&encode_frame(
            Command::Settings,
            0,
            settings_data.as_bytes(),
        ))
        .await
        .unwrap();
        tls.flush().await.unwrap();
        // Read ServerSettings to confirm session is established
        for _ in 0..5 {
            if let Some((hdr, _)) = read_frame(&mut tls).await
                && hdr.command == Command::ServerSettings
            {
                break;
            }
        }
        held_connections.push(tls);
    }

    // Both permits are now held. Try to open a 3rd connection and complete TLS handshake.
    // TCP connect may succeed (kernel backlog), but the TLS handshake requires the
    // server to accept() from kernel queue. With the current bug, the accept loop is
    // blocked on semaphore.acquire_owned(), so accept() is never called and the TLS
    // handshake hangs indefinitely.
    let connector3 = TlsConnector::from(tls_client_config.clone());
    let server_name3 = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let handshake_result = tokio::time::timeout(Duration::from_millis(500), async {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port)).await?;
        let _tls = connector3.connect(server_name3, tcp).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;

    assert!(
        handshake_result.is_ok(),
        "3rd connection TLS handshake timed out — accept loop is blocked by semaphore"
    );
    assert!(
        handshake_result.unwrap().is_ok(),
        "3rd connection TLS handshake failed"
    );

    // Cleanup
    drop(held_connections);
    shutdown.cancel();
}

/// Verify the server handles a burst of concurrent connections under load.
/// Even with all semaphore permits held, new connections complete TLS handshake
/// because the accept loop is never blocked by the semaphore.
///
/// Creates a server with max_connections=5, holds 5 connections, then fires
/// 10 parallel connections and asserts at least 5 complete TLS handshake within 500ms.
#[tokio::test]
async fn test_burst_connections_accepted_under_load() {
    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .max_connections(5)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let connector = TlsConnector::from(tls_client_config.clone());
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    // Fill all 5 slots with established connections
    let mut held = Vec::new();
    for _ in 0..5 {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .await
            .unwrap();
        let mut tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();
        let settings_data = format!("v=2\npadding-md5={}", padding_md5);
        tls.write_all(&encode_frame(
            Command::Settings,
            0,
            settings_data.as_bytes(),
        ))
        .await
        .unwrap();
        tls.flush().await.unwrap();
        for _ in 0..5 {
            if let Some((hdr, _)) = read_frame(&mut tls).await
                && hdr.command == Command::ServerSettings
            {
                break;
            }
        }
        held.push(tls);
    }

    // All 5 permits held. Fire 10 connections in parallel and try TLS handshake.
    // With the current bug, accept loop is blocked so TLS handshakes never start.
    // After the fix, connections should be accepted and queued for permits.
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..10 {
        let count = success_count.clone();
        let port = server_port;
        let cli_cfg = tls_client_config.clone();
        handles.push(tokio::spawn(async move {
            let result = tokio::time::timeout(Duration::from_millis(500), async {
                let tcp = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
                let connector = TlsConnector::from(cli_cfg);
                let sn = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                let _tls = connector.connect(sn, tcp).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await;
            if let Ok(Ok(())) = result {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let connected = success_count.load(Ordering::Relaxed);
    assert!(
        connected >= 5,
        "only {connected}/10 burst TLS handshakes completed — \
         accept loop blocked by semaphore"
    );

    drop(held);
    shutdown.cancel();
}
