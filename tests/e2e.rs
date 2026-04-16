//! End-to-end integration test for the AnyTLS protocol.
//!
//! Flow:
//! 1. Start a TCP echo server on a random port.
//! 2. Start the AnyTLS server (TLS + auth + session) on another random port.
//! 3. A simulated client connects via TLS, authenticates, exchanges settings,
//!    opens a stream (SYN) with SOCKS5 address pointing to the echo server,
//!    sends data (PSH), and reads back the echoed response.

use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::{DirectRouter, Server, SinglePasswordAuth};

const PASSWORD: &str = "test-password-e2e";

/// Generate a self-signed TLS certificate and return (server_config, root_cert_der).
fn make_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));

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

    (Arc::new(server_config), Arc::new(client_config))
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

async fn read_frame(
    reader: &mut (impl AsyncReadExt + Unpin),
) -> Option<(FrameHeader, Vec<u8>)> {
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
            .build(),
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
            .build(),
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
            panic!("expected connection close after auth failure, got {} bytes", n);
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
            .build(),
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
    tls.write_all(&encode_frame(Command::Settings, 0, settings_data.as_bytes()))
        .await
        .unwrap();

    // Drain ServerSettings
    for _ in 0..3 {
        if let Some((hdr, _)) = read_frame(&mut tls).await {
            if hdr.command == Command::ServerSettings {
                break;
            }
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
