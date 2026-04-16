//! Benchmark: TLS handshake latency — full vs resumed (session tickets).
//!
//! Setup is done once per benchmark group. Each iteration measures only
//! the TCP connect + TLS handshake time.

use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

fn make_tls_configs(
    enable_tickets: bool,
) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    if enable_tickets {
        if let Ok(ticketer) = rustls::crypto::aws_lc_rs::Ticketer::new() {
            server_config.ticketer = ticketer;
        }
    }

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (Arc::new(server_config), Arc::new(client_config))
}

async fn start_tls_server(server_config: Arc<rustls::ServerConfig>) -> (u16, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let acceptor = TlsAcceptor::from(server_config);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                result = listener.accept() => {
                    if let Ok((tcp, _)) = result {
                        let acc = acceptor.clone();
                        tokio::spawn(async move {
                            if let Ok(mut tls) = acc.accept(tcp).await {
                                use tokio::io::AsyncReadExt;
                                let mut buf = [0u8; 1];
                                let _ = tls.read(&mut buf).await;
                            }
                        });
                    }
                }
            }
        }
    });

    (port, cancel)
}

fn bench_tls_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("tls_handshake");
    group.sample_size(50);

    // --- Full handshake (no session tickets) ---
    {
        let (server_config, client_config) = make_tls_configs(false);
        let (port, cancel) = rt.block_on(start_tls_server(server_config));
        let connector = TlsConnector::from(client_config);

        group.bench_function("full_no_tickets", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                    let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
                        .await
                        .unwrap();
                    let _tls = connector.connect(server_name, tcp).await.unwrap();
                })
            });
        });

        cancel.cancel();
    }

    // --- Full handshake (with tickets, but first connection = always full) ---
    {
        let (server_config, client_config) = make_tls_configs(true);
        let (port, cancel) = rt.block_on(start_tls_server(server_config));
        let connector = TlsConnector::from(client_config);

        group.bench_function("full_with_tickets", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                    let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
                        .await
                        .unwrap();
                    let _tls = connector.connect(server_name, tcp).await.unwrap();
                })
            });
        });

        cancel.cancel();
    }

    // --- Resumed handshake (with tickets, warm session cache) ---
    // Each iteration gets a fresh client config + one warm-up connection,
    // but this time we only measure the SECOND connection (resumed).
    {
        let (server_config, client_config) = make_tls_configs(true);
        let (port, cancel) = rt.block_on(start_tls_server(server_config));
        let connector = TlsConnector::from(client_config);

        // Warm up: first connection to cache the session ticket
        rt.block_on(async {
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            let _tls = connector.connect(server_name, tcp).await.unwrap();
        });

        group.bench_function("resumed_with_tickets", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
                    let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
                        .await
                        .unwrap();
                    let _tls = connector.connect(server_name, tcp).await.unwrap();
                })
            });
        });

        cancel.cancel();
    }

    group.finish();
}

criterion_group!(benches, bench_tls_handshake);
criterion_main!(benches);
