//! Benchmark: settings response write — coalesced single write vs multiple writes.
//!
//! Measures the overhead difference between writing UpdatePaddingScheme and
//! ServerSettings as separate write_all calls vs a single coalesced buffer.

use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use tokio::io::AsyncWriteExt;

const ITERATIONS: usize = 10_000;

/// Old approach: separate write_all calls per frame (may create separate TLS records).
async fn write_settings_separate<W: AsyncWriteExt + Unpin>(w: &mut W, padding_data: &[u8]) {
    // UpdatePaddingScheme
    let header = FrameHeader {
        command: Command::UpdatePaddingScheme,
        stream_id: 0,
        length: padding_data.len() as u16,
    };
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);
    w.write_all(&hdr_buf).await.unwrap();
    w.write_all(padding_data).await.unwrap();

    // ServerSettings
    let header = FrameHeader {
        command: Command::ServerSettings,
        stream_id: 0,
        length: 3,
    };
    header.encode(&mut hdr_buf);
    let mut buf = [0u8; HEADER_SIZE + 3];
    buf[..HEADER_SIZE].copy_from_slice(&hdr_buf);
    buf[HEADER_SIZE..].copy_from_slice(b"v=2");
    w.write_all(&buf).await.unwrap();

    w.flush().await.unwrap();
}

/// Optimized approach: coalesce all frames into a single write_all call.
async fn write_settings_coalesced<W: AsyncWriteExt + Unpin>(w: &mut W, padding_data: &[u8]) {
    let total = (HEADER_SIZE + padding_data.len()) + (HEADER_SIZE + 3);
    let mut buf = Vec::with_capacity(total);

    // UpdatePaddingScheme
    let header = FrameHeader {
        command: Command::UpdatePaddingScheme,
        stream_id: 0,
        length: padding_data.len() as u16,
    };
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);
    buf.extend_from_slice(&hdr_buf);
    buf.extend_from_slice(padding_data);

    // ServerSettings
    let header = FrameHeader {
        command: Command::ServerSettings,
        stream_id: 0,
        length: 3,
    };
    header.encode(&mut hdr_buf);
    buf.extend_from_slice(&hdr_buf);
    buf.extend_from_slice(b"v=2");

    w.write_all(&buf).await.unwrap();
    w.flush().await.unwrap();
}

fn bench_settings_response(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_data = padding.raw_scheme().as_bytes().to_vec();

    let mut group = c.benchmark_group("settings_response");

    group.bench_function("separate_writes", |b| {
        let data = padding_data.clone();
        b.iter(|| {
            rt.block_on(async {
                let mut sink = tokio::io::sink();
                for _ in 0..ITERATIONS {
                    write_settings_separate(&mut sink, &data).await;
                }
            })
        });
    });

    group.bench_function("coalesced_write", |b| {
        let data = padding_data.clone();
        b.iter(|| {
            rt.block_on(async {
                let mut sink = tokio::io::sink();
                for _ in 0..ITERATIONS {
                    write_settings_coalesced(&mut sink, &data).await;
                }
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_settings_response);
criterion_main!(benches);
