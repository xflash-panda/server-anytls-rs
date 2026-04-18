//! Benchmark: write_frame control frame heap allocation vs stack allocation.
//!
//! Tests the overhead of Vec::with_capacity in write_frame for small control frames
//! (FIN, SynAck, HeartResponse) which are 7 bytes (header only, no payload).

use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use tokio::io::AsyncWriteExt;

const ITERATIONS: usize = 10_000;

/// Current approach: Vec::with_capacity heap allocation per frame.
async fn write_frame_heap<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cmd: Command,
    stream_id: u32,
    data: &[u8],
) {
    let header = FrameHeader {
        command: cmd,
        stream_id,
        length: data.len() as u16,
    };
    let mut buf = Vec::with_capacity(HEADER_SIZE + data.len());
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);
    buf.extend_from_slice(&hdr_buf);
    buf.extend_from_slice(data);
    w.write_all(&buf).await.unwrap();
}

/// Optimized: stack buffer for small frames, Vec only for large ones.
async fn write_frame_stack<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cmd: Command,
    stream_id: u32,
    data: &[u8],
) {
    let header = FrameHeader {
        command: cmd,
        stream_id,
        length: data.len() as u16,
    };
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);

    let total = HEADER_SIZE + data.len();
    if total <= 128 {
        // Stack-allocated buffer for small control frames
        let mut stack_buf = [0u8; 128];
        stack_buf[..HEADER_SIZE].copy_from_slice(&hdr_buf);
        stack_buf[HEADER_SIZE..total].copy_from_slice(data);
        w.write_all(&stack_buf[..total]).await.unwrap();
    } else {
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&hdr_buf);
        buf.extend_from_slice(data);
        w.write_all(&buf).await.unwrap();
    }
}

fn bench_write_frame_alloc(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("write_frame_alloc");

    // Test with empty payload (FIN, SynAck, HeartResponse) — the hottest path
    group.bench_function("heap_empty_payload", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut sink = tokio::io::sink();
                for _ in 0..ITERATIONS {
                    write_frame_heap(&mut sink, Command::Fin, 1, &[]).await;
                }
            })
        });
    });

    group.bench_function("stack_empty_payload", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut sink = tokio::io::sink();
                for _ in 0..ITERATIONS {
                    write_frame_stack(&mut sink, Command::Fin, 1, &[]).await;
                }
            })
        });
    });

    // Test with small payload (e.g. "v=2" for ServerSettings — 3 bytes)
    group.bench_function("heap_small_payload", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut sink = tokio::io::sink();
                for _ in 0..ITERATIONS {
                    write_frame_heap(&mut sink, Command::ServerSettings, 0, b"v=2").await;
                }
            })
        });
    });

    group.bench_function("stack_small_payload", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut sink = tokio::io::sink();
                for _ in 0..ITERATIONS {
                    write_frame_stack(&mut sink, Command::ServerSettings, 0, b"v=2").await;
                }
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_write_frame_alloc);
criterion_main!(benches);
