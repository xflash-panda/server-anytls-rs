//! Benchmark: auth padding read — heap allocation vs stack buffer.
//!
//! Measures the overhead of vec![0u8; N] vs stack [0u8; 1024] for reading
//! and discarding auth padding data.

use criterion::{Criterion, criterion_group, criterion_main};
use tokio::io::AsyncReadExt;

const ITERATIONS: usize = 10_000;
const PADDING_LEN: usize = 512; // Typical padding size

/// Old approach: heap-allocated Vec per read.
async fn read_padding_heap<R: AsyncReadExt + Unpin>(reader: &mut R, len: usize) {
    let mut padding = vec![0u8; len];
    reader.read_exact(&mut padding).await.unwrap();
}

/// Optimized: stack buffer (max 1024 bytes).
async fn read_padding_stack<R: AsyncReadExt + Unpin>(reader: &mut R, len: usize) {
    let mut padding = [0u8; 1024];
    reader.read_exact(&mut padding[..len]).await.unwrap();
}

fn bench_auth_padding(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("auth_padding");

    // Pre-allocate input data once — avoids masking the heap-vs-stack difference
    // with a shared allocation cost in both arms.
    let input_data = vec![0xABu8; PADDING_LEN];

    group.bench_function("heap_alloc", |b| {
        let data = input_data.clone();
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..ITERATIONS {
                    let mut cursor = std::io::Cursor::new(&data);
                    read_padding_heap(&mut cursor, PADDING_LEN).await;
                }
            })
        });
    });

    group.bench_function("stack_buffer", |b| {
        let data = input_data.clone();
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..ITERATIONS {
                    let mut cursor = std::io::Cursor::new(&data);
                    read_padding_stack(&mut cursor, PADDING_LEN).await;
                }
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_auth_padding);
criterion_main!(benches);
