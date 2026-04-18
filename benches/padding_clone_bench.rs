//! Benchmark: PaddingFactory clone cost — HashMap clone vs Arc clone.
//!
//! Measures the per-connection cost of cloning PaddingFactory. With Arc
//! wrapping the inner data, clone is just an atomic refcount increment.

use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};

const ITERATIONS: usize = 100_000;

fn bench_padding_clone(c: &mut Criterion) {
    let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();

    c.bench_function("padding_factory_clone", |b| {
        b.iter(|| {
            for _ in 0..ITERATIONS {
                std::hint::black_box(factory.clone());
            }
        });
    });
}

criterion_group!(benches, bench_padding_clone);
criterion_main!(benches);
