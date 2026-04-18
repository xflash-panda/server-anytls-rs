//! Benchmark: Address::host_string() allocation overhead.
//!
//! Tests the cost of creating a new String every time host_string() is called,
//! vs returning Cow<str> for domain addresses (zero-alloc for the most common case).

use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::Address;

const ITERATIONS: usize = 100_000;

fn bench_host_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("host_string");

    // Domain address — the most common case in routing
    let domain_addr = Address::Domain("api.example.com".to_string(), 443);

    group.bench_function("domain_host_string_alloc", |b| {
        b.iter(|| {
            for _ in 0..ITERATIONS {
                let s = domain_addr.host_string();
                std::hint::black_box(&s);
            }
        });
    });

    group.bench_function("domain_host_str_borrow", |b| {
        b.iter(|| {
            for _ in 0..ITERATIONS {
                let s = domain_addr.host_str();
                std::hint::black_box(&s);
            }
        });
    });

    // IPv4 address — always needs formatting
    let ipv4_addr = Address::IPv4([192, 168, 1, 100], 80);

    group.bench_function("ipv4_host_string_alloc", |b| {
        b.iter(|| {
            for _ in 0..ITERATIONS {
                let s = ipv4_addr.host_string();
                std::hint::black_box(&s);
            }
        });
    });

    group.bench_function("ipv4_host_str_cow", |b| {
        b.iter(|| {
            for _ in 0..ITERATIONS {
                let s = ipv4_addr.host_str();
                std::hint::black_box(&s);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_host_string);
criterion_main!(benches);
