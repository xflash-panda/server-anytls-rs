//! RED/GREEN benchmark: DNS resolution overhead in the routing + connect path.
//!
//! Measures the cost of DNS resolution in two scenarios:
//! 1. `route_then_connect` — current code: route() resolves DNS for private IP check,
//!    then connect_target() resolves DNS again. Two DNS lookups per stream.
//! 2. `route_with_resolved` — optimized: route() resolves DNS once and passes the
//!    resolved IP to connect, avoiding the duplicate lookup.
//!
//! Also measures repeated lookups for the same domain (cache miss penalty).

use criterion::{Criterion, criterion_group, criterion_main};
use std::net::SocketAddr;
/// Simulate the CURRENT code path: two separate DNS resolutions.
async fn double_dns_lookup(domain: &str, port: u16) -> Option<SocketAddr> {
    // First lookup: what route() does for private IP check
    let _first = tokio::net::lookup_host(format!("{}:{}", domain, 0))
        .await
        .ok();

    // Second lookup: what connect_target() does via TcpStream::connect
    let second = tokio::net::lookup_host(format!("{}:{}", domain, port))
        .await
        .ok()?;
    second.into_iter().next()
}

/// Simulate the OPTIMIZED path: one DNS resolution, reuse the result.
async fn single_dns_lookup(domain: &str, port: u16) -> Option<SocketAddr> {
    let mut addrs = tokio::net::lookup_host(format!("{}:{}", domain, port))
        .await
        .ok()?;
    addrs.next()
}

/// Benchmark: double vs single DNS resolution per stream (real DNS).
fn bench_dns_resolution(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("dns_resolution");
    group.sample_size(20);

    // Use a real domain that will actually hit the resolver
    let domain = "example.com";
    let port = 80u16;

    group.bench_function("double_lookup_current", |b| {
        b.iter(|| rt.block_on(async { double_dns_lookup(domain, port).await }));
    });

    group.bench_function("single_lookup_optimized", |b| {
        b.iter(|| rt.block_on(async { single_dns_lookup(domain, port).await }));
    });

    group.finish();
}

/// Benchmark: repeated lookups for the same domain (no cache vs cached).
/// Shows the cost of resolving the same domain N times without caching.
fn bench_dns_repeated(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("dns_repeated_lookups");
    group.sample_size(10);

    let domain = "example.com";
    let n = 50; // simulate 50 streams to the same domain

    group.bench_function("50x_uncached_lookups", |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..n {
                    let _ = tokio::net::lookup_host(format!("{}:80", domain)).await;
                }
            })
        });
    });

    group.bench_function("50x_cached_resolve_once", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Resolve once, reuse N times
                let resolved = tokio::net::lookup_host(format!("{}:80", domain))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next());
                for _ in 0..n {
                    let _ = std::hint::black_box(&resolved);
                }
            })
        });
    });

    group.finish();
}

/// Micro-benchmark: raw cost of a single tokio::net::lookup_host call.
fn bench_dns_single_call(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("dns_single_call");
    group.sample_size(30);

    group.bench_function("lookup_host_example_com", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = tokio::net::lookup_host("example.com:80").await;
            })
        });
    });

    // Compare with IP address (no DNS needed) — baseline
    group.bench_function("lookup_host_ip_addr", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = tokio::net::lookup_host("93.184.216.34:80").await;
            })
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_dns_single_call,
    bench_dns_resolution,
    bench_dns_repeated
);
criterion_main!(benches);
