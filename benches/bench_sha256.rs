use criterion::{black_box, Criterion, criterion_group, criterion_main};
use sha256::sha256; // Replace `blockchain` with your crate name

fn benchmark_sha256(c: &mut Criterion) {
    let input = "hello world";
    c.bench_function("sha256", |b| {
        b.iter(|| sha256(black_box(input.as_bytes())))
    });
}

criterion_group!(benches, benchmark_sha256);
criterion_main!(benches);
