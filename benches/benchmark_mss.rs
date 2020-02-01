//!
//! Benchmark MSS
//!
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use iota_conversion::Trinary;
use mam_rs::{
    definitions::ss::PrivateKeyGenerator, mss::MssPrivateKeyGenerator, spongos::MamSpongos,
    wots::WotsPrivateKeyGenerator,
};

const SEED: &str =
    "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

fn criterion_benchmark(c: &mut Criterion) {
    let seed_trits = SEED.trits();
    let nonce = [0; 18];

    let mut group = c.benchmark_group("Mss");
    group.sample_size(10);
    // We can also use loops to define multiple benchmarks, even over multiple dimensions.
    for it in 2..20 {
        let p_string = format!("MSS With Depth {}", it);
        group.bench_with_input(BenchmarkId::new("Generate", p_string), &it, |b, depth| {
            b.iter(|| {
                let mss_kgen = MssPrivateKeyGenerator::<
                    MamSpongos,
                    WotsPrivateKeyGenerator<MamSpongos>,
                >::from_depth(*depth as usize);
                mss_kgen.generate(&seed_trits, &nonce).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
