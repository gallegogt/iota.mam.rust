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
    for it in 0..7 {
        let p_string = format!("Private Key With Level {}", it + 3);
        group.bench_with_input(
            BenchmarkId::new("Generate", p_string),
            &(2, it + 3),
            |b, (h_subtree, t_level)| {
                b.iter(|| {
                    let mss_kgen = MssPrivateKeyGenerator::<
                        MamSpongos,
                        WotsPrivateKeyGenerator<MamSpongos>,
                    >::new(
                        *h_subtree as usize, *t_level as usize
                    );
                    mss_kgen.generate(&seed_trits, &nonce).unwrap();
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
