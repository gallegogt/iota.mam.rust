//!
//! Benchmark MSS
//!
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use iota_conversion::Trinary;
use mam_rs::{
    // definitions::ss::{PrivateKey, PublicKey},
    mss::{MssPrivateKeyGenerator, MssV1PrivateKeyGenerator},
    spongos::MamSpongos,
    wots::WotsV1PrivateKeyGenerator,
};

const SEED: &str =
    "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

fn criterion_benchmark(c: &mut Criterion) {
    let seed_trits = SEED.trits();
    let nonce = [0; 18];

    let mut group = c.benchmark_group("Mss");
    group.sample_size(10);
    // We can also use loops to define multiple benchmarks, even over multiple dimensions.
    for it in 0..10 {
        let p_string = format!("Private Key With Level {}", it + 3);
        group.bench_with_input(BenchmarkId::new("Generate", p_string), &(2, it + 3,),
                |b, (h_subtree, t_level)| b.iter(|| {
                    MssV1PrivateKeyGenerator::<MamSpongos, WotsV1PrivateKeyGenerator<MamSpongos>>::generate(
                        &seed_trits,
                        &nonce,
                        *h_subtree as usize,
                        *t_level as usize,
                    )
                    .unwrap();
                }));
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
