//!
//! Benchmark MSS
//!
use criterion::{criterion_group, criterion_main, Criterion};
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

    c.bench_function("MSS_GENERATE_SK", |b| {
        b.iter(|| {
            MssV1PrivateKeyGenerator::<MamSpongos, WotsV1PrivateKeyGenerator<MamSpongos>>::generate(
                &seed_trits,
                &nonce,
                5,
                2,
            )
            .unwrap();
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
