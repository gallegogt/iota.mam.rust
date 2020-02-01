//!
//! Benchmark WOTS
//!
use criterion::{criterion_group, criterion_main, Criterion};
use iota_conversion::Trinary;
use mam_rs::{
    definitions::ss::{PrivateKey, PrivateKeyGenerator},
    spongos::MamSpongos,
    wots::{WotsPrivateKey, WotsPrivateKeyGenerator},
};

const SEED: &str =
    "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

fn wots_generate_private_key() -> WotsPrivateKey<MamSpongos> {
    let seed_trits = SEED.trits();
    let nonce = [0; 18];
    let wots_kgen: WotsPrivateKeyGenerator<MamSpongos> = WotsPrivateKeyGenerator::default();
    wots_kgen.generate(&seed_trits, &nonce).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let seed_trits = SEED.trits();
    let nonce = [0; 18];
    let wots_kgen: WotsPrivateKeyGenerator<MamSpongos> = WotsPrivateKeyGenerator::default();

    c.bench_function("WOTS_GSK", |b| {
        b.iter(|| {
            let _ = wots_kgen.generate(&seed_trits, &nonce).unwrap();
        })
    });

    // Test Generate Public Key
    let sk = wots_generate_private_key();
    c.bench_function("WOTS_GPK", |b| {
        b.iter(|| {
            sk.generate_public_key();
        })
    });

    c.bench_function("WOTS_GPK", |b| {
        b.iter(|| {
            let sk_ = wots_generate_private_key();
            sk_.generate_public_key();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
