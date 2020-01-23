//!
//! Benchmark Sponge
//!
use criterion::{criterion_group, criterion_main, Criterion};
use iota_conversion::Trinary;
use mam_rs::{
    definitions::{Sponge, Transform},
    sponge::{MamSponge, SpongeCtrl, SpongeTransform, MAM_SPONGE_WIDTH},
    spongos::MamSpongos,
};

fn criterion_benchmark(c: &mut Criterion) {
    let mut state = [0i8; MAM_SPONGE_WIDTH];
    let text = [1i8; 162];
    const TRYTES: &str =
        "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM";

    c.bench_function("SPONGE_TRANSFORM", |b| {
        b.iter(|| {
            SpongeTransform::transform(&mut state);
        })
    });

    c.bench_function("SPONGE_ABS", |b| {
        b.iter(|| {
            let mut layer = MamSponge::default();
            layer.absorb((SpongeCtrl::Key, TRYTES.trits())).unwrap();
        })
    });

    c.bench_function("SPONGE_ABS_SQE", |b| {
        b.iter(|| {
            let mut layer = MamSponge::default();
            layer.absorb((SpongeCtrl::Key, TRYTES.trits())).unwrap();
            layer.squeeze((SpongeCtrl::Prn, 81 * 3));
        })
    });

    c.bench_function("SPONGE_PRN", |b| {
        b.iter(|| {
            let mut layer = MamSponge::default();
            layer.absorb((SpongeCtrl::Key, TRYTES.trits())).unwrap();
            layer.squeeze((SpongeCtrl::Prn, 81 * 162));
        })
    });

    c.bench_function("SPONGE_SPONGOS_HASH", |b| {
        b.iter(|| {
            let mut layer = MamSpongos::default();
            layer.hash(&text, 162).unwrap();
        })
    });

    c.bench_function("SPONGE_SPONGOS_26xHASH", |b| {
        b.iter(|| {
            let mut layer = MamSpongos::default();
            (0..26).for_each(|_| {
                layer.hash(&text, 162).unwrap();
            })
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
