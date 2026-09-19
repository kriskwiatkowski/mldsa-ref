// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mldsa::{generate_key, sign, verify, MLDSAParameters};

fn benchmark_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    let parameter_sets = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
    let seed = vec![0u8; 32];

    for param_name in parameter_sets.iter() {
        let param = MLDSAParameters::new(param_name).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    let mut pk = vec![0u8; 2592];
                    let mut sk = vec![0u8; 4896];
                    generate_key(black_box(param), black_box(&seed), &mut pk, &mut sk)
                });
            },
        );
    }

    group.finish();
}

fn benchmark_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");

    let parameter_sets = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
    let seed = vec![0u8; 32];
    let message = b"Benchmark message for signing test";

    for param_name in parameter_sets.iter() {
        let param = MLDSAParameters::new(param_name).unwrap();
        let mut pk = vec![0u8; 2592];
        let mut sk = vec![0u8; 4896];
        let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
        pk.truncate(pk_len);
        sk.truncate(sk_len);

        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    let mut sig = vec![0u8; 4627];
                    sign(
                        black_box(param),
                        black_box(&sk),
                        black_box(message),
                        black_box(true),
                        &mut sig,
                    )
                });
            },
        );
    }

    group.finish();
}

fn benchmark_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    let parameter_sets = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
    let seed = vec![0u8; 32];
    let message = b"Benchmark message for verification test";

    for param_name in parameter_sets.iter() {
        let param = MLDSAParameters::new(param_name).unwrap();
        let mut pk = vec![0u8; 2592];
        let mut sk = vec![0u8; 4896];
        let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
        pk.truncate(pk_len);
        sk.truncate(sk_len);
        let mut signature = vec![0u8; 4627];
        let sig_len = sign(&param, &sk, message, true, &mut signature);
        signature.truncate(sig_len);

        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    verify(
                        black_box(param),
                        black_box(&pk),
                        black_box(message),
                        black_box(&signature),
                    )
                });
            },
        );
    }

    group.finish();
}

fn benchmark_sign_verify_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_verify_roundtrip");

    let parameter_sets = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
    let seed = vec![0u8; 32];
    let message = b"Benchmark message for roundtrip test";

    for param_name in parameter_sets.iter() {
        let param = MLDSAParameters::new(param_name).unwrap();
        let mut pk = vec![0u8; 2592];
        let mut sk = vec![0u8; 4896];
        let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
        pk.truncate(pk_len);
        sk.truncate(sk_len);

        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    let mut sig = vec![0u8; 4627];
                    let sig_len = sign(
                        black_box(param),
                        black_box(&sk),
                        black_box(message),
                        black_box(true),
                        &mut sig,
                    );
                    sig.truncate(sig_len);
                    verify(
                        black_box(param),
                        black_box(&pk),
                        black_box(message),
                        black_box(&sig),
                    )
                });
            },
        );
    }

    group.finish();
}

fn benchmark_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_message_sizes");

    let param = MLDSAParameters::new("ML-DSA-44").unwrap();
    let seed = vec![0u8; 32];
    let mut pk = vec![0u8; 2592];
    let mut sk = vec![0u8; 4896];
    let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
    pk.truncate(pk_len);
    sk.truncate(sk_len);

    let message_sizes = [64, 256, 1024, 4096, 16384];

    for size in message_sizes.iter() {
        let message = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &message, |b, msg| {
            b.iter(|| {
                let mut sig = vec![0u8; 4627];
                sign(
                    black_box(&param),
                    black_box(&sk),
                    black_box(msg),
                    black_box(true),
                    &mut sig,
                )
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_keygen,
    benchmark_sign,
    benchmark_verify,
    benchmark_sign_verify_roundtrip,
    benchmark_message_sizes
);
criterion_main!(benches);
