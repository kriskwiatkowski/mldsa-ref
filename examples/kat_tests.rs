// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! KAT (Known Answer Tests) for ML-DSA implementation
//! Tests key generation, signature generation, and signature verification
//! using NIST FIPS-204 test vectors

use mldsa::*;
use serde::Deserialize;
use std::fs;
use std::path::Path;

// KAT deserialization
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestFile {
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    tg_id: u32,
    parameter_set: String,
    #[serde(default)]
    deterministic: Option<bool>,
    #[serde(default)]
    pre_hash: Option<String>,
    #[serde(default)]
    signature_interface: Option<String>,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Test {
    tc_id: u32,
    #[serde(default)]
    seed: Option<String>,
    #[serde(default)]
    sk: Option<String>,
    #[serde(default)]
    pk: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    hash_alg: Option<String>,
    #[serde(default)]
    mu: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedResult {
    #[allow(dead_code)]
    tc_id: u32,
    #[serde(default)]
    pk: Option<String>,
    #[serde(default)]
    sk: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    test_passed: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedFile {
    test_groups: Vec<ExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedGroup {
    #[allow(dead_code)]
    tg_id: u32,
    tests: Vec<ExpectedResult>,
}

// Helper Functions
fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("Invalid hex string")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes).to_uppercase()
}

fn print_result<T: std::fmt::Debug>(label: &str, passed: i32, total: i32, failed_tests: &[T]) {
    println!(
        "{}{} Results: {}/{} tests passed",
        " ".repeat(10),
        label,
        passed,
        total
    );

    if !failed_tests.is_empty() {
        println!("Failed tests: {:?}", failed_tests);
    }
}

// KAT: Key Generation Tests
fn run_keygen_kat() {
    let kat_dir = "FIPS-204";
    let prompt_file = Path::new(kat_dir).join("keyGen/prompt.json");
    let expected_file = Path::new(kat_dir).join("keyGen/expectedResults.json");

    println!("Testing ML-DSA Key Generation");
    let prompt_data: TestFile = serde_json::from_str(
        &fs::read_to_string(&prompt_file).expect("Failed to read prompt file"),
    )
    .expect("Failed to parse prompt JSON");

    let expected_data: ExpectedFile = serde_json::from_str(
        &fs::read_to_string(&expected_file).expect("Failed to read expected file"),
    )
    .expect("Failed to parse expected JSON");

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut failed_tests = Vec::new();

    for (tg_prompt, tg_expected) in prompt_data
        .test_groups
        .iter()
        .zip(expected_data.test_groups.iter())
    {
        let param_set = &tg_prompt.parameter_set;
        let tg_id = tg_prompt.tg_id;

        let param = MLDSAParameters::new(param_set)
            .expect(&format!("Invalid parameter set: {}", param_set));

        for (test_prompt, test_expected) in tg_prompt.tests.iter().zip(tg_expected.tests.iter()) {
            let tc_id = test_prompt.tc_id;
            total_tests += 1;

            let seed = hex_to_bytes(test_prompt.seed.as_ref().unwrap());
            let expected_pk = hex_to_bytes(test_expected.pk.as_ref().unwrap());
            let expected_sk = hex_to_bytes(test_expected.sk.as_ref().unwrap());

            // Generate key pair
            let mut pk = vec![0u8; 5000];
            let mut sk = vec![0u8; 5000];
            let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
            pk.truncate(pk_len);
            sk.truncate(sk_len);

            // Check results
            let pk_match = pk == expected_pk;
            let sk_match = sk == expected_sk;

            if pk_match && sk_match {
                passed_tests += 1;
            } else {
                failed_tests.push((tg_id, tc_id, param_set.clone()));
                println!("  Test {}: FAIL", tc_id);
                if !pk_match {
                    println!("    PK mismatch");
                    println!(
                        "    Expected: {}...",
                        &bytes_to_hex(&expected_pk)[..80.min(expected_pk.len() * 2)]
                    );
                    println!(
                        "    Got:      {}...",
                        &bytes_to_hex(&pk)[..80.min(pk.len() * 2)]
                    );
                }
                if !sk_match {
                    println!("    SK mismatch");
                    println!(
                        "    Expected: {}...",
                        &bytes_to_hex(&expected_sk)[..80.min(expected_sk.len() * 2)]
                    );
                    println!(
                        "    Got:      {}...",
                        &bytes_to_hex(&sk)[..80.min(sk.len() * 2)]
                    );
                }
            }
        }
    }

    print_result("KeyGen", passed_tests, total_tests, failed_tests.as_slice());
}

// KAT: Signature Generation (Deterministic only)
fn run_siggen_kat() {
    let kat_dir = "FIPS-204";
    let prompt_file = Path::new(kat_dir).join("sigGen/prompt.json");
    let expected_file = Path::new(kat_dir).join("sigGen/expectedResults.json");

    println!("Testing ML-DSA Signature Generation");

    let prompt_data: TestFile = serde_json::from_str(
        &fs::read_to_string(&prompt_file).expect("Failed to read prompt file"),
    )
    .expect("Failed to parse prompt JSON");

    let expected_data: ExpectedFile = serde_json::from_str(
        &fs::read_to_string(&expected_file).expect("Failed to read expected file"),
    )
    .expect("Failed to parse expected JSON");

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut failed_tests = Vec::new();

    for (tg_prompt, tg_expected) in prompt_data
        .test_groups
        .iter()
        .zip(expected_data.test_groups.iter())
    {
        // Only test deterministic signatures
        if !tg_prompt.deterministic.unwrap_or(true) {
            continue;
        }

        let param_set = &tg_prompt.parameter_set;
        let tg_id = tg_prompt.tg_id;
        let pre_hash_mode = tg_prompt
            .pre_hash
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("pure");
        let signature_interface = tg_prompt
            .signature_interface
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("internal");

        let param = MLDSAParameters::new(param_set)
            .expect(&format!("Invalid parameter set: {}", param_set));

        for (test_prompt, test_expected) in tg_prompt.tests.iter().zip(tg_expected.tests.iter()) {
            let tc_id = test_prompt.tc_id;

            // Skip tests that use mu instead of message
            if test_prompt.mu.is_some() || test_prompt.message.is_none() {
                continue;
            }

            total_tests += 1;

            let sk = hex_to_bytes(test_prompt.sk.as_ref().unwrap());
            let message = hex_to_bytes(test_prompt.message.as_ref().unwrap());
            let ctx = hex_to_bytes(test_prompt.context.as_ref().unwrap_or(&String::new()));
            let expected_sig = hex_to_bytes(test_expected.signature.as_ref().unwrap());
            let hash_alg = test_prompt
                .hash_alg
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("SHA2-512");

            // Generate signature based on pre-hash mode and interface
            let signature = if pre_hash_mode == "preHash" {
                let mut sig = vec![0u8; 5000];
                let sig_len =
                    hash_ml_dsa_sign(&param, &sk, &message, &ctx, true, hash_alg, &mut sig)
                        .expect("hash_ml_dsa_sign failed");
                sig.truncate(sig_len);
                sig
            } else if signature_interface == "external" {
                // External interface: M' = 0 || len(ctx) || ctx || M
                let mut m_prime = vec![0u8, ctx.len() as u8];
                m_prime.extend_from_slice(&ctx);
                m_prime.extend_from_slice(&message);
                {
                    let mut sig = vec![0u8; 5000];
                    let sig_len = sign(&param, &sk, &m_prime, true, &mut sig);
                    sig.truncate(sig_len);
                    sig
                }
            } else {
                // Internal interface: use message directly
                {
                    let mut sig = vec![0u8; 5000];
                    let sig_len = sign(&param, &sk, &message, true, &mut sig);
                    sig.truncate(sig_len);
                    sig
                }
            };

            // ML-DSA sigGen is deterministic for a given (sk, message, rnd=0), so a
            // correct implementation must reproduce the expected bytes exactly.
            if signature == expected_sig {
                passed_tests += 1;
            } else {
                failed_tests.push((tg_id, tc_id, param_set.clone(), pre_hash_mode.to_string()));
                println!("  Test {}: FAIL", tc_id);
                if signature.len() != expected_sig.len() {
                    println!(
                        "    Signature length mismatch: expected {}, got {}",
                        expected_sig.len(),
                        signature.len()
                    );
                } else {
                    println!("    Signature content mismatch (length matched)");
                }
            }
        }
    }
    print_result("SigGen", passed_tests, total_tests, failed_tests.as_slice());
}

// KAT: Signature Verification Tests
fn run_sigver_kat() {
    let kat_dir = "FIPS-204";
    let prompt_file = Path::new(kat_dir).join("sigVer/prompt.json");
    let expected_file = Path::new(kat_dir).join("sigVer/expectedResults.json");

    println!("Testing ML-DSA Signature Verification");
    let prompt_data: TestFile = serde_json::from_str(
        &fs::read_to_string(&prompt_file).expect("Failed to read prompt file"),
    )
    .expect("Failed to parse prompt JSON");

    let expected_data: ExpectedFile = serde_json::from_str(
        &fs::read_to_string(&expected_file).expect("Failed to read expected file"),
    )
    .expect("Failed to parse expected JSON");

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut failed_tests = Vec::new();

    for (tg_prompt, tg_expected) in prompt_data
        .test_groups
        .iter()
        .zip(expected_data.test_groups.iter())
    {
        let param_set = &tg_prompt.parameter_set;
        let tg_id = tg_prompt.tg_id;
        let pre_hash_mode = tg_prompt
            .pre_hash
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("pure");
        let signature_interface = tg_prompt
            .signature_interface
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("internal");

        let param = MLDSAParameters::new(param_set)
            .expect(&format!("Invalid parameter set: {}", param_set));

        for (test_prompt, test_expected) in tg_prompt.tests.iter().zip(tg_expected.tests.iter()) {
            let tc_id = test_prompt.tc_id;

            // Skip tests that use mu instead of message
            if test_prompt.mu.is_some() || test_prompt.message.is_none() {
                continue;
            }

            total_tests += 1;

            let pk = hex_to_bytes(test_prompt.pk.as_ref().unwrap());
            let message = hex_to_bytes(test_prompt.message.as_ref().unwrap());
            let signature = hex_to_bytes(test_prompt.signature.as_ref().unwrap());
            let ctx = hex_to_bytes(test_prompt.context.as_ref().unwrap_or(&String::new()));
            let hash_alg = test_prompt
                .hash_alg
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("SHA2-512");
            let expected_result = test_expected.test_passed.unwrap_or(false);

            // Verify signature based on pre-hash mode and interface
            let result = if pre_hash_mode == "preHash" {
                hash_ml_dsa_verify(&param, &pk, &message, &signature, &ctx, hash_alg)
            } else if signature_interface == "external" {
                // External interface: M' = 0 || len(ctx) || ctx || M
                let mut m_prime = vec![0u8, ctx.len() as u8];
                m_prime.extend_from_slice(&ctx);
                m_prime.extend_from_slice(&message);
                verify(&param, &pk, &m_prime, &signature)
            } else {
                // Internal interface: use message directly
                verify(&param, &pk, &message, &signature)
            };

            // Check result
            if result == expected_result {
                passed_tests += 1;
            } else {
                failed_tests.push((tg_id, tc_id, param_set.clone(), pre_hash_mode.to_string()));
                println!("  Test {}: FAIL", tc_id);
                println!("    Expected: {}, Got: {}", expected_result, result);
            }
        }
    }

    print_result("SigVer", passed_tests, total_tests, failed_tests.as_slice());
}

// Run all
fn main() {
    run_keygen_kat();
    run_siggen_kat();
    run_sigver_kat();
}
