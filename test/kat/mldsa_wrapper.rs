// ACVP binary-protocol wrapper around the RustCrypto ml-dsa crate.
// See katwalk::modulewrapper for the shared stdin/stdout framing.

use katwalk::modulewrapper;
use mldsa::{generate_key, hash_ml_dsa_sign, hash_ml_dsa_verify, sign, verify, MLDSAParameters};
use serde::Serialize;

use env_logger::{Builder, Target};
use log::LevelFilter;
use log::{error, info};
use std::fs::OpenOptions;

const UNSUPPORTED: &[u8] = b"unsupported";
const PARAMETER_SETS: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

// Consumers (e.g. acvp-cli) read `deterministic`/`externalMu` as JSON arrays
// of the values supported, per the ACVP capability schema, so a `Some(bool)`
// here is serialized as a single-element array rather than a bare boolean.
fn bool_as_singleton_array<S: serde::Serializer>(
    value: &Option<bool>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(value.iter())
}

// One entry per ACVP mode (keyGen/sigGen/sigVer) this wrapper advertises
// support for. `None` fields are omitted from the serialized JSON via
// `skip_serializing_if`, since ACVP only expects the fields relevant to
// a given mode (e.g. keyGen has no `signatureInterfaces`).
#[derive(Serialize)]
struct Registration {
    algorithm: &'static str,
    mode: &'static str,
    revision: &'static str,
    // Parameter sets supported directly by this mode (keyGen only; sigGen
    // and sigVer instead list theirs per-capability, see `Capability`).
    #[serde(rename = "parameterSets", skip_serializing_if = "Option::is_none")]
    parameter_sets: Option<&'static [&'static str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<Vec<Capability>>,
    // Whether signing is deterministic (rnd = 0).
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "bool_as_singleton_array"
    )]
    deterministic: Option<bool>,
    // Which of "internal"/"external" Sign/Verify interfaces are supported.
    #[serde(
        rename = "signatureInterfaces",
        skip_serializing_if = "Option::is_none"
    )]
    signature_interfaces: Option<&'static [&'static str]>,
    // Whether signing/verifying on a precomputed mu is supported.
    #[serde(
        rename = "externalMu",
        skip_serializing_if = "Option::is_none",
        serialize_with = "bool_as_singleton_array"
    )]
    external_mu: Option<bool>,
    // Supported preHash modes: "pure" (no prehashing) and/or "preHash"
    // (HashML-DSA over an externally hashed message).
    #[serde(rename = "preHash", skip_serializing_if = "Option::is_none")]
    pre_hash: Option<&'static [&'static str]>,
}

#[derive(Serialize)]
struct Capability {
    #[serde(rename = "parameterSets")]
    parameter_sets: &'static [&'static str],
    #[serde(rename = "messageLength")]
    message_length: [LengthDomain; 1],
    #[serde(rename = "hashAlgs")]
    hash_algs: Vec<&'static str>,
    #[serde(rename = "contextLength")]
    context_length: [LengthDomain; 1],
}

#[derive(Serialize)]
struct LengthDomain {
    min: u32,
    max: u32,
    increment: u32,
}

fn config() -> Result<Vec<u8>, String> {
    let internal_capability = || Capability {
        parameter_sets: &PARAMETER_SETS,
        message_length: [LengthDomain {
            min: 8,
            max: 65_536,
            increment: 8,
        }],
        hash_algs: vec![
            "SHA2-224",
            "SHA2-256",
            "SHA2-384",
            "SHA2-512",
            "SHA2-512/224",
            "SHA2-512/256",
            "SHA3-224",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
            "SHAKE-128",
            "SHAKE-256",
        ],
        context_length: [LengthDomain {
            min: 0,
            max: 2040,
            increment: 8,
        }],
    };
    serde_json::to_vec(&vec![
        Registration {
            algorithm: "ML-DSA",
            mode: "keyGen",
            revision: "FIPS204",
            parameter_sets: Some(&PARAMETER_SETS),
            capabilities: None,
            deterministic: None,
            signature_interfaces: None,
            external_mu: None,
            pre_hash: None,
        },
        Registration {
            algorithm: "ML-DSA",
            mode: "sigGen",
            revision: "FIPS204",
            parameter_sets: None, // Not used by the SigGen operation. SigGen uses capabilities instead.
            capabilities: Some(vec![internal_capability()]),
            deterministic: Some(true),
            signature_interfaces: Some(&["external", "internal"]),
            external_mu: Some(false),
            pre_hash: Some(&["pure", "preHash"]),
        },
        Registration {
            algorithm: "ML-DSA",
            mode: "sigVer",
            revision: "FIPS204",
            parameter_sets: None,
            capabilities: Some(vec![internal_capability()]),
            deterministic: None,
            signature_interfaces: Some(&["external", "internal"]),
            external_mu: Some(false),
            pre_hash: Some(&["pure", "preHash"]),
        },
    ])
    .map_err(|e| format!("failed to serialize ML-DSA configuration: {e}"))
}

fn expect_args<'a>(
    args: &'a [Vec<u8>],
    expected: usize,
    command: &str,
) -> Result<&'a [Vec<u8>], String> {
    if args.len() != expected {
        return Err(format!(
            "{command} expects {} arguments, got {}",
            expected - 1,
            args.len().saturating_sub(1)
        ));
    }
    Ok(args)
}

fn keygen(param_set: &str, seed: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let param =
        MLDSAParameters::new(param_set).expect(&format!("Invalid parameter set: {}", param_set));
    let mut pk: Vec<u8> = vec![0; param.public_key_length];
    let mut sk: Vec<u8> = vec![0; param.private_key_length];
    let (pk_len, sk_len) = generate_key(&param, seed, &mut pk, &mut sk);
    if pk_len != param.public_key_length {
        return Err(format!(
            "public key length mismatch: got {}, expected {}",
            pk_len, param.public_key_length
        ));
    }
    if sk_len != param.private_key_length {
        return Err(format!(
            "private key length mismatch: got {}, expected {}",
            sk_len, param.private_key_length
        ));
    }
    Ok(vec![pk, sk])
}

fn sign_internal(param_set: &str, sk: &[u8], message: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let p = MLDSAParameters::new(param_set)
        .map_err(|e| format!("invalid parameter set {param_set}: {e}"))?;
    let mut signature = vec![0; p.signature_length];
    // Only deterministic case supported for pure ML-DSA
    let signature_len = sign(&p, sk, &message, true, &mut signature);
    if signature_len != p.signature_length {
        return Err(format!(
            "signature length mismatch: got {}, expected {}",
            signature_len, p.signature_length
        ));
    }
    Ok(vec![signature])
}

fn sign_external(
    param_set: &str,
    sk: &[u8],
    message: &[u8],
    context: &[u8],
    pre_hash: &[u8],
    hash_alg: &[u8],
    _rnd: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let p = MLDSAParameters::new(param_set)
        .map_err(|e| format!("invalid parameter set {param_set}: {e}"))?;
    let mut signature = vec![0; p.signature_length];
    let signature_len = match pre_hash {
        b"pure" => {
            if !hash_alg.is_empty() {
                return Err("hashAlg must be absent for pure ML-DSA".to_string());
            }
            if context.len() > u8::MAX as usize {
                return Err(format!(
                    "context must be at most 255 bytes, got {}",
                    context.len()
                ));
            }
            // FIPS 204 Algorithm 2 (ML-DSA.Sign): M' = 0x00 || len(ctx) || ctx || M.
            // `sign` is the internal operation and expects this framing already
            // applied, so it must be built here rather than passing `message` raw.
            let mut m_prime = vec![0u8, context.len() as u8];
            m_prime.extend_from_slice(context);
            m_prime.extend_from_slice(message);
            // Only deterministic case supported for pure ML-DSA
            sign(&p, sk, &m_prime, true, &mut signature)
        }
        b"preHash" => {
            let hash_alg = std::str::from_utf8(hash_alg)
                .map_err(|e| format!("invalid hash algorithm: {e}"))?;
            hash_ml_dsa_sign(&p, sk, message, context, true, hash_alg, &mut signature)
                .map_err(|e| format!("ML-DSA pre-hash signing failed: {e}"))?
        }
        _ => {
            return Err(format!(
                "unsupported ML-DSA preHash mode: {}",
                String::from_utf8_lossy(pre_hash)
            ));
        }
    };
    if signature_len != p.signature_length {
        return Err(format!(
            "signature length mismatch: got {}, expected {}",
            signature_len, p.signature_length
        ));
    }
    Ok(vec![signature])
}

fn verify_internal(param_set: &str, pk: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, String> {
    let p = MLDSAParameters::new(param_set)
        .map_err(|e| format!("invalid parameter set {param_set}: {e}"))?;
    // Only deterministic case supported for pure ML-DSA
    Ok(verify(&p, pk, &msg, &sign))
}

fn verify_external(
    param_set: &str,
    pk: &[u8],
    msg: &[u8],
    context: &[u8],
    pre_hash: &[u8],
    hash_alg: &[u8],
    sign: &[u8],
) -> Result<bool, String> {
    let p = MLDSAParameters::new(param_set)
        .map_err(|e| format!("invalid parameter set {param_set}: {e}"))?;
    // Only deterministic case supported for pure ML-DSA
    match pre_hash {
        b"pure" => {
            if !hash_alg.is_empty() {
                return Err("hashAlg must be absent for pure ML-DSA".to_string());
            }
            if context.len() > u8::MAX as usize {
                return Err(format!(
                    "context must be at most 255 bytes, got {}",
                    context.len()
                ));
            }
            // FIPS 204 Algorithm 2 (ML-DSA.Sign): M' = 0x00 || len(ctx) || ctx || M.
            // `sign` is the internal operation and expects this framing already
            // applied, so it must be built here rather than passing `message` raw.
            let mut m_prime = vec![0u8, context.len() as u8];
            m_prime.extend_from_slice(context);
            m_prime.extend_from_slice(msg);
            // Only deterministic case supported for pure ML-DSA
            Ok(verify(&p, pk, &m_prime, &sign))
        }
        b"preHash" => {
            if context.len() > u8::MAX as usize {
                return Err(format!(
                    "context must be at most 255 bytes, got {}",
                    context.len()
                ));
            }
            let hash_alg = std::str::from_utf8(hash_alg)
                .map_err(|e| format!("invalid hash algorithm: {e}"))?;
            Ok(hash_ml_dsa_verify(&p, pk, msg, &sign, context, hash_alg))
        }
        _ => Err(format!(
            "unsupported ML-DSA preHash mode: {}",
            String::from_utf8_lossy(pre_hash)
        )),
    }
}

fn signing_key(param_set: &str, key_format: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let key_format =
        std::str::from_utf8(key_format).map_err(|e| format!("invalid key format: {e}"))?;
    match key_format {
        "seed" => {
            let outputs = keygen(param_set, key)?;
            let Some(sk) = outputs.get(1) else {
                return Err("key generation failed".to_string());
            };
            Ok(sk.clone())
        }
        "expanded" => {
            info!("key {}", hex::encode(&key));
            Ok(key.to_vec())
        }
        _ => return Err(format!("unsupported key format: {key_format}")),
    }
}

fn dispatch(args: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let command = std::str::from_utf8(args.first().ok_or("empty frame")?)
        .map_err(|e| format!("invalid command: {e}"))?;

    match command {
        "getConfig" => {
            expect_args(args, 1, command)?;
            Ok(vec![config()?])
        }
        "ML-DSA/keyGen" => {
            let args = expect_args(args, 3, command)?;
            let param_set =
                std::str::from_utf8(&args[1]).map_err(|e| format!("invalid parameter set: {e}"))?;
            match param_set {
                "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => keygen(param_set, &args[2]),
                _ => Ok(vec![UNSUPPORTED.to_vec()]),
            }
        }
        "ML-DSA/signExternal" => {
            let args = expect_args(args, 9, command)?;
            let param_set =
                std::str::from_utf8(&args[1]).map_err(|e| format!("invalid parameter set: {e}"))?;
            let key = signing_key(param_set, &args[2], &args[3])?;
            sign_external(
                param_set, &key, &args[4], &args[5], &args[6], &args[7], &args[8],
            )
        }
        "ML-DSA/signInternal" => {
            let args = expect_args(args, 6, command)?;
            let param_set =
                std::str::from_utf8(&args[1]).map_err(|e| format!("invalid parameter set: {e}"))?;
            let key = signing_key(param_set, &args[2], &args[3])?;
            Ok(sign_internal(param_set, &key, &args[4])?)
        }
        "ML-DSA/verifyInternal" => {
            let args = expect_args(args, 5, command)?;
            let pk = &args[2];
            let msg: &[u8] = &args[3];
            let sig: &[u8] = &args[4];
            let param_set =
                std::str::from_utf8(&args[1]).map_err(|e| format!("invalid parameter set: {e}"))?;
            let passed = verify_internal(param_set, pk, msg, sig)?;
            Ok(vec![vec![u8::from(passed)]])
        }
        "ML-DSA/verifyExternal" => {
            let args = expect_args(args, 8, command)?;
            let param_set =
                std::str::from_utf8(&args[1]).map_err(|e| format!("invalid parameter set: {e}"))?;
            let pk = &args[2];
            let msg: &[u8] = &args[3];
            let ctx: &[u8] = &args[4];
            let pre_hash: &[u8] = &args[5];
            let hash: &[u8] = &args[6];
            let sig: &[u8] = &args[7];
            let passed = verify_external(param_set, pk, msg, ctx, pre_hash, hash, sig)?;
            Ok(vec![vec![u8::from(passed)]])
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn main() {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("mldsa-wrapper.log")
        .expect("failed to open log file");

    Builder::new()
        .filter_level(LevelFilter::Debug)
        .target(Target::Pipe(Box::new(log_file)))
        .init();

    modulewrapper::run("mldsa_wrapper", |args| {
        let result = dispatch(args);
        if let Err(error) = &result {
            error!("Module request failed: {error}");
        }
        result
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::Path;

    #[test]
    fn fips202_vectors_validate_hashml_dsa_sha3_and_shake_prehashes() {
        // SHA3-256 tcId=221 and SHA3-512 tcId=384 from the local FIPS-202
        // corpus. SHAKE-128 tcId=230 provides the 256-bit HashML-DSA
        // prehash, while SHAKE-256 tcId=35 provides at least its required
        // 512-bit prehash output.
        let cases = [
            (
                "SHA3-256",
                "",
                "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A",
            ),
            (
                "SHA3-512",
                "",
                "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26",
            ),
            (
                "SHAKE-128",
                "B3E0ABDFE024B4D76D24F0",
                "6065987CB4865BAA5374CBE2803DC16228EE0FFDE023EA26F0D8CFC632DDD423",
            ),
            (
                "SHAKE-256",
                "A21198252B3928D4273BDC3BE3F3E026BAB4F52008491A1814EBBE9C39FBEA87118CD8993EA307582AA8C2ADBFB9336F29BF7A",
                "78C4EC2BA13DAF27FA4E67B78BC70CFF3FBA1B09157C5639BD2FF751BCCE48CD3200BE88554A988CF7A11767A9155DEA750CB909B11B9A1DFB9F49B875C8EFE3",
            ),
        ];

        for (hash_alg, message, expected_digest) in cases {
            let message = hex::decode(message).unwrap();
            let encoded = prehashed_message(&message, &[], hash_alg.as_bytes()).unwrap();
            // All FIPS 204 HashML-DSA OIDs used here are 11-byte DER values.
            assert_eq!(
                hex::encode(&encoded[13..]),
                expected_digest.to_ascii_lowercase(),
                "{hash_alg} pre-hash did not match its FIPS-202 KAT"
            );
        }
    }

    fn fips202_digest(algorithm: &str, message: &[u8], output_len: usize) -> Vec<u8> {
        match algorithm {
            "SHA3-256" => Sha3_256::digest(message).to_vec(),
            "SHA3-512" => Sha3_512::digest(message).to_vec(),
            "SHAKE-128" => {
                let mut output = vec![0; output_len];
                Shake128::default()
                    .chain(message)
                    .finalize_xof()
                    .read(&mut output);
                output
            }
            "SHAKE-256" => {
                let mut output = vec![0; output_len];
                Shake256::default()
                    .chain(message)
                    .finalize_xof()
                    .read(&mut output);
                output
            }
            _ => unreachable!("test only calls registered FIPS-202 algorithms"),
        }
    }

    #[test]
    fn fips202_byte_aligned_aft_vectors_when_configured() {
        let Ok(root) = std::env::var("ACVP_FIPS202_DIR") else {
            return;
        };
        let root = Path::new(&root);
        let algorithms = ["SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256"];
        let mut tested = 0;

        for algorithm in algorithms {
            let prompt: Value = serde_json::from_slice(
                &std::fs::read(root.join(algorithm).join("prompt.json"))
                    .unwrap_or_else(|e| panic!("failed to read {algorithm} FIPS-202 prompt: {e}")),
            )
            .unwrap_or_else(|e| panic!("failed to parse {algorithm} FIPS-202 prompt: {e}"));
            let expected: Value = serde_json::from_slice(
                &std::fs::read(root.join(algorithm).join("expectedResults.json")).unwrap_or_else(
                    |e| panic!("failed to read {algorithm} FIPS-202 expected results: {e}"),
                ),
            )
            .unwrap_or_else(|e| {
                panic!("failed to parse {algorithm} FIPS-202 expected results: {e}")
            });
            let expected_groups = expected["testGroups"]
                .as_array()
                .expect("FIPS-202 expected results must contain testGroups");

            for group in prompt["testGroups"]
                .as_array()
                .expect("FIPS-202 prompt must contain testGroups")
            {
                if group["testType"].as_str() != Some("AFT") {
                    continue;
                }
                let group_id = group["tgId"]
                    .as_u64()
                    .expect("FIPS-202 AFT group must contain tgId");
                let expected_group = expected_groups
                    .iter()
                    .find(|candidate| candidate["tgId"].as_u64() == Some(group_id))
                    .unwrap_or_else(|| panic!("missing expected group {group_id} for {algorithm}"));

                for test in group["tests"]
                    .as_array()
                    .expect("FIPS-202 AFT group must contain tests")
                {
                    let message_len = test["len"]
                        .as_u64()
                        .expect("FIPS-202 AFT test must contain len");
                    let output_len = test["outLen"].as_u64().unwrap_or(0);
                    if message_len % 8 != 0 || (output_len != 0 && output_len % 8 != 0) {
                        continue;
                    }
                    let test_id = test["tcId"]
                        .as_u64()
                        .expect("FIPS-202 AFT test must contain tcId");
                    let expected_test = expected_group["tests"]
                        .as_array()
                        .expect("FIPS-202 expected group must contain tests")
                        .iter()
                        .find(|candidate| candidate["tcId"].as_u64() == Some(test_id))
                        .unwrap_or_else(|| {
                            panic!("missing expected test {group_id}/{test_id} for {algorithm}")
                        });
                    let message = hex::decode(
                        test["msg"]
                            .as_str()
                            .expect("FIPS-202 AFT test must contain msg"),
                    )
                    .expect("FIPS-202 AFT message must be hexadecimal");
                    let expected_output = hex::decode(
                        expected_test["md"]
                            .as_str()
                            .expect("FIPS-202 expected test must contain md"),
                    )
                    .expect("FIPS-202 expected digest must be hexadecimal");
                    assert_eq!(
                        fips202_digest(algorithm, &message, expected_output.len()),
                        expected_output,
                        "{algorithm} FIPS-202 AFT mismatch at {group_id}/{test_id}"
                    );
                    tested += 1;
                }
            }
        }
        assert!(tested > 0, "no byte-aligned FIPS-202 AFT cases were found");
    }
}
