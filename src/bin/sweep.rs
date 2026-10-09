//! Measure the ML-DSA rejection-sampling loop.
//!
//! Signs many distinct messages and records, per parameter set, the
//! distribution of signing-loop repetitions together with a breakdown of which
//! validity check rejected each attempt. Emits JSON for the blog pipeline.
//!
//! Keys are rotated so the result estimates the acceptance probability averaged
//! over keys, which is what the published figures claim to describe. Holding a
//! single key fixed would measure that key's acceptance probability instead.
//!
//!   cargo run --release --bin sweep -- --sets 44,65,87 --n 100000 --json out.json

use mldsa::{generate_key, sign_traced, MLDSAParameters, MAX_PRIVATE_KEY_BYTES,
            MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES};
use std::collections::BTreeMap;
use std::io::Write;

struct Acc {
    hist: BTreeMap<u32, u64>,
    fail_z: u64,
    fail_r0: u64,
    fail_ct0: u64,
    fail_hint: u64,
    attempts: u64,
    signatures: u64,
}

impl Acc {
    fn new() -> Self {
        Acc { hist: BTreeMap::new(), fail_z: 0, fail_r0: 0, fail_ct0: 0,
              fail_hint: 0, attempts: 0, signatures: 0 }
    }
    fn push(&mut self, s: mldsa::SignStats) {
        *self.hist.entry(s.iterations).or_insert(0) += 1;
        self.fail_z += s.fail_z as u64;
        self.fail_r0 += s.fail_r0 as u64;
        self.fail_ct0 += s.fail_ct0 as u64;
        self.fail_hint += s.fail_hint as u64;
        self.attempts += s.iterations as u64;
        self.signatures += 1;
    }
    fn mean(&self) -> f64 { self.attempts as f64 / self.signatures as f64 }
}

/// Per-key breakdown, so the key-to-key spread of P_hint can be checked
/// separately from per-attempt binomial noise (the same distinction the
/// interactive WASM panel's key-count control makes).
#[derive(Default, Clone, Copy)]
struct KeyAcc {
    signatures: u64,
    fail_ct0: u64,
    fail_hint: u64,
}

fn arg(name: &str, default: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
        .unwrap_or_else(|| default.to_string())
}

fn main() {
    let sets = arg("--sets", "44,65,87");
    let n: u64 = arg("--n", "10000").parse().expect("--n must be an integer");
    let nkeys: u64 = arg("--keys", "16").parse().expect("--keys must be an integer");
    let out = arg("--json", "");

    let mut blocks: Vec<String> = Vec::new();

    for tag in sets.split(',') {
        let name = format!("ML-DSA-{}", tag.trim());
        let param = MLDSAParameters::new(&name)
            .unwrap_or_else(|_| panic!("unknown parameter set {name}"));

        // Pre-generate the key pool.
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for ki in 0..nkeys {
            let seed: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(ki as u8)).collect();
            let mut pk = [0u8; MAX_PUBLIC_KEY_BYTES];
            let mut sk = [0u8; MAX_PRIVATE_KEY_BYTES];
            let (_pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
            keys.push(sk[..sk_len].to_vec());
        }

        let mut acc = Acc::new();
        let mut per_key = vec![KeyAcc::default(); nkeys as usize];
        let mut sig = [0u8; MAX_SIGNATURE_BYTES];
        let start = std::time::Instant::now();

        for i in 0..n {
            let msg = i.to_le_bytes();
            let ki = (i % nkeys) as usize;
            let sk = &keys[ki];
            let (_len, st) = sign_traced(&param, sk, &msg, true, &mut sig);
            let ka = &mut per_key[ki];
            ka.signatures += 1;
            ka.fail_ct0 += st.fail_ct0 as u64;
            ka.fail_hint += st.fail_hint as u64;
            acc.push(st);
            if i % 2000 == 0 && i > 0 {
                eprint!("\r{name}: {i}/{n}  mean={:.4}", acc.mean());
                let _ = std::io::stderr().flush();
            }
        }
        eprintln!("\r{name}: {n}/{n}  mean={:.4}  ({:.1}s)", acc.mean(), start.elapsed().as_secs_f64());

        let hist: Vec<String> = acc.hist.iter()
            .map(|(k, v)| format!("      \"{k}\": {v}")).collect();
        let p = acc.signatures as f64 / acc.attempts as f64;

        let per_key_json: Vec<String> = per_key.iter()
            .map(|k| format!(
                "        {{\"signatures\": {}, \"fail_ct0\": {}, \"fail_hint\": {}}}",
                k.signatures, k.fail_ct0, k.fail_hint))
            .collect();

        blocks.push(format!(
r#"    "{name}": {{
      "n": {},
      "keys": {},
      "variant": "deterministic",
      "attempts": {},
      "p": {:.7},
      "mean": {:.6},
      "max_observed": {},
      "by_reason": {{
        "z": {}, "r0": {}, "ct0": {}, "hint": {}
      }},
      "per_key": [
{}
      ],
      "histogram": {{
{}
      }}
    }}"#,
            acc.signatures, nkeys, acc.attempts, p, acc.mean(),
            acc.hist.keys().last().unwrap_or(&0),
            acc.fail_z, acc.fail_r0, acc.fail_ct0, acc.fail_hint,
            per_key_json.join(",\n"),
            hist.join(",\n")));
    }

    let json = format!(
"{{\n  \"tool\": \"mldsa-edu sweep\",\n  \"implementation\": \"mldsa-ref (Rust)\",\n  \"parameter_sets\": {{\n{}\n  }}\n}}\n",
        blocks.join(",\n"));

    if out.is_empty() {
        print!("{json}");
    } else {
        std::fs::write(&out, &json).expect("write json");
        eprintln!("wrote {out}");
    }
}
