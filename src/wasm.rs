//! Browser bindings for the rejection-sampling explorer.
//!
//! The point of shipping the real implementation to the browser is that a
//! reader watching the loop abort is watching actual ML-DSA abort, against
//! actual thresholds, rather than a simulated coin flip. Everything here is a
//! thin JSON wrapper over [`crate::sign_core`]; no cryptographic logic lives in
//! this file.
//!
//! All randomness is supplied by the caller. JavaScript owns `crypto.getRandomValues`,
//! so this module never needs an RNG of its own and stays deterministic given
//! its inputs.

use crate::{
    generate_key, sign_core, AttemptRecord, MLDSAParameters, Trace, MAX_PRIVATE_KEY_BYTES,
    MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES,
};
use wasm_bindgen::prelude::*;

/// Largest trace we keep per signature. Long tails are interesting, but a
/// browser has no use for ten thousand DOM rows; `truncated` reports overflow.
const TRACE_CAP: usize = 512;

fn params(set: &str) -> Result<MLDSAParameters, JsValue> {
    MLDSAParameters::new(set).map_err(|_| JsValue::from_str(&format!("unknown parameter set: {set}")))
}

fn key_from_seed(p: &MLDSAParameters, seed: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 32];
    for (i, b) in seed.iter().take(32).enumerate() {
        s[i] = *b;
    }
    let mut pk = [0u8; MAX_PUBLIC_KEY_BYTES];
    let mut sk = [0u8; MAX_PRIVATE_KEY_BYTES];
    let (_pk_len, sk_len) = generate_key(p, &s, &mut pk, &mut sk);
    sk[..sk_len].to_vec()
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// FIPS 204 parameters and the four rejection thresholds, as JSON.
///
/// The page renders thresholds from this rather than hardcoding them, so the
/// numbers a reader sees always come from the same implementation that produced
/// the trace beside them.
#[wasm_bindgen]
pub fn param_info(set: &str) -> Result<String, JsValue> {
    let p = params(set)?;
    Ok(format!(
        r#"{{"name":"{}","k":{},"l":{},"eta":{},"tau":{},"beta":{},"gamma1":{},"gamma2":{},"omega":{},"lambda":{},"d":{},"signature_bytes":{},"public_key_bytes":{},"private_key_bytes":{},"thresholds":{{"z":{},"r0":{},"ct0":{},"hint":{}}}}}"#,
        esc(p.name), p.k, p.l, p.eta, p.tau, p.beta, p.gamma1, p.gamma2, p.omega, p.lambda, p.d,
        p.signature_length, p.public_key_length, p.private_key_length,
        p.gamma1 - p.beta, p.gamma2 - p.beta, p.gamma2, p.omega
    ))
}

fn record_json(r: &AttemptRecord) -> String {
    format!(
        r#"{{"z":{},"r0":{},"ct0":{},"hint":{},"fail_z":{},"fail_r0":{},"fail_ct0":{},"fail_hint":{},"accepted":{}}}"#,
        r.z_norm, r.r0_norm, r.ct0_norm, r.hint_weight,
        r.fail_z, r.fail_r0, r.fail_ct0, r.fail_hint, r.accepted()
    )
}

/// Sign one message and return the full per-attempt trace as JSON.
///
/// `rnd` is FIPS 204's per-message randomness: pass 32 zero bytes for the
/// deterministic variant, fresh random bytes for the hedged variant. The
/// difference is directly visible in the explorer -- deterministic signing
/// makes the repetition count a stable fingerprint of (key, message), hedged
/// signing re-rolls it every time.
#[wasm_bindgen]
pub fn sign_trace(set: &str, key_seed: &[u8], msg: &[u8], rnd: &[u8]) -> Result<String, JsValue> {
    let p = params(set)?;
    let sk = key_from_seed(&p, key_seed);

    let mut r = [0u8; 32];
    for (i, b) in rnd.iter().take(32).enumerate() {
        r[i] = *b;
    }

    let mut buf = [AttemptRecord::default(); TRACE_CAP];
    let mut trace = Trace::new(&mut buf);
    let mut sig = [0u8; MAX_SIGNATURE_BYTES];

    let (sig_len, stats) = sign_core(&p, &sk, msg, &r, &mut sig, Some(&mut trace));

    let attempts: Vec<String> = trace.records().iter().map(record_json).collect();
    Ok(format!(
        r#"{{"set":"{}","iterations":{},"truncated":{},"signature_bytes":{},"fail_z":{},"fail_r0":{},"fail_ct0":{},"fail_hint":{},"attempts":[{}]}}"#,
        esc(p.name), stats.iterations, trace.truncated(), sig_len,
        stats.fail_z, stats.fail_r0, stats.fail_ct0, stats.fail_hint,
        attempts.join(",")
    ))
}

/// Sign `n` distinct messages and return the repetition histogram as JSON.
///
/// Messages are a little-endian counter starting at `msg_offset`, so a caller
/// can chunk a long run across several calls (keeping the UI responsive) and
/// still cover distinct messages. One key is used throughout: browser key
/// generation is expensive, and the page says so rather than implying this
/// estimates the key-averaged acceptance probability.
#[wasm_bindgen]
pub fn sweep(set: &str, key_seed: &[u8], n: u32, msg_offset: u32) -> Result<String, JsValue> {
    let p = params(set)?;
    let sk = key_from_seed(&p, key_seed);

    let mut hist: Vec<u32> = Vec::new();
    let (mut attempts, mut fz, mut fr, mut fc, mut fh) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut sig = [0u8; MAX_SIGNATURE_BYTES];
    let zero = [0u8; 32];

    for i in 0..n {
        let msg = (msg_offset as u64 + i as u64).to_le_bytes();
        let (_len, st) = sign_core(&p, &sk, &msg, &zero, &mut sig, None);
        let it = st.iterations as usize;
        if hist.len() <= it {
            hist.resize(it + 1, 0);
        }
        hist[it] += 1;
        attempts += st.iterations as u64;
        fz += st.fail_z as u64;
        fr += st.fail_r0 as u64;
        fc += st.fail_ct0 as u64;
        fh += st.fail_hint as u64;
    }

    let pairs: Vec<String> = hist
        .iter()
        .enumerate()
        .filter(|(_, c)| **c > 0)
        .map(|(k, c)| format!(r#""{k}":{c}"#))
        .collect();

    Ok(format!(
        r#"{{"set":"{}","n":{},"attempts":{},"by_reason":{{"z":{},"r0":{},"ct0":{},"hint":{}}},"histogram":{{{}}}}}"#,
        esc(p.name), n, attempts, fz, fr, fc, fh, pairs.join(",")
    ))
}
