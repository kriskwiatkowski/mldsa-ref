// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! ML-DSA (FIPS-204) Implementation
//!
//! Rust implementation of ML-DSA based on FIPS-204 standard.
//! Supports Pure ML-DSA and HashML-DSA (pre-hash) modes.
//!
//! Education purposes only. Don't use for anything else.

#![no_std]

use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};

// Constants

const Q: i32 = 8380417; // Modulus
const N: usize = 256; // Polynomial degree
const ROOT: i32 = 1753; // Primitive root of unity mod Q

// Buffer size constants for no_std stack allocations
const MAX_K: usize = 8;
const MAX_L: usize = 7;
const POLY_SIZE: usize = 256;

// Part of API
pub const MAX_PRIVATE_KEY_BYTES: usize = 4896;
pub const MAX_PUBLIC_KEY_BYTES: usize = 2592;
pub const MAX_SIGNATURE_BYTES: usize = 4627;

// Parameter Sets
/// Contains all cryptographic parameters as per FIPS-204:
/// - ML-DSA-44: NIST security level 2 (128-bit)
/// - ML-DSA-65: NIST security level 3 (192-bit)
/// - ML-DSA-87: NIST security level 5 (256-bit)
#[derive(Clone, Debug)]
pub struct MLDSAParameters {
    /// Parameter set name (e.g., "ML-DSA-44")
    pub name: &'static str,
    /// Number of bits dropped in key generation
    pub d: usize,
    /// Number of ±1 coefficients in challenge polynomial
    pub tau: usize,
    /// Security level in bits (128, 192, or 256)
    pub lambda: usize,
    /// Range for mask generation
    pub gamma1: i32,
    /// Low-order rounding range
    pub gamma2: i32,
    /// Rows in matrix A
    pub k: usize,
    /// Columns in matrix A
    pub l: usize,
    /// Range for secret key coefficients
    pub eta: usize,
    /// Rejection threshold
    pub beta: i32,
    /// Maximum number of 1s in hint polynomial
    pub omega: usize,
    /// Private key byte length
    pub private_key_length: usize,
    /// Public key byte length
    pub public_key_length: usize,
    /// Signature byte length
    pub signature_length: usize,
}

impl MLDSAParameters {
    /// Creates a new parameter set by name.
    ///
    /// # Arguments
    /// * `name` - Parameter set identifier: "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87"
    ///
    /// # Returns
    /// * `Ok(MLDSAParameters)` - Valid parameter set
    /// * `Err(String)` - Unknown parameter set name
    ///
    /// # Example
    /// ```
    /// use mldsa::MLDSAParameters;
    /// let params = MLDSAParameters::new("ML-DSA-44").unwrap();
    /// ```
    pub fn new(name: &str) -> Result<Self, &'static str> {
        match name {
            "ML-DSA-44" => Ok(MLDSAParameters {
                name: "ML-DSA-44",
                d: 13,
                tau: 39,
                lambda: 128,
                gamma1: 1 << 17,
                gamma2: 95232,
                k: 4,
                l: 4,
                eta: 2,
                beta: 78,
                omega: 80,
                private_key_length: 2560,
                public_key_length: 1312,
                signature_length: 2420,
            }),
            "ML-DSA-65" => Ok(MLDSAParameters {
                name: "ML-DSA-65",
                d: 13,
                tau: 49,
                lambda: 192,
                gamma1: 1 << 19,
                gamma2: 261888,
                k: 6,
                l: 5,
                eta: 4,
                beta: 196,
                omega: 55,
                private_key_length: 4032,
                public_key_length: 1952,
                signature_length: 3309,
            }),
            "ML-DSA-87" => Ok(MLDSAParameters {
                name: "ML-DSA-87",
                d: 13,
                tau: 60,
                lambda: 256,
                gamma1: 1 << 19,
                gamma2: 261888,
                k: 8,
                l: 7,
                eta: 2,
                beta: 120,
                omega: 75,
                private_key_length: 4896,
                public_key_length: 2592,
                signature_length: 4627,
            }),
            _ => Err("Unknown parameter set"),
        }
    }
}

// Helpers
fn pos_mod(x: i32, modulus: i32) -> i32 {
    let r = x % modulus;
    if r < 0 {
        r + modulus
    } else {
        r
    }
}

fn pos_mod_i64(x: i64, modulus: i32) -> i32 {
    let r = x % (modulus as i64);
    if r < 0 {
        (r + modulus as i64) as i32
    } else {
        r as i32
    }
}

fn plus_minus_mod(x: i32, modulus: i32) -> i32 {
    let mut r = x % modulus;
    if r < 0 {
        r += modulus;
    }
    if r > modulus / 2 {
        r -= modulus;
    }
    r
}

fn get_exact_bit_length(x: i32) -> usize {
    if x == 0 {
        0
    } else {
        32 - (x.leading_zeros() as usize)
    }
}

fn exp2(x: usize) -> i32 {
    1 << x
}

fn ceiling_divide(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

// Algorithm 9: IntegerToBits - writes to output buffer
fn integer_to_bits(mut x: i32, alpha: usize, output: &mut [bool]) -> usize {
    for i in 0..alpha {
        output[i] = (x % 2) == 1;
        x /= 2;
    }
    alpha
}

// Algorithm 10: BitsToInteger
fn bits_to_integer(y: &[bool], alpha: usize) -> i32 {
    let mut x = 0;
    for i in (0..alpha).rev() {
        x = (2 * x) + if y[i] { 1 } else { 0 };
    }
    x
}

// Algorithm 12: BitsToBytes - writes to output buffer
fn bits_to_bytes(y: &[bool], output: &mut [u8]) -> usize {
    let c = y.len();
    let len = ceiling_divide(c, 8);
    for i in 0..len {
        output[i] = 0;
    }
    for i in 0..c {
        output[i / 8] += if y[i] { 1 } else { 0 } * (1 << (i % 8));
    }
    len
}

// Algorithm 13: BytesToBits - writes to output buffer
fn bytes_to_bits(z: &[u8], output: &mut [bool]) -> usize {
    let d = z.len();
    let mut idx = 0;
    for i in 0..d {
        let mut byte = z[i];
        for _ in 0..8 {
            output[idx] = (byte % 2) == 1;
            byte /= 2;
            idx += 1;
        }
    }
    idx
}

// Algorithm 14: CoeffFromThreeBytes
fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<i32> {
    let z = (((b2 & 127) as i32) << 16) | ((b1 as i32) << 8) | (b0 as i32);
    if z < Q {
        Some(z)
    } else {
        None
    }
}

// Algorithm 15: CoeffFromHalfByte
fn coeff_from_half_byte(b: u8, eta: usize) -> Option<i32> {
    if eta == 2 && b < 15 {
        Some(2 - ((b % 5) as i32))
    } else if eta == 4 && b < 9 {
        Some(4 - (b as i32))
    } else {
        None
    }
}

// Algorithm 16: SimpleBitPack - writes to output buffer
fn simple_bit_pack(w: &[i32], b: i32, output: &mut [u8]) -> usize {
    let bitlen = get_exact_bit_length(b);
    let mut all_bits = [false; 256 * 32]; // Max bits needed
    let mut bit_idx = 0;
    for i in 0..256 {
        bit_idx += integer_to_bits(w[i], bitlen, &mut all_bits[bit_idx..]);
    }
    bits_to_bytes(&all_bits[..bit_idx], output)
}

// Algorithm 17: BitPack - writes to output buffer
fn bit_pack(w: &[i32], a: i32, b: i32, output: &mut [u8]) -> usize {
    let bitlen = get_exact_bit_length(a + b);
    let mut all_bits = [false; 256 * 32]; // Max bits needed
    let mut bit_idx = 0;
    for i in 0..256 {
        bit_idx += integer_to_bits(b - w[i], bitlen, &mut all_bits[bit_idx..]);
    }
    bits_to_bytes(&all_bits[..bit_idx], output)
}

// Algorithm 18: SimpleBitUnpack - writes to output buffer (256 i32 elements)
fn simple_bit_unpack(v: &[u8], b: i32, output: &mut [i32]) -> usize {
    let c = get_exact_bit_length(b);
    let mut z = [false; 256 * 32]; // Max bits
    let z_len = bytes_to_bits(v, &mut z);

    for i in 0..256 {
        let start = i * c;
        let end = (i + 1) * c;
        if end <= z_len {
            output[i] = bits_to_integer(&z[start..end], c);
        } else if start < z_len {
            // Pad with zeros if needed
            let mut padded = [false; 32];
            let available = z_len - start;
            padded[..available].copy_from_slice(&z[start..z_len]);
            output[i] = bits_to_integer(&padded[..c], c);
        } else {
            output[i] = 0;
        }
    }
    256
}

// Algorithm 19: BitUnpack - writes to output buffer (256 i32 elements)
fn bit_unpack(v: &[u8], a: i32, b: i32, output: &mut [i32]) -> usize {
    let c = get_exact_bit_length(a + b);
    let mut z = [false; 256 * 32]; // Max bits
    let z_len = bytes_to_bits(v, &mut z);

    for i in 0..256 {
        let start = i * c;
        let end = (i + 1) * c;
        if end <= z_len {
            output[i] = b - bits_to_integer(&z[start..end], c);
        } else if start < z_len {
            // Pad with zeros if needed
            let mut padded = [false; 32];
            let available = z_len - start;
            padded[..available].copy_from_slice(&z[start..z_len]);
            output[i] = b - bits_to_integer(&padded[..c], c);
        } else {
            output[i] = b;
        }
    }
    256
}

// Algorithm 20: HintBitPack - writes to output buffer
fn hint_bit_pack(
    h: &[[i32; POLY_SIZE]; MAX_K],
    omega: usize,
    k: usize,
    output: &mut [u8],
) -> usize {
    let len = omega + k;
    for i in 0..len {
        output[i] = 0;
    }
    let mut index = 0;
    for i in 0..k {
        for j in 0..256 {
            if h[i][j] != 0 {
                output[index] = j as u8;
                index += 1;
            }
        }
        output[omega + i] = index as u8;
    }
    len
}

// Algorithm 21: HintBitUnpack - writes to output buffer
fn hint_bit_unpack(
    y: &[u8],
    omega: usize,
    k: usize,
    output: &mut [[i32; POLY_SIZE]; MAX_K],
) -> bool {
    for i in 0..k {
        for j in 0..256 {
            output[i][j] = 0;
        }
    }

    let mut index = 0usize;
    for i in 0..k {
        let bound = y[omega + i] as usize;
        if bound < index || bound > omega {
            return false;
        }

        let first = index;
        while index < bound {
            if index > first && y[index - 1] >= y[index] {
                return false;
            }
            output[i][y[index] as usize] = 1;
            index += 1;
        }
    }

    while index < omega {
        if y[index] != 0 {
            return false;
        }
        index += 1;
    }

    true
}

// Algorithm 22: pkEncode
fn pk_encode(
    param: &MLDSAParameters,
    rho: &[bool],
    t1: &[[i32; POLY_SIZE]; MAX_K],
    output: &mut [u8],
) -> usize {
    let mut offset = 0;
    offset += bits_to_bytes(rho, &mut output[offset..]);

    let bitlen = get_exact_bit_length(Q - 1) - param.d;
    let mut temp_buf = [0u8; 512];
    for i in 0..param.k {
        let len = simple_bit_pack(&t1[i], exp2(bitlen) - 1, &mut temp_buf);
        output[offset..offset + len].copy_from_slice(&temp_buf[..len]);
        offset += len;
    }
    offset
}

// Algorithm 23: pkDecode
fn pk_decode(
    param: &MLDSAParameters,
    pk: &[u8],
    rho_out: &mut [bool],
    t1_out: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    let _rho_len = bytes_to_bits(&pk[..32], rho_out);

    let bitlen = get_exact_bit_length(Q - 1) - param.d;
    let chunk_len = ceiling_divide(bitlen * 256, 8);
    let mut offset = 32;

    for i in 0..param.k {
        let chunk_end = offset + chunk_len;
        let _len = simple_bit_unpack(&pk[offset..chunk_end], exp2(bitlen) - 1, &mut t1_out[i]);
        offset = chunk_end;
    }
}

// Algorithm 24: skEncode
fn sk_encode(
    param: &MLDSAParameters,
    rho: &[bool],
    k: &[bool],
    tr: &[bool],
    s1: &[[i32; POLY_SIZE]; MAX_L],
    s2: &[[i32; POLY_SIZE]; MAX_K],
    t0: &[[i32; POLY_SIZE]; MAX_K],
    output: &mut [u8],
) -> usize {
    let mut offset = 0;
    offset += bits_to_bytes(rho, &mut output[offset..]);
    offset += bits_to_bytes(k, &mut output[offset..]);
    offset += bits_to_bytes(tr, &mut output[offset..]);

    let mut temp_buf = [0u8; 512];
    for i in 0..param.l {
        let len = bit_pack(&s1[i], param.eta as i32, param.eta as i32, &mut temp_buf);
        output[offset..offset + len].copy_from_slice(&temp_buf[..len]);
        offset += len;
    }
    for i in 0..param.k {
        let len = bit_pack(&s2[i], param.eta as i32, param.eta as i32, &mut temp_buf);
        output[offset..offset + len].copy_from_slice(&temp_buf[..len]);
        offset += len;
    }
    for i in 0..param.k {
        let len = bit_pack(
            &t0[i],
            exp2(param.d - 1) - 1,
            exp2(param.d - 1),
            &mut temp_buf,
        );
        output[offset..offset + len].copy_from_slice(&temp_buf[..len]);
        offset += len;
    }

    offset
}

// Algorithm 25: skDecode
fn sk_decode(
    param: &MLDSAParameters,
    sk: &[u8],
    rho_out: &mut [bool],
    k_out: &mut [bool],
    tr_out: &mut [bool],
    s1_out: &mut [[i32; POLY_SIZE]; MAX_L],
    s2_out: &mut [[i32; POLY_SIZE]; MAX_K],
    t0_out: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    let _rho_len = bytes_to_bits(&sk[..32], rho_out);
    let _k_len = bytes_to_bits(&sk[32..64], k_out);
    let _tr_len = bytes_to_bits(&sk[64..128], tr_out);

    let mut offset = 128;
    let eta = param.eta as i32;
    let eta_pack_len = ceiling_divide(get_exact_bit_length(2 * eta) * 256, 8);

    for i in 0..param.l {
        let _len = bit_unpack(&sk[offset..offset + eta_pack_len], eta, eta, &mut s1_out[i]);
        offset += eta_pack_len;
    }

    for i in 0..param.k {
        let _len = bit_unpack(&sk[offset..offset + eta_pack_len], eta, eta, &mut s2_out[i]);
        offset += eta_pack_len;
    }

    let t0_pack_len = ceiling_divide(get_exact_bit_length(exp2(param.d) - 1) * 256, 8);
    for i in 0..param.k {
        let _len = bit_unpack(
            &sk[offset..offset + t0_pack_len],
            exp2(param.d - 1) - 1,
            exp2(param.d - 1),
            &mut t0_out[i],
        );
        offset += t0_pack_len;
    }
}

// Algorithm 26: sigEncode
fn sig_encode(
    param: &MLDSAParameters,
    c_tilde: &[u8],
    z: &[[i32; POLY_SIZE]; MAX_L],
    h: &[[i32; POLY_SIZE]; MAX_K],
    output: &mut [u8],
) -> usize {
    let lambda_bytes = 2 * param.lambda / 8;
    output[..lambda_bytes].copy_from_slice(&c_tilde[..lambda_bytes]);
    let mut offset = lambda_bytes;

    let mut temp_buf = [0u8; 640]; // Max bytes for bit_pack output (256 * 20 bits / 8)
    for i in 0..param.l {
        let len = bit_pack(&z[i], param.gamma1 - 1, param.gamma1, &mut temp_buf);
        output[offset..offset + len].copy_from_slice(&temp_buf[..len]);
        offset += len;
    }
    let len = hint_bit_pack(h, param.omega, param.k, &mut temp_buf);
    output[offset..offset + len].copy_from_slice(&temp_buf[..len]);
    offset += len;
    offset
}

// Algorithm 27: sigDecode
fn sig_decode(
    param: &MLDSAParameters,
    sigma: &[u8],
    c_tilde_out: &mut [u8],
    z_out: &mut [[i32; POLY_SIZE]; MAX_L],
    h_out: &mut [[i32; POLY_SIZE]; MAX_K],
) -> bool {
    let lambda_bytes = 2 * param.lambda / 8;
    c_tilde_out[..lambda_bytes].copy_from_slice(&sigma[..lambda_bytes]);

    let mut offset = lambda_bytes;
    let gamma1_bitlen = get_exact_bit_length(2 * param.gamma1 - 1);
    let z_pack_len = ceiling_divide(gamma1_bitlen * 256, 8);

    for i in 0..param.l {
        let _len = bit_unpack(
            &sigma[offset..offset + z_pack_len],
            param.gamma1 - 1,
            param.gamma1,
            &mut z_out[i],
        );
        offset += z_pack_len;
    }

    hint_bit_unpack(&sigma[offset..], param.omega, param.k, h_out)
}

// Algorithm 28: w1Encode
fn w1_encode(
    param: &MLDSAParameters,
    w1: &[[i32; POLY_SIZE]; MAX_K],
    output: &mut [bool],
) -> usize {
    let _bitlen = get_exact_bit_length((Q - 1) / (2 * param.gamma2) - 1);
    let mut offset = 0;
    let mut temp_bytes = [0u8; 256];
    let mut temp_bits = [false; 2048];

    for i in 0..param.k {
        let byte_len = simple_bit_pack(&w1[i], (Q - 1) / (2 * param.gamma2) - 1, &mut temp_bytes);
        let bit_len = bytes_to_bits(&temp_bytes[..byte_len], &mut temp_bits);
        output[offset..offset + bit_len].copy_from_slice(&temp_bits[..bit_len]);
        offset += bit_len;
    }
    offset
}

// Algorithm 29: SampleInBall
fn sample_in_ball(param: &MLDSAParameters, rho: &[u8], output: &mut [i32]) {
    output.fill(0);
    let mut xof = Shake256::default();
    xof.update(rho);
    let mut reader = xof.finalize_xof();

    let mut buf = [0u8; 1];
    let mut signs = [0u8; 8];
    reader.read(&mut signs);

    let mut sign_bits = [0u8; 64];
    let mut idx = 0;
    for byte in signs.iter() {
        for i in 0..8 {
            sign_bits[idx] = (byte >> i) & 1;
            idx += 1;
        }
    }

    for i in (256 - param.tau)..256 {
        loop {
            reader.read(&mut buf);
            let j = buf[0] as usize;
            if j <= i {
                output[i] = output[j];
                let sign_idx = i - (256 - param.tau);
                output[j] = if sign_bits[sign_idx] == 0 { 1 } else { -1 };
                break;
            }
        }
    }
}

// Algorithm 30: RejNTTPoly
fn rej_ntt_poly(rho: &[bool], output: &mut [i32]) {
    let mut rho_bytes = [0u8; 64 + 2];
    let rho_bytes_len = bits_to_bytes(rho, &mut rho_bytes);

    let mut xof = Shake128::default();
    xof.update(&rho_bytes[..rho_bytes_len]);
    let mut reader = xof.finalize_xof();

    let mut buf = [0u8; 3];
    let mut count = 0;
    while count < 256 {
        reader.read(&mut buf);
        if let Some(coeff) = coeff_from_three_bytes(buf[0], buf[1], buf[2]) {
            output[count] = coeff;
            count += 1;
        }
    }
}

// Algorithm 31: RejBoundedPoly
fn rej_bounded_poly(param: &MLDSAParameters, rho: &[bool], output: &mut [i32]) {
    let mut rho_bytes = [0u8; 64 + 2];
    let rho_bytes_len = bits_to_bytes(rho, &mut rho_bytes);

    let mut xof = Shake256::default();
    xof.update(&rho_bytes[..rho_bytes_len]);
    let mut reader = xof.finalize_xof();

    let mut buf = [0u8; 1];
    let mut count = 0;
    while count < 256 {
        reader.read(&mut buf);
        let z = buf[0];

        if let Some(coeff) = coeff_from_half_byte(z & 0x0F, param.eta) {
            output[count] = coeff;
            count += 1;
        }
        if count < 256 {
            if let Some(coeff) = coeff_from_half_byte(z >> 4, param.eta) {
                output[count] = coeff;
                count += 1;
            }
        }
    }
}

// Algorithm 32: ExpandA
fn expand_a(
    param: &MLDSAParameters,
    rho: &[bool],
    a_hat_out: &mut [[[i32; POLY_SIZE]; MAX_L]; MAX_K],
) {
    for r in 0..param.k {
        for s in 0..param.l {
            let mut rho_prime = [false; 512 + 16];
            let rho_len = rho.len();
            rho_prime[..rho_len].copy_from_slice(rho);

            let mut s_bits = [false; 8];
            let _ = integer_to_bits(s as i32, 8, &mut s_bits);
            rho_prime[rho_len..rho_len + 8].copy_from_slice(&s_bits);

            let mut r_bits = [false; 8];
            let _ = integer_to_bits(r as i32, 8, &mut r_bits);
            rho_prime[rho_len + 8..rho_len + 16].copy_from_slice(&r_bits);

            rej_ntt_poly(&rho_prime[..rho_len + 16], &mut a_hat_out[r][s]);
        }
    }
}

// Algorithm 33: ExpandS
fn expand_s(
    param: &MLDSAParameters,
    rho: &[bool],
    s1_out: &mut [[i32; POLY_SIZE]; MAX_L],
    s2_out: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    for r in 0..param.l {
        let mut rho_prime = [false; 512 + 16];
        let rho_len = rho.len();
        rho_prime[..rho_len].copy_from_slice(rho);

        let mut r_bits = [false; 16];
        let _ = integer_to_bits(r as i32, 16, &mut r_bits);
        rho_prime[rho_len..rho_len + 16].copy_from_slice(&r_bits);

        rej_bounded_poly(param, &rho_prime[..rho_len + 16], &mut s1_out[r]);
    }

    for r in 0..param.k {
        let mut rho_prime = [false; 512 + 16];
        let rho_len = rho.len();
        rho_prime[..rho_len].copy_from_slice(rho);

        let mut r_bits = [false; 16];
        let _ = integer_to_bits((param.l + r) as i32, 16, &mut r_bits);
        rho_prime[rho_len..rho_len + 16].copy_from_slice(&r_bits);

        rej_bounded_poly(param, &rho_prime[..rho_len + 16], &mut s2_out[r]);
    }
}

// Algorithm 34: ExpandMask
fn expand_mask(
    param: &MLDSAParameters,
    rho: &[bool],
    mu: usize,
    y_out: &mut [[i32; POLY_SIZE]; MAX_L],
) {
    let c = 1 + get_exact_bit_length(param.gamma1 - 1);

    for r in 0..param.l {
        let mut rho_prime = [false; 512 + 16];
        let rho_len = rho.len();
        rho_prime[..rho_len].copy_from_slice(rho);

        let mut r_bits = [false; 16];
        let _ = integer_to_bits((mu + r) as i32, 16, &mut r_bits);
        rho_prime[rho_len..rho_len + 16].copy_from_slice(&r_bits);

        let mut rho_bytes = [0u8; 64 + 2];
        let rho_bytes_len = bits_to_bytes(&rho_prime[..rho_len + 16], &mut rho_bytes);

        let mut xof = Shake256::default();
        xof.update(&rho_bytes[..rho_bytes_len]);
        let mut reader = xof.finalize_xof();

        let bytes_needed = ceiling_divide(c * 256, 8);
        let mut buf = [0u8; 1024];
        reader.read(&mut buf[..bytes_needed]);

        let mut bits = [false; 8192];
        let _bits_count = bytes_to_bits(&buf[..bytes_needed], &mut bits);

        for i in 0..256 {
            let start = i * c;
            let end = (i + 1) * c;
            // BitUnpack(v, gamma1-1, gamma1): y = b - z = gamma1 - z.
            y_out[r][i] = param.gamma1 - bits_to_integer(&bits[start..end], c);
        }
    }
}

// Algorithm 35: Power2Round
fn power2_round(param: &MLDSAParameters, r: i32) -> (i32, i32) {
    let r_mod = pos_mod(r, Q);
    let r0 = plus_minus_mod(r_mod, exp2(param.d));
    ((r_mod - r0) / exp2(param.d), r0)
}

// Algorithm 36: Decompose
fn decompose(param: &MLDSAParameters, r: i32) -> (i32, i32) {
    let r_mod = pos_mod(r, Q);
    let r0 = plus_minus_mod(r_mod, 2 * param.gamma2);

    if r_mod - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r_mod - r0) / (2 * param.gamma2), r0)
    }
}

// Algorithm 37: HighBits
fn high_bits(param: &MLDSAParameters, r: i32) -> i32 {
    decompose(param, r).0
}

// Algorithm 38: LowBits
fn low_bits(param: &MLDSAParameters, r: i32) -> i32 {
    decompose(param, r).1
}

// Algorithm 39: MakeHint
fn make_hint(param: &MLDSAParameters, z: i32, r: i32) -> bool {
    let r1 = high_bits(param, r);
    let v1 = high_bits(param, r + z);
    r1 != v1
}

// Algorithm 40: UseHint
fn use_hint(param: &MLDSAParameters, h: bool, r: i32) -> i32 {
    let m = (Q - 1) / (2 * param.gamma2);
    let (r1, r0) = decompose(param, r);

    if !h {
        return r1;
    }

    if r0 > 0 {
        pos_mod(r1 + 1, m)
    } else {
        pos_mod(r1 - 1, m)
    }
}

fn pow_mod(mut base: u64, mut exp: u64, modu: u64) -> u64 {
    base %= modu;
    let mut result: u64 = 1;

    while exp > 0 {
        if (exp & 1) == 1 {
            result = (result * base) % modu;
        }
        base = (base * base) % modu;
        exp >>= 1;
    }
    result
}

// 8-bit reversal for indices 0..255
fn bitrev(k: usize) -> usize {
    let mut result = 0usize;
    for i in 0..8 {
        if (k & (1 << i)) != 0 {
            result |= 1 << (7 - i);
        }
    }
    result
}

fn calc_zeta(exp: usize) -> i32 {
    pow_mod(ROOT as u64, exp as u64, Q as u64) as i32
}

fn get_zeta(k: usize) -> i32 {
    let exp = bitrev(k);
    calc_zeta(exp)
}

// Algorithm 41: NTT
fn ntt(w: &mut [i32]) {
    let mut k = 0;
    let mut len = N / 2;

    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = get_zeta(k);
            for j in start..(start + len) {
                let t = pos_mod_i64(zeta as i64 * w[j + len] as i64, Q);
                w[j + len] = pos_mod_i64(w[j] as i64 - t as i64, Q);
                w[j] = pos_mod_i64(w[j] as i64 + t as i64, Q);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

// Algorithm 42: NTT-inverse
fn ntt_inverse(w_hat: &mut [i32]) {
    let mut k = 256;
    let mut len = 1;

    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -get_zeta(k);
            for j in start..(start + len) {
                let t = w_hat[j];
                w_hat[j] = pos_mod_i64(t as i64 + w_hat[j + len] as i64, Q);
                w_hat[j + len] = pos_mod_i64(t as i64 - w_hat[j + len] as i64, Q);
                w_hat[j + len] = pos_mod_i64(zeta as i64 * w_hat[j + len] as i64, Q);
            }
            start += 2 * len;
        }
        len *= 2;
    }

    let f = 8347681; // Inverse of 256 mod Q
    for i in 0..256 {
        w_hat[i] = pos_mod_i64(f as i64 * w_hat[i] as i64, Q);
    }
}

fn pairwise_multiply_l(
    a: &[i32],
    b: &[[i32; POLY_SIZE]; MAX_L],
    result: &mut [[i32; POLY_SIZE]; MAX_L],
) {
    for i in 0..MAX_L {
        for j in 0..256 {
            result[i][j] = pos_mod_i64(b[i][j] as i64 * a[j] as i64, Q);
        }
    }
}

fn pairwise_multiply_k(
    a: &[i32],
    b: &[[i32; POLY_SIZE]; MAX_K],
    result: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    for i in 0..MAX_K {
        for j in 0..256 {
            result[i][j] = pos_mod_i64(b[i][j] as i64 * a[j] as i64, Q);
        }
    }
}

fn matrix_multiply(
    a: &[[[i32; POLY_SIZE]; MAX_L]; MAX_K],
    b: &[[i32; POLY_SIZE]; MAX_L],
    a_rows: usize,
    a_cols: usize,
    result: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    for i in 0..a_rows {
        for k in 0..256 {
            result[i][k] = 0;
        }
        for j in 0..a_cols {
            for k in 0..256 {
                let sum = result[i][k] as i64 + (a[i][j][k] as i64 * b[j][k] as i64);
                result[i][k] = pos_mod_i64(sum, Q);
            }
        }
    }
}

fn matrix_add_l(
    a: &[[i32; POLY_SIZE]; MAX_L],
    b: &[[i32; POLY_SIZE]; MAX_L],
    rows: usize,
    result: &mut [[i32; POLY_SIZE]; MAX_L],
) {
    for i in 0..rows {
        for j in 0..256 {
            result[i][j] = pos_mod_i64(a[i][j] as i64 + b[i][j] as i64, Q);
        }
    }
}

fn matrix_add(
    a: &[[i32; POLY_SIZE]; MAX_K],
    b: &[[i32; POLY_SIZE]; MAX_K],
    rows: usize,
    result: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    for i in 0..rows {
        for j in 0..256 {
            result[i][j] = pos_mod_i64(a[i][j] as i64 + b[i][j] as i64, Q);
        }
    }
}

fn matrix_subtract(
    a: &[[i32; POLY_SIZE]; MAX_K],
    b: &[[i32; POLY_SIZE]; MAX_K],
    rows: usize,
    result: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    for i in 0..rows {
        for j in 0..256 {
            result[i][j] = pos_mod_i64(a[i][j] as i64 - b[i][j] as i64, Q);
        }
    }
}

fn negate_matrix_k(
    a: &[[i32; POLY_SIZE]; MAX_K],
    rows: usize,
    result: &mut [[i32; POLY_SIZE]; MAX_K],
) {
    for i in 0..rows {
        for j in 0..256 {
            result[i][j] = pos_mod(-a[i][j], Q);
        }
    }
}

fn infinity_norm(a: &[[i32; POLY_SIZE]]) -> i32 {
    let mut max_val = 0i32;
    for row in a {
        for &val in row {
            let abs_val = plus_minus_mod(val, Q).abs();
            if abs_val > max_val {
                max_val = abs_val;
            }
        }
    }
    max_val
}

// Main functions

/// Generates an ML-DSA public/private keypair.
///
/// # Arguments
/// * `param` - Parameter set defining the security level
/// * `seed` - 32-byte random seed for key generation
///
/// # Returns
/// A tuple `(public_key, private_key)` with lengths matching `param.public_key_length`
/// and `param.private_key_length` respectively.
///
/// # Example
/// ```
/// use mldsa::{MLDSAParameters, generate_key};
/// let param = MLDSAParameters::new("ML-DSA-44").unwrap();
/// let seed = [0u8; 32]; // Use secure randomness in production
/// let mut pk = [0u8; 1312];
/// let mut sk = [0u8; 2560];
/// let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
/// ```
pub fn generate_key(
    param: &MLDSAParameters,
    seed: &[u8],
    pk_out: &mut [u8],
    sk_out: &mut [u8],
) -> (usize, usize) {
    // Expand seed with k and l appended
    let mut xof = Shake256::default();
    xof.update(seed);
    xof.update(&[param.k as u8]);
    xof.update(&[param.l as u8]);
    let mut reader = xof.finalize_xof();

    let mut seed_expanded = [0u8; 128];
    reader.read(&mut seed_expanded);

    let mut rho = [false; 256];
    let mut rho_prime = [false; 512];
    let mut k_bits = [false; 256];
    let _rho_len = bytes_to_bits(&seed_expanded[..32], &mut rho);
    let _rho_prime_len = bytes_to_bits(&seed_expanded[32..96], &mut rho_prime);
    let _k_len = bytes_to_bits(&seed_expanded[96..128], &mut k_bits);

    // Expand A
    let mut a_hat = [[[0i32; POLY_SIZE]; MAX_L]; MAX_K];
    expand_a(param, &rho[.._rho_len], &mut a_hat);

    // Sample s1, s2
    let mut s1 = [[0i32; POLY_SIZE]; MAX_L];
    let mut s2 = [[0i32; POLY_SIZE]; MAX_K];
    expand_s(param, &rho_prime[.._rho_prime_len], &mut s1, &mut s2);

    // Transform s1 to NTT
    let mut s1_hat = [[0i32; POLY_SIZE]; MAX_L];
    for i in 0..param.l {
        s1_hat[i].copy_from_slice(&s1[i]);
        ntt(&mut s1_hat[i]);
    }

    // Compute t = NTT^-1(A_hat * NTT(s1)) + s2
    let mut t_temp = [[0i32; POLY_SIZE]; MAX_K];
    matrix_multiply(&a_hat, &s1_hat, param.k, param.l, &mut t_temp);

    let mut t_temp_inv = [[0i32; POLY_SIZE]; MAX_K];
    for i in 0..param.k {
        t_temp_inv[i].copy_from_slice(&t_temp[i]);
        ntt_inverse(&mut t_temp_inv[i]);
    }

    let mut t = [[0i32; POLY_SIZE]; MAX_K];
    matrix_add(&t_temp_inv, &s2, param.k, &mut t);

    // Power2Round
    let mut t1 = [[0i32; POLY_SIZE]; MAX_K];
    let mut t0 = [[0i32; POLY_SIZE]; MAX_K];
    for i in 0..param.k {
        for j in 0..256 {
            let (hi, lo) = power2_round(param, t[i][j]);
            t1[i][j] = hi;
            t0[i][j] = lo;
        }
    }

    // Encode public key
    let pk_len = pk_encode(param, &rho[.._rho_len], &t1, pk_out);

    // Compute tr
    let mut xof_tr = Shake256::default();
    xof_tr.update(&pk_out[..pk_len]);
    let mut reader_tr = xof_tr.finalize_xof();
    let mut tr_bytes = [0u8; 64];
    reader_tr.read(&mut tr_bytes);
    let mut tr = [false; 512];
    let tr_len = bytes_to_bits(&tr_bytes, &mut tr);

    let sk_len = sk_encode(
        param,
        &rho[.._rho_len],
        &k_bits[.._k_len],
        &tr[..tr_len],
        &s1,
        &s2,
        &t0,
        sk_out,
    );

    (pk_len, sk_len)
}

/// Signs a message using ML-DSA.
///
/// # Arguments
/// * `param` - Parameter set defining the security level
/// * `sk` - Private key from `generate_key`
/// * `m` - Message to sign (arbitrary length)
/// * `deterministic` - If true, produces deterministic signatures
///
/// # Returns
/// Signature bytes with length `param.signature_length`.
///
/// # Example
/// ```
/// use mldsa::{MLDSAParameters, generate_key, sign};
/// let param = MLDSAParameters::new("ML-DSA-44").unwrap();
/// let seed = [0u8; 32];
/// let mut pk = [0u8; 1312];
/// let mut sk = [0u8; 2560];
/// let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
/// let mut signature = [0u8; 2420];
/// let sig_len = sign(&param, &sk[..sk_len], b"Hello, world!", true, &mut signature);
/// ```
pub fn sign(
    param: &MLDSAParameters,
    sk: &[u8],
    m: &[u8],
    _deterministic: bool,
    sig_out: &mut [u8],
) -> usize {
    // Decode secret key
    let mut rho = [false; 256];
    let mut k_bits = [false; 256];
    let mut tr = [false; 512];
    let mut s1 = [[0i32; POLY_SIZE]; MAX_L];
    let mut s2 = [[0i32; POLY_SIZE]; MAX_K];
    let mut t0 = [[0i32; POLY_SIZE]; MAX_K];
    sk_decode(
        param,
        sk,
        &mut rho,
        &mut k_bits,
        &mut tr,
        &mut s1,
        &mut s2,
        &mut t0,
    );

    // Transform to NTT domain
    let mut s1_hat = [[0i32; POLY_SIZE]; MAX_L];
    let mut s2_hat = [[0i32; POLY_SIZE]; MAX_K];
    let mut t0_hat = [[0i32; POLY_SIZE]; MAX_K];
    for i in 0..param.l {
        s1_hat[i].copy_from_slice(&s1[i]);
        ntt(&mut s1_hat[i]);
    }
    for i in 0..param.k {
        s2_hat[i].copy_from_slice(&s2[i]);
        ntt(&mut s2_hat[i]);
        t0_hat[i].copy_from_slice(&t0[i]);
        ntt(&mut t0_hat[i]);
    }

    let mut a_hat = [[[0i32; POLY_SIZE]; MAX_L]; MAX_K];
    expand_a(param, &rho, &mut a_hat);

    // Compute message representative mu
    let mut tr_bytes = [0u8; 64];
    let tr_bytes_len = bits_to_bytes(&tr, &mut tr_bytes);

    let mut xof_mu = Shake256::default();
    xof_mu.update(&tr_bytes[..tr_bytes_len]);
    xof_mu.update(m);
    let mut reader_mu = xof_mu.finalize_xof();
    let mut mu = [0u8; 64];
    reader_mu.read(&mut mu);

    // Generate rnd (0 for deterministic)
    let rnd = [0u8; 32];

    // Compute rho'
    // K is 32 bytes (256 bits); k_bits is oversized to 512 for reuse
    // elsewhere, so it must be sliced here or the trailing zero padding
    // gets absorbed into the hash along with K.
    let mut k_bits_bytes = [0u8; 64];
    let k_bits_bytes_len = bits_to_bytes(&k_bits, &mut k_bits_bytes);

    let mut xof_rho_prime = Shake256::default();
    xof_rho_prime.update(&k_bits_bytes[..k_bits_bytes_len]);
    xof_rho_prime.update(&rnd);
    xof_rho_prime.update(&mu);
    let mut reader_rho_prime = xof_rho_prime.finalize_xof();
    let mut rho_prime_bytes = [0u8; 64];
    reader_rho_prime.read(&mut rho_prime_bytes);
    let mut rho_prime = [false; 512];
    let rho_prime_len = bytes_to_bits(&rho_prime_bytes, &mut rho_prime);

    let mut kappa = 0;

    loop {
        // Expand mask
        let mut y = [[0i32; POLY_SIZE]; MAX_L];
        expand_mask(param, &rho_prime[..rho_prime_len], kappa, &mut y);

        // Compute w
        let mut y_hat = [[0i32; POLY_SIZE]; MAX_L];
        for i in 0..param.l {
            y_hat[i].copy_from_slice(&y[i]);
            ntt(&mut y_hat[i]);
        }

        let mut w_temp = [[0i32; POLY_SIZE]; MAX_K];
        matrix_multiply(&a_hat, &y_hat, param.k, param.l, &mut w_temp);

        let mut w = [[0i32; POLY_SIZE]; MAX_K];
        for i in 0..param.k {
            w[i].copy_from_slice(&w_temp[i]);
            ntt_inverse(&mut w[i]);
        }

        // Extract high bits
        let mut w1 = [[0i32; POLY_SIZE]; MAX_K];
        for i in 0..param.k {
            for j in 0..256 {
                w1[i][j] = high_bits(param, w[i][j]);
            }
        }

        // Compute challenge
        let mut w1_encoded = [false; 8192];
        let w1_encoded_len = w1_encode(param, &w1, &mut w1_encoded);

        let mut w1_enc_bytes = [0u8; 1024];
        let w1_enc_bytes_len = bits_to_bytes(&w1_encoded[..w1_encoded_len], &mut w1_enc_bytes);

        let mut xof_c = Shake256::default();
        xof_c.update(&mu);
        xof_c.update(&w1_enc_bytes[..w1_enc_bytes_len]);
        let mut reader_c = xof_c.finalize_xof();
        let mut c_tilde = [0u8; 64];
        let c_tilde_len = 2 * param.lambda / 8;
        reader_c.read(&mut c_tilde[..c_tilde_len]);

        // Sample c
        let mut c = [0i32; POLY_SIZE];
        sample_in_ball(param, &c_tilde[..c_tilde_len], &mut c);
        let mut c_hat = c;
        ntt(&mut c_hat);

        // Compute z and checks
        let mut cs1_temp = [[0i32; POLY_SIZE]; MAX_L];
        pairwise_multiply_l(&c_hat, &s1_hat, &mut cs1_temp);

        let mut cs1 = [[0i32; POLY_SIZE]; MAX_L];
        for i in 0..param.l {
            cs1[i].copy_from_slice(&cs1_temp[i]);
            ntt_inverse(&mut cs1[i]);
        }

        let mut cs2_temp = [[0i32; POLY_SIZE]; MAX_K];
        pairwise_multiply_k(&c_hat, &s2_hat, &mut cs2_temp);

        let mut cs2 = [[0i32; POLY_SIZE]; MAX_K];
        for i in 0..param.k {
            cs2[i].copy_from_slice(&cs2_temp[i]);
            ntt_inverse(&mut cs2[i]);
        }

        let mut z = [[0i32; POLY_SIZE]; MAX_L];
        matrix_add_l(&y, &cs1, param.l, &mut z);

        // Check ||z||
        let mut w_minus_cs2 = [[0i32; POLY_SIZE]; MAX_K];
        matrix_subtract(&w, &cs2, param.k, &mut w_minus_cs2);

        let mut r0 = [[0i32; POLY_SIZE]; MAX_K];
        for i in 0..param.k {
            for j in 0..256 {
                r0[i][j] = low_bits(param, w_minus_cs2[i][j]);
            }
        }

        if infinity_norm(&z[..param.l]) >= param.gamma1 - param.beta
            || infinity_norm(&r0[..param.k]) >= param.gamma2 - param.beta
        {
            kappa += param.l;
            continue;
        }

        // Compute hints
        let mut ct0_temp = [[0i32; POLY_SIZE]; MAX_K];
        pairwise_multiply_k(&c_hat, &t0_hat, &mut ct0_temp);

        let mut ct0 = [[0i32; POLY_SIZE]; MAX_K];
        for i in 0..param.k {
            ct0[i].copy_from_slice(&ct0_temp[i]);
            ntt_inverse(&mut ct0[i]);
        }

        let mut negated_ct0 = [[0i32; POLY_SIZE]; MAX_K];
        negate_matrix_k(&ct0, param.k, &mut negated_ct0);

        let mut ct0_added = [[0i32; POLY_SIZE]; MAX_K];
        matrix_add(&w_minus_cs2, &ct0, param.k, &mut ct0_added);

        let mut h_matrix = [[0i32; POLY_SIZE]; MAX_K];
        let mut sum_h = 0;

        for i in 0..param.k {
            for j in 0..256 {
                if make_hint(param, negated_ct0[i][j], ct0_added[i][j]) {
                    h_matrix[i][j] = 1;
                    sum_h += 1;
                } else {
                    h_matrix[i][j] = 0;
                }
            }
        }

        // Check hint count and ||ct0||
        if infinity_norm(&ct0[..param.k]) >= param.gamma2 || sum_h > param.omega {
            kappa += param.l;
            continue;
        }

        // sigEncode expects z mod± q (centered representative); z is
        // currently in canonical [0, Q) form from matrix_add_l.
        for i in 0..param.l {
            for j in 0..256 {
                z[i][j] = plus_minus_mod(z[i][j], Q);
            }
        }
        // Encode signature
        return sig_encode(param, &c_tilde, &z, &h_matrix, sig_out);
    }
}

/// Verifies an ML-DSA signature on a message.
///
/// # Arguments
/// * `param` - Parameter set used for signing
/// * `pk` - Public key from `generate_key`
/// * `m` - Message that was signed
/// * `sigma` - Signature to verify
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
/// ```no_run
/// use mldsa::{MLDSAParameters, generate_key, sign, verify};
/// let param = MLDSAParameters::new("ML-DSA-44").unwrap();
/// // Use a varied seed (important for proper key generation)
/// let seed: Vec<u8> = (0..32).map(|i| i as u8).collect();
/// let mut pk = [0u8; 1312];
/// let mut sk = [0u8; 2560];
/// let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
/// let mut signature = [0u8; 2420];
/// let sig_len = sign(&param, &sk[..sk_len], b"Hello, world!", true, &mut signature);
/// let valid = verify(&param, &pk[..pk_len], b"Hello, world!", &signature[..sig_len]);
/// assert!(valid);
/// ```
pub fn verify(param: &MLDSAParameters, pk: &[u8], m: &[u8], sigma: &[u8]) -> bool {
    // Decode public key
    let mut rho = [false; 256];
    let mut t1 = [[0i32; POLY_SIZE]; MAX_K];
    pk_decode(param, pk, &mut rho, &mut t1);

    // Decode signature
    let mut c_tilde = [0u8; 64];
    let mut z = [[0i32; POLY_SIZE]; MAX_L];
    let mut h = [[0i32; POLY_SIZE]; MAX_K];
    if !sig_decode(param, sigma, &mut c_tilde, &mut z, &mut h) {
        return false;
    }

    // Check ||z||
    if infinity_norm(&z[..param.l]) >= param.gamma1 - param.beta {
        return false;
    }

    // Check hint count
    let mut sum_h = 0;
    for i in 0..param.k {
        for j in 0..256 {
            sum_h += h[i][j];
        }
    }
    if sum_h > param.omega as i32 {
        return false;
    }

    // Compute tr
    let mut xof_tr = Shake256::default();
    xof_tr.update(pk);
    let mut reader_tr = xof_tr.finalize_xof();
    let mut tr_bytes = [0u8; 64];
    reader_tr.read(&mut tr_bytes);
    let mut tr = [false; 512];
    let tr_len = bytes_to_bits(&tr_bytes, &mut tr);

    // Compute mu
    let mut tr_bytes_out = [0u8; 64];
    let tr_bytes_len = bits_to_bytes(&tr[..tr_len], &mut tr_bytes_out);

    let mut xof_mu = Shake256::default();
    xof_mu.update(&tr_bytes_out[..tr_bytes_len]);
    xof_mu.update(m);
    let mut reader_mu = xof_mu.finalize_xof();
    let mut mu = [0u8; 64];
    reader_mu.read(&mut mu);

    // Sample c
    let c_tilde_len = 2 * param.lambda / 8;
    let mut c = [0i32; POLY_SIZE];
    sample_in_ball(param, &c_tilde[..c_tilde_len], &mut c);
    let mut c_hat = c;
    ntt(&mut c_hat);

    // Expand A
    let mut a_hat = [[[0i32; POLY_SIZE]; MAX_L]; MAX_K];
    expand_a(param, &rho, &mut a_hat);

    // Transform z to NTT
    let mut z_hat = [[0i32; POLY_SIZE]; MAX_L];
    for i in 0..param.l {
        z_hat[i].copy_from_slice(&z[i]);
        ntt(&mut z_hat[i]);
    }

    // Compute Az
    let mut az_hat = [[0i32; POLY_SIZE]; MAX_K];
    matrix_multiply(&a_hat, &z_hat, param.k, param.l, &mut az_hat);

    // Compute t1 * 2^d
    let mut t1_shifted = [[0i32; POLY_SIZE]; MAX_K];
    for i in 0..param.k {
        for j in 0..256 {
            t1_shifted[i][j] = pos_mod(t1[i][j] * exp2(param.d), Q);
        }
    }

    let mut t1_shifted_hat = [[0i32; POLY_SIZE]; MAX_K];
    for i in 0..param.k {
        t1_shifted_hat[i].copy_from_slice(&t1_shifted[i]);
        ntt(&mut t1_shifted_hat[i]);
    }

    // Compute ct1 * 2^d
    let mut ct1_2d_hat = [[0i32; POLY_SIZE]; MAX_K];
    pairwise_multiply_k(&c_hat, &t1_shifted_hat, &mut ct1_2d_hat);

    // Compute Az - ct1*2^d
    let mut w_prime_approx_hat = [[0i32; POLY_SIZE]; MAX_K];
    matrix_subtract(&az_hat, &ct1_2d_hat, param.k, &mut w_prime_approx_hat);

    let mut w_prime_approx = [[0i32; POLY_SIZE]; MAX_K];
    for i in 0..param.k {
        w_prime_approx[i].copy_from_slice(&w_prime_approx_hat[i]);
        ntt_inverse(&mut w_prime_approx[i]);
    }

    // Use hints
    let mut w1_prime = [[0i32; POLY_SIZE]; MAX_K];
    for i in 0..param.k {
        for j in 0..256 {
            let w_val = pos_mod(w_prime_approx[i][j], Q);
            w1_prime[i][j] = use_hint(param, h[i][j] == 1, w_val);
        }
    }

    // Compute c_tilde'
    let mut w1_encoded_temp = [false; 8192];
    let w1_encoded_len = w1_encode(param, &w1_prime, &mut w1_encoded_temp);

    let mut w1_enc_bytes = [0u8; 1024];
    let w1_enc_bytes_len = bits_to_bytes(&w1_encoded_temp[..w1_encoded_len], &mut w1_enc_bytes);

    let mut xof_c_prime = Shake256::default();
    xof_c_prime.update(&mu);
    xof_c_prime.update(&w1_enc_bytes[..w1_enc_bytes_len]);
    let mut reader_c_prime = xof_c_prime.finalize_xof();
    let mut c_tilde_prime = [0u8; 64];
    reader_c_prime.read(&mut c_tilde_prime[..c_tilde_len]);

    // Compare
    c_tilde[..c_tilde_len] == c_tilde_prime[..c_tilde_len]
}

/// Hash algorithm OIDs (DER-encoded)
const HASH_OIDS: &[(&str, &[u8])] = &[
    (
        "SHA2-224",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        ],
    ),
    (
        "SHA2-256",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
    ),
    (
        "SHA2-384",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ],
    ),
    (
        "SHA2-512",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
    ),
    (
        "SHA2-512/224",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
        ],
    ),
    (
        "SHA2-512/256",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
        ],
    ),
    (
        "SHA3-224",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
        ],
    ),
    (
        "SHA3-256",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        ],
    ),
    (
        "SHA3-384",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        ],
    ),
    (
        "SHA3-512",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
        ],
    ),
    (
        "SHAKE-128",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
        ],
    ),
    (
        "SHAKE-256",
        &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
        ],
    ),
];

fn get_hash_oid(hash_alg: &str) -> Option<&[u8]> {
    HASH_OIDS
        .iter()
        .find(|(name, _)| *name == hash_alg)
        .map(|(_, oid)| *oid)
}

fn hash_message(hash_alg: &str, m: &[u8], output: &mut [u8]) -> Option<usize> {
    match hash_alg {
        "SHA2-224" => {
            let digest = Sha224::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA2-256" => {
            let digest = Sha256::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA2-384" => {
            let digest = Sha384::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA2-512" => {
            let digest = Sha512::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA2-512/224" => {
            let digest = Sha512_224::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA2-512/256" => {
            let digest = Sha512_256::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA3-224" => {
            let digest = Sha3_224::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA3-256" => {
            let digest = Sha3_256::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA3-384" => {
            let digest = Sha3_384::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHA3-512" => {
            let digest = Sha3_512::digest(m);
            let len = digest.len();
            output[..len].copy_from_slice(&digest);
            Some(len)
        }
        "SHAKE-128" => {
            let mut xof = Shake128::default();
            xof.update(m);
            let mut reader = xof.finalize_xof();
            reader.read(&mut output[..32]);
            Some(32)
        }
        "SHAKE-256" => {
            let mut xof = Shake256::default();
            xof.update(m);
            let mut reader = xof.finalize_xof();
            reader.read(&mut output[..64]);
            Some(64)
        }
        _ => None,
    }
}

/// Signs a message using HashML-DSA.
///
/// # Arguments
/// * `param` - Parameter set defining the security level
/// * `sk` - Private key from `generate_key`
/// * `m` - Message to sign (will be hashed)
/// * `ctx` - Context string for domain separation (max 255 bytes)
/// * `deterministic` - If true, produces deterministic signatures
/// * `hash_alg` - Hash algorithm: "SHA2-256", "SHA2-512", "SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256"
///
/// # Returns
/// * `Ok(usize)` - Signature length
/// * `Err(&'static str)` - If context is too long or hash algorithm is unsupported
///
/// # Example
/// ```
/// use mldsa::{MLDSAParameters, generate_key, hash_ml_dsa_sign};
/// let param = MLDSAParameters::new("ML-DSA-44").unwrap();
/// let seed = [0u8; 32];
/// let mut pk = [0u8; 1312];
/// let mut sk = [0u8; 2560];
/// let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
/// let large_message = b"Some large message to sign";
/// let mut sig = [0u8; 2420];
/// let sig_len = hash_ml_dsa_sign(&param, &sk[..sk_len], large_message, b"app-v1", true, "SHA2-256", &mut sig).unwrap();
/// ```
pub fn hash_ml_dsa_sign(
    param: &MLDSAParameters,
    sk: &[u8],
    m: &[u8],
    ctx: &[u8],
    deterministic: bool,
    hash_alg: &str,
    sig_out: &mut [u8],
) -> Result<usize, &'static str> {
    if ctx.len() > 255 {
        return Err("Context must be at most 255 bytes");
    }

    let Some(oid) = get_hash_oid(hash_alg) else {
        return Err("Unsupported hash algorithm");
    };

    let mut ph = [0u8; 64];
    let Some(ph_len) = hash_message(hash_alg, m, &mut ph) else {
        return Err("Failed to hash message");
    };

    // Build M': 1 || len(ctx) || ctx || OID || PH
    let mut m_prime = [0u8; 1024];
    m_prime[0] = 1;
    m_prime[1] = ctx.len() as u8;
    let mut offset = 2;
    m_prime[offset..offset + ctx.len()].copy_from_slice(ctx);
    offset += ctx.len();
    m_prime[offset..offset + oid.len()].copy_from_slice(oid);
    offset += oid.len();
    m_prime[offset..offset + ph_len].copy_from_slice(&ph[..ph_len]);
    offset += ph_len;

    // Sign M' using standard ML-DSA
    Ok(sign(param, sk, &m_prime[..offset], deterministic, sig_out))
}

/// Verifies a HashML-DSA signature.
///
/// # Arguments
/// * `param` - Parameter set used for signing
/// * `pk` - Public key from `generate_key`
/// * `m` - Message that was signed (will be hashed)
/// * `sig` - Signature to verify
/// * `ctx` - Context string used during signing (max 255 bytes)
/// * `hash_alg` - Hash algorithm used during signing
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
/// ```
/// use mldsa::{MLDSAParameters, generate_key, hash_ml_dsa_sign, hash_ml_dsa_verify};
/// let param = MLDSAParameters::new("ML-DSA-44").unwrap();
/// let seed = [0u8; 32];
/// let mut pk = [0u8; 1312];
/// let mut sk = [0u8; 2560];
/// let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
/// let large_message = b"Some large message to sign";
/// let mut sig = [0u8; 2420];
/// let sig_len = hash_ml_dsa_sign(&param, &sk[..sk_len], large_message, b"app-v1", true, "SHA2-256", &mut sig).unwrap();
/// let valid = hash_ml_dsa_verify(&param, &pk[..pk_len], large_message, &sig[..sig_len], b"app-v1", "SHA2-256");
/// ```
pub fn hash_ml_dsa_verify(
    param: &MLDSAParameters,
    pk: &[u8],
    m: &[u8],
    sigma: &[u8],
    ctx: &[u8],
    hash_alg: &str,
) -> bool {
    if ctx.len() > 255 {
        return false;
    }

    let Some(oid) = get_hash_oid(hash_alg) else {
        return false;
    };

    let mut ph = [0u8; 64];
    let Some(ph_len) = hash_message(hash_alg, m, &mut ph) else {
        return false;
    };

    // Build M': 1 || len(ctx) || ctx || OID || PH
    let mut m_prime = [0u8; 1024];
    m_prime[0] = 1;
    m_prime[1] = ctx.len() as u8;
    let mut offset = 2;
    m_prime[offset..offset + ctx.len()].copy_from_slice(ctx);
    offset += ctx.len();
    m_prime[offset..offset + oid.len()].copy_from_slice(oid);
    offset += oid.len();
    m_prime[offset..offset + ph_len].copy_from_slice(&ph[..ph_len]);
    offset += ph_len;

    // Verify M' using standard ML-DSA
    verify(param, pk, &m_prime[..offset], sigma)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_ml_dsa_44_keygen() {
        let param = MLDSAParameters::new("ML-DSA-44").unwrap();
        let seed = [0u8; 32];

        let mut pk = [0u8; MAX_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; MAX_PRIVATE_KEY_BYTES];

        let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
        assert_eq!(pk_len, param.public_key_length);
        assert_eq!(sk_len, param.private_key_length);
    }

    #[test]
    fn test_ml_dsa_65() {
        let param = MLDSAParameters::new("ML-DSA-65").unwrap();
        let seed = [0u8; 32];

        let mut pk = [0u8; MAX_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; MAX_PRIVATE_KEY_BYTES];

        let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
        assert_eq!(pk_len, param.public_key_length);
        assert_eq!(sk_len, param.private_key_length);
    }

    #[test]
    fn test_ml_dsa_87() {
        let param = MLDSAParameters::new("ML-DSA-87").unwrap();
        let seed = [0u8; 32];

        let mut pk = [0u8; MAX_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; MAX_PRIVATE_KEY_BYTES];

        let (pk_len, sk_len) = generate_key(&param, &seed, &mut pk, &mut sk);
        assert_eq!(pk_len, param.public_key_length);
        assert_eq!(sk_len, param.private_key_length);
    }
}
