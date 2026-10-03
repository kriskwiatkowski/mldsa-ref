# Minimal Rust implementation of ML-DSA

A very small but complete implementation of ML-DSA.

## Build & run

Run KAT tests:

```
cargo run --example kat_tests
```

Run benchmarks:

```
cargo bench
```

## Security

None. This implementation is for educational purposes only and provides no security guarantees.

## How to Cite

To cite mldsa-ref, use one of the following formats and update the version and date you accessed this project.

BibTeX Source

```bibtex
@manual{mldsaref,
  title        = {MLDSA-ref: A reference implementation of ML-DSA digital signature},
  author       = {Kris Kwiatkowski},
  abstract     = {{MLDSA-ref is a small, self-contained Rust implementation of
                   ML-DSA, the module-lattice-based post-quantum digital signature
                   algorithm standardized by NIST in FIPS 204. It covers key
                   generation, signing and verification, and is validated against
                   known-answer test vectors. The code favours readability over
                   performance and is meant for education and experimentation; it
                   makes no security guarantees and is not intended for
                   production use.}},
  note         = {Available at \url{https://github.com/kriskwiatkowski/mldsa-ref}.},
  month        = oct,
  year         = {2026}
}
```

CFF Style

See attached [CITATION.cff](CITATION.cff) file.
