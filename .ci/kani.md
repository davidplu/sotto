# Core parser proofs

Kani checks selected properties of the production Rust code for every input admitted by
each harness. The `Kani proofs` workflow runs on PRs, main and manual dispatch. Failures,
missing named harnesses and timeouts fail the job. Repository required-check settings are
separate from adding a workflow; this change does not configure branch protection.

## Proof scope

| Harness | Inputs and claim | Boundary |
| --- | --- | --- |
| `envelope::verification::header_validation_and_slicing` | Every byte value for lengths 0 through 64. Inputs shorter than 26 bytes reject first; only scheme 1/algorithm 1 pass the header check; returned nonce/ciphertext slices match the wire layout. | Structural parsing only; authentication and tag validity remain in AEAD. |
| `format::verification::decode_symbol_total_and_compatible` | Every Unicode scalar is classified by the real decoder's symbol helper according to the current Crockford alphabet table and aliases. Reachability covers both accepted and rejected classes. | The proof checks the implementation against the maintained alphabet table; fixed golden vectors independently check the wire spelling. It does not symbolically execute allocation-heavy whole-string round trips or prove `encode_key`/`decode_key`. Native property tests cover those behaviours. |

All safety and unwinding checks remain enabled. The envelope harness loop-unwind limit is 65.
The symbol harness has no production loop to unwind. An insufficient limit is a proof failure,
not permission to ignore the remaining iterations. Production functions are not stubbed.

`aead::open` calls the extracted parser, so the proof covers its actual structural
validation. Native regression tests pin error precedence and the existing `Crypto`
error for a full header with a missing/short authentication tag.

These proofs do not establish cryptographic security, authentication correctness,
unbounded input safety, absence of timing leaks, universal correctness, database concurrency,
or correctness on every target. Existing
crypto property tests and native/WASM vector checks remain necessary. Native Kani
verification is not execution of the WASM artifact.

## Reproduce

Install the exact verifier version with Rustup available:

```sh
cargo install --locked kani-verifier --version 0.67.0
cargo kani setup
cargo kani --version
```

The expected version output is `cargo-kani 0.67.0`. Setup installs Kani's own
`nightly-2025-11-21` compiler; normal builds continue to use the project's stable
toolchain. Kani injects its verification crate, so no production dependency is added.

```sh
cargo kani -p sotto-core --exact \
  --harness envelope::verification::header_validation_and_slicing \
  --harness format::verification::decode_symbol_total_and_compatible \
  --output-format terse -Z unstable-options --harness-timeout 5m --jobs 2
```

The unstable-options flag enables the bounded execution timeout, not weakened checks.
Explicit exact harness names make deletion or renaming fail instead of silently reducing
the suite. CI retains verifier output for 14 days and rejects lockfile changes. Its
15-minute timeout includes setup; each proof has a five-minute execution limit.

Investigate a failed assertion or counterexample against the production function. For
unwinding failures, inspect the loop and input bounds before increasing the limit. A
timeout or unsupported reachable construct is inconclusive and cannot count as success.
Changing an agreed domain requires an explicit scope decision and updated documentation.

References: [Kani installation](https://model-checking.github.io/kani/install-guide.html),
[harness attributes and unwinding](https://model-checking.github.io/kani/reference/attributes.html),
[Cargo integration](https://model-checking.github.io/kani/usage.html).
