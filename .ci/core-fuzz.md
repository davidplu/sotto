# Core codec fuzzing

The core fuzz workflow drives the real `sotto-core` format APIs with libFuzzer and
AddressSanitizer on Linux. It covers base32 strings and versioned key strings. The
fuzz package is isolated from the application workspace and has its own lockfile.

## Reproduce locally

Install the pinned tools and nightly compiler:

```sh
cargo +stable install --locked cargo-fuzz --version 0.13.2
rustup toolchain install nightly-2025-11-21 --profile minimal
```

Run the 30-second PR profile for either target:

```sh
scripts/check-core-fuzz --profile pr --target base32_codec
scripts/check-core-fuzz --profile pr --target key_strings
```

The runner bounds each fuzzer input at 16,385 bytes, including its one-byte mode
prefix (the generated body boundary is 16,384 bytes and the production payload boundary
is 4,096 bytes), and writes a fresh record under
`target/core-fuzz/`. It starts each record with `status: failed`, records the exact
commit, command, toolchain, platform, configuration and lockfile digests, starting
corpus digest, workflow identity and execution count, and changes status only after
every tracked seed has replayed successfully and libFuzzer emits its completion marker
and exits successfully. Logs are retained in the record. A timeout, signal, sanitizer
failure, missing target, zero executions or missing completion marker remains
failed/inconclusive. Each input also has a ten-second libFuzzer timeout so a single
hang cannot consume the campaign budget. Seed replays have a two-minute process watchdog to
allow sanitizer startup while keeping a bounded failure path. Pull request campaigns use and
record the fixed nonzero libFuzzer seed `0x5A17` for reproducible mutation sequences. Nightly
jobs set `CORE_FUZZ_SEED` to their unique GitHub run ID; the runner folds that ID into
libFuzzer's 32-bit seed range, so each run explores a fresh mutation sequence and records the
effective seed in its evidence. Manual or local nightly runs generate a fresh
nonzero seed unless `--seed` or `CORE_FUZZ_SEED` supplies one.

Trusted starter inputs live in `fuzz/seeds/<target>/`. The runner copies them into a fresh
working corpus under `target/core-fuzz/`; the ignored `fuzz/corpus/` directory is reserved for
local cargo-fuzz state and must not be used as evidence.
An optional trusted generated corpus can be added to that fresh copy with `--corpus
/path/to/corpus`; its digest is recorded alongside the tracked seed digest.

For a one-input replay:

```sh
scripts/check-core-fuzz --profile pr --target key_strings \
  --replay /path/to/failing-input
```

Replay does not claim a campaign completed; it only verifies the saved reproducer exits
according to the target's assertion. Use synthetic inputs only. Never commit generated
artifacts or promote a PR corpus into trusted nightly corpus storage.

## Target modes

`base32_codec` uses a mode byte followed by bounded payload data. It exercises encoder
round trips, valid UTF-8 decoding and constructed valid/invalid Crockford symbols,
separators and aliases.

`key_strings` uses a mode byte followed by bounded data. It exercises `SK`, `RK` and
`MT` versioned keys, arbitrary text, correctly shaped but malformed bodies, wrong
versions and successful round trips. Separate modes assert missing headers, invalid
symbols, short bodies and checksum mutations after a valid header. The tracked seeds
include NUL, whitespace, multibyte and combining text plus each rejection stage.

The properties and fixed WASM/native fixtures remain the deterministic oracle. A fuzz
finding is not fixed by changing production validation to accept it. Minimise the saved
input, add a normal regression test in a separate change, and retain the original
reproducer in the private campaign record.

## CI allocation

Pull requests and pushes to `main` run both targets independently for 30 seconds each
after seed replay. Nightly runs both targets for 30 minutes each with `fail-fast: false`.
Manual dispatch selects either profile at the selected ref. Linux x86_64 is the
sanitizer authority; native core source tests run on Ubuntu, macOS and Windows, and
WASM tests remain separate.

The workflow pins the cargo-fuzz release, Rust nightly, actions and the fuzz lockfile.
It uploads each run record on success or failure for 14 days. A successful earlier run
cannot satisfy a later failed or incomplete invocation. This workflow does not create
release holds or configure repository required-check settings; those remain separate
assurance work.

The local Apple Silicon ASAN binary currently hangs before libFuzzer prints its help or
initialisation banner. Local smoke can use `--sanitizer none` to validate target logic;
CI's Linux AddressSanitizer run is the sanitizer evidence and must be green before the
campaign is considered complete.
