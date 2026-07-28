# Byte-window integration evidence

This local upstream-candidate branch checks that `jolt-crypto` composes with
the incubating `jolt.bytes/Window` API without coupling production crypto code
to one byte container.

## Selected shape

`jolt-crypto` keeps its existing Java-compatible inputs. `SecretKeySpec`,
`IvParameterSpec`, `Cipher.doFinal`, `Mac.doFinal`, and
`MessageDigest.digest` already coerce Seqable binary values through
`byte-array`; `jolt.bytes/Window` implements that contract. The
`jolt-bytes` dependency is therefore test-only.

The integration gate creates every Window over a larger byte array with
non-empty prefix and suffix sentinels. It checks:

- AES-CBC accepts Window key, IV, plaintext, and ciphertext and round-trips the
  selected plaintext;
- HMAC-SHA256 over a Window equals HMAC-SHA256 over its materialized bytes; and
- SHA-256 over a Window equals SHA-256 over its materialized bytes.

This catches an implementation that consumes the parent array rather than the
selected half-open Window.

## Evidence and proof boundary

The gate was run in source mode against:

- Jolt proposal core
  `46e1f74fc14f29283586900ef4b98c45375c0500`;
- `jolt-bytes`
  `c34b4d2275240a1efc7630f94cf97880cb905cc9`; and
- official Chez Scheme 10.4.1.

All 13 crypto checks passed. The existing NIST/known-vector checks and AES
round trips still passed.

The platform-provider follow-on expands this to 26 checks. The same
sentinel-guarded Window values cross both implementations of the native handler
contract:

- OpenSSL on Linux and macOS, x86_64 and aarch64; and
- Windows CNG on native Windows x86_64 and ARM64.

Hosted run
[`30377886592`](https://github.com/casselc/jolt-crypto/actions/runs/30377886592)
passed all six jobs at exact source revision
`00a3a9a23f49bf4cd02fd87aa11ee8c921b2a6f6`. Every lane used exact Jolt core
`46e1f74f`, official Chez 10.4.1, source mode with the AOT cache disabled, and
an exact target assertion. Each printed the selected provider and the complete
four-operation handler set before all 26 checks passed.

The documentation-tip follow-up,
[`30380719100`](https://github.com/casselc/jolt-crypto/actions/runs/30380719100),
also passed all six jobs. Every target restored its Chez cache and skipped both
the build and save steps; individual jobs completed in about 24–85 seconds
instead of the cold run's 3–9 minutes. The checked-in restore/build/assert/save
sequence therefore avoids repeat compilation within this repository. GitHub
Actions caches remain repository-scoped, so eliminating the first build in
each downstream repository requires a separately published, checksum-pinned
toolchain archive rather than weaker cache keys.

The native local Windows x86_64 run also selected CNG even though the
development machine has an unrelated OpenSSL DLL installed with Git for
Windows. That distinguishes provider selection from accidental symbol
availability.

The `jolt-bytes` Ansatz and exhaustive runtime evidence establishes the
Window's bounded selection and traversal contract. This gate establishes that
the crypto adapter observes that traversal contract at the FFI boundary. It
does not prove OpenSSL's algorithms, native ABI correctness, constant-time
behavior, or alias non-escape.

A zero-copy native borrow is deliberately not inferred from this result.
`jolt.bytes` does not expose its backing array, and portable Clojure cannot
enforce that an arbitrary callback does not retain an alias. Any future scoped
borrow belongs in a separately specified runtime SPI with explicit lifetime,
mutation, exception, and retention laws; it should not be smuggled into the
portable Window API merely to optimize this consumer.

## Reproduction

Run from the proposal-core checkout so the source launcher can find its
vendored submodules:

```sh
JOLT_PWD=/path/to/jolt-crypto \
JOLT_AOT_CACHE=0 \
/path/to/chez-10.4.1/bin/scheme --script host/chez/cli.ss -M:test
```

This branch is published in the writable `casselc/jolt-crypto` fork. The
inherited released-`joltc` workflow has been replaced with a source-runtime
matrix pinned to the reviewed Jolt core. It covers Linux and macOS on x86_64
and aarch64 plus native Windows x86_64 and ARM64. The six-lane hosted evidence
above promotes all six from proposed to observed source-runtime coverage; it
does not imply packaged-`joltc` or AOT coverage.
