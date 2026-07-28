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

The public `jolt-crypto` workflow still uses the latest released `joltc`.
Hosted proof-stack evidence should wait until the required proposal-core
semantics are in an upstream release or a writable downstream fork is
explicitly selected.
