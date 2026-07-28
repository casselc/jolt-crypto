# ADR 0001: Select platform-native crypto behind one handler contract

## Status

Accepted on the `codex/jolt-bytes-integration` upstream-candidate branch.

## Context

The original implementation bound every primitive directly to OpenSSL and
declared `libcrypto` plus `libssl` as required native dependencies. Those
declarations named only Linux and Darwin candidates. Jolt resolves required
native dependencies eagerly, before application namespaces load, so merely
carrying `jolt-crypto` made an otherwise unrelated Windows application abort:

```text
required native library crypto not found — tried [] for windows
```

Installing an OpenSSL DLL could not help because the Windows candidate list was
empty. More importantly, Windows already provides the required primitives
through CNG in `bcrypt.dll`; requiring an unrelated OpenSSL distribution would
create an unnecessary deployment dependency.

The public Java-compatible surface needs only four native operations:

- AES-CBC with PKCS#7 padding;
- keyed HMAC;
- one-shot message digest; and
- cryptographically secure random bytes.

## Decision

`jolt.crypto.provider` validates and selects a small handler map containing
`:aes-cbc`, `:hmac`, `:digest`, and `:random-bytes`.

- Linux and macOS select OpenSSL `libcrypto`.
- Windows selects CNG from the system `bcrypt.dll`.
- The Java-compatible shims in `jolt.crypto` depend only on the handler
  contract, never on native handles or provider-specific algorithm objects.
- `provider-info` exposes the selected provider and target for diagnostics but
  no native handle.

Windows uses Windows 10+ CNG algorithm pseudo-handles:

- `BCRYPT_AES_CBC_ALG_HANDLE`;
- `BCRYPT_MD5_ALG_HANDLE`, `BCRYPT_SHA1_ALG_HANDLE`, and
  `BCRYPT_SHA256_ALG_HANDLE`; and
- `BCRYPT_HMAC_SHA1_ALG_HANDLE` and `BCRYPT_HMAC_SHA256_ALG_HANDLE`.

Pseudo-handles avoid provider-open/close ownership and UTF-16 algorithm
identifiers. AES keys still have explicit lifetime: every
`BCryptGenerateSymmetricKey` handle is retired by `BCryptDestroyKey`.
`BCryptEncrypt` and `BCryptDecrypt` mutate their IV buffer, so the CNG provider
copies the caller's IV and preserves the portable non-mutation contract.
`BCryptGenRandom` uses `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.

The native declarations are optional at dependency-graph startup. Requiring
`jolt.crypto` then selects and loads the provider for the observed target and
fails closed if it is unavailable. This lets a cross-platform application carry
the library without eagerly loading a provider it never uses.

`libssl` is removed from this library's dependency declaration. No primitive in
`jolt-crypto` uses it; TLS libraries must own their own TLS provider.

## Contract evidence

Both providers run the same public suite:

- AES-128 and AES-256 round trips;
- HMAC-SHA256 and HMAC-SHA1 known vectors and exact lengths;
- SHA-256 and MD5 known vectors;
- native secure-random fill;
- exact target/provider selection; and
- sentinel-guarded `jolt.bytes/Window` inputs through AES, HMAC, and digest.

The tests use Jolt core
`46e1f74fc14f29283586900ef4b98c45375c0500`, whose scoped
`with-byte-array-pointer` primitive borrows non-empty byte arrays only for the
dynamic extent of a native call chain. Native code may not retain those
pointers. Provider-owned outputs, mutable IV copies, and native handles remain
explicitly allocated and retired.

This establishes provider agreement at the public contract. It does not prove
the implementations of OpenSSL or CNG, side-channel resistance, operating
system entropy guarantees, or the Jolt FFI implementation itself.

## Consequences

- `ring-chez-adapter` and similar applications can retain `jolt-crypto` in their
  ordinary dependency graph on Windows.
- Windows needs no artifact download or external OpenSSL installation.
- Windows x86_64 and ARM64 exercise the same CNG source.
- HMAC-SHA1 now returns and reports 20 bytes. The old OpenSSL adapter
  accidentally hard-coded 32 bytes for every HMAC algorithm.
- Adding a provider requires satisfying the four-operation handler contract and
  passing the same known-vector and byte-window suite.

## Rejected approaches

### Ship or discover OpenSSL on Windows

This adds a native artifact and loader-path problem despite Windows already
shipping the required primitives. Git for Windows happens to carry a suitable
DLL on one development host, but that is not an application runtime contract.

### Keep crypto as an opt-in downstream alias

That unblocks applications which never use crypto, but applications using Ring
sessions or CSRF still fail. It treats a provider defect as every consumer's
dependency-management problem.

### Put crypto primitives in core Jolt

The FFI primitives belong in core; this policy and compatibility surface do
not. Keeping provider selection in the library lets it evolve independently and
offers a concrete handler-map shape for a future portable
`clojure.platform.crypto` contract.
