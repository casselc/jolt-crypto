# jolt-crypto

Symmetric crypto for [Jolt](https://github.com/jolt-lang/jolt), bound to the
system OpenSSL (`libcrypto`) through `jolt.ffi`, and exposed as the slice of the
`javax.crypto` / `java.security` surface real Clojure libraries touch:

| Class | What you get |
|-------|--------------|
| `javax.crypto.Cipher` | `AES/CBC/PKCS5Padding` (128/192/256 — key length picks the variant) |
| `javax.crypto.Mac` | `HmacSHA512`, `HmacSHA384`, `HmacSHA256`, `HmacSHA1` |
| `java.security.MessageDigest` | `SHA-512`, `SHA-384`, `SHA-256`, `SHA-224`, `SHA-1`, `MD5` |
| `java.security.SecureRandom` | `RAND_bytes`-backed `nextBytes` / `generateSeed` |
| `javax.crypto.spec.SecretKeySpec` / `IvParameterSpec` | key + IV holders |

This is enough for `ring-core`'s encrypted session-cookie store and the CSRF
token machinery, so **ring-defaults** loads and runs on Jolt.

## Use

```clojure
;; deps.edn
jolt-lang/jolt-crypto {:git/url "https://github.com/jolt-lang/jolt-crypto"
                       :git/sha "..."}
```

```clojure
(require 'jolt.crypto)   ;; installs the host-class shims on load
```

The shims register through Jolt's host-shim hooks (`__register-class-ctor!` /
`__register-class-statics!` / `__register-class-methods!`) — the same seam
[jolt-lang/http-client](https://github.com/jolt-lang/http-client) uses for its
`java.net` / `java.io` shims. `libcrypto`/`libssl` are declared `:jolt/native`
and loaded before the namespace; an app that also pulls http-client shares the
one loaded copy (jolt.deps reconciles natives).

## Test

```
joltc -M:test
```
