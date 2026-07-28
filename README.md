# jolt-crypto

Symmetric crypto for [Jolt](https://github.com/jolt-lang/jolt), backed by the
operating system's native provider through `jolt.ffi`—OpenSSL (`libcrypto`) on
Linux/macOS and CNG (`bcrypt.dll`) on Windows—and exposed as the slice of the
`javax.crypto` / `java.security` surface real Clojure libraries touch:

| Class | What you get |
|-------|--------------|
| `javax.crypto.Cipher` | `AES/CBC/PKCS5Padding` (128/192/256 — key length picks the variant) |
| `javax.crypto.Mac` | `HmacSHA256`, `HmacSHA1` |
| `java.security.MessageDigest` | `SHA-256`, `SHA-1`, `MD5` |
| `java.security.SecureRandom` | OS-native `nextBytes` / `generateSeed` |
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
`__register-class-statics!` / `__register-class-methods!`)—the same seam
[jolt-lang/http-client](https://github.com/jolt-lang/http-client) uses for its
`java.net` / `java.io` shims. A validated four-operation provider map separates
that portable surface from native AES-CBC, HMAC, digest, and random-byte
handlers. Provider declarations are optional at dependency-graph startup, so a
consumer that carries jolt-crypto but never requires it does not fail on another
platform; requiring `jolt.crypto` fails closed unless the provider for the
observed target loads.

`jolt-crypto` deliberately owns only `libcrypto` on POSIX and `bcrypt.dll` on
Windows. It does not declare `libssl`; TLS consumers own that dependency.

## Test

```
joltc -M:test
```

The local `codex/jolt-bytes-integration` branch also exercises sliced
`jolt.bytes/Window` values through AES, HMAC, and MessageDigest. The dependency
is test-only because the existing Java-compatible entry points already accept
portable Seqable byte regions; see
[`docs/BYTE-WINDOW-INTEGRATION.md`](docs/BYTE-WINDOW-INTEGRATION.md).

The public integration workflow pins Jolt core
`46e1f74fc14f29283586900ef4b98c45375c0500`, disables the AOT cache, asserts the
observed target, and exercises the provider on Linux, macOS, Windows x86_64, and
Windows ARM64 using official Chez Scheme 10.4.1.
