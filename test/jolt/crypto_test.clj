(ns jolt.crypto-test
  "Drives the shims through the javax.crypto / java.security surface, exactly the
  way ring-core's session-cookie store does."
  (:require [jolt.bytes :as bytes]
            [jolt.crypto :as crypto]))

(import '[javax.crypto Cipher Mac])
(import '[javax.crypto.spec SecretKeySpec IvParameterSpec])
(import '[java.security SecureRandom MessageDigest])

(def ^:private failures (atom 0))
(defn- check [label ok?] (println (if ok? "ok  " "FAIL") label) (when-not ok? (swap! failures inc)))

(defn- ba= [a b] (= (seq a) (seq b)))
(defn- hex [data]
  (apply str (map #(format "%02x" (bit-and % 0xff)) (seq data))))
(defn- throws? [f]
  (try
    (f)
    false
    (catch Throwable _ true)))

(defn- byte-window
  "Put `body` behind non-empty sentinels so every consumer must respect the
  selected Window rather than accidentally hashing or encrypting its parent."
  [body]
  (let [backing (byte-array (concat [99] body [100]))]
    (bytes/window backing 1 (inc (count body)))))

(defn- encrypt [key data]
  (let [iv (byte-array (repeatedly 16 #(rand-int 256)))
        cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
    (.init cipher Cipher/ENCRYPT_MODE (SecretKeySpec. key "AES") (IvParameterSpec. iv))
    {:iv iv :ct (.doFinal cipher data)}))

(defn- decrypt [key iv ct]
  (let [cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
    (.init cipher Cipher/DECRYPT_MODE (SecretKeySpec. key "AES") (IvParameterSpec. iv))
    (.doFinal cipher ct)))

(defn -main [& _]
  (let [target (jolt.host/target)
        info (crypto/provider-info)
        expected-provider (if (= :windows (:os target)) :cng :openssl)
        expected-os (System/getenv "JOLT_EXPECT_OS")
        expected-arch (System/getenv "JOLT_EXPECT_ARCH")]
    (println "target:" target "provider:" info)
    (check "provider matches the observed operating system"
           (= expected-provider (:name info)))
    (check "provider publishes exactly the portable primitive contract"
           (= #{:aes-cbc :hmac :digest :random-bytes}
              (:operations info)))
    (when expected-os
      (check "target operating system matches the declared CI lane"
             (= (keyword expected-os) (:os target))))
    (when expected-arch
      (check "target architecture matches the declared CI lane"
             (= (keyword expected-arch) (:arch target)))))

  ;; SecureRandom fills a buffer with (probably) non-zero, varying bytes.
  (let [sr (SecureRandom.) a (byte-array 16) b (byte-array 16)]
    (.nextBytes sr a) (.nextBytes sr b)
    (check "SecureRandom fills" (= 16 (alength a)))
    (check "SecureRandom varies" (not (ba= a b)))
    (check "SecureRandom accepts an empty destination"
           (nil? (.nextBytes sr (byte-array 0)))))

  ;; AES-128 round-trip
  (let [key (byte-array (range 16))
        msg (byte-array (map int "the quick brown fox jumps over the lazy dog"))
        {:keys [iv ct]} (encrypt key msg)]
    (check "AES-128 round-trips" (ba= msg (decrypt key iv ct)))
    (check "AES ciphertext differs from plaintext" (not (ba= msg ct))))

  ;; AES-256 round-trip (32-byte key picks the 256 variant)
  (let [key (byte-array (range 32))
        msg (byte-array (map int "secret"))
        {:keys [iv ct]} (encrypt key msg)]
    (check "AES-256 round-trips" (ba= msg (decrypt key iv ct))))

  ;; AES-192 exercises the middle key-size branch on both providers. The native
  ;; operation must not mutate the IV supplied through the Java-compatible API.
  (let [key (byte-array (range 24))
        iv (byte-array (range 16))
        iv-before (aclone iv)
        msg (byte-array 0)
        cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")
        _ (.init cipher Cipher/ENCRYPT_MODE
                 (SecretKeySpec. key "AES")
                 (IvParameterSpec. iv))
        encrypted (.doFinal cipher msg)
        decipher (Cipher/getInstance "AES/CBC/PKCS5Padding")
        _ (.init decipher Cipher/DECRYPT_MODE
                 (SecretKeySpec. key "AES")
                 (IvParameterSpec. iv))
        plaintext (.doFinal decipher encrypted)]
    (check "AES-192 empty plaintext emits one padding block"
           (= 16 (alength encrypted)))
    (check "AES-192 empty plaintext round-trips"
           (zero? (alength plaintext)))
    (check "native AES leaves the caller's IV unchanged"
           (ba= iv-before iv))
    (check "AES rejects a non-standard key length"
           (throws?
            #(let [bad (Cipher/getInstance "AES/CBC/PKCS5Padding")]
               (.init bad Cipher/ENCRYPT_MODE
                      (SecretKeySpec. (byte-array 15) "AES")
                      (IvParameterSpec. iv))
               (.doFinal bad (byte-array 1))))))

  ;; HMAC-SHA256: deterministic, 32 bytes, key-sensitive
  (let [data (byte-array (map int "message"))
        mac1 (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 16)) "HmacSHA256")) (.doFinal m data))
        mac1' (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 16)) "HmacSHA256")) (.doFinal m data))
        mac2 (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 1 17)) "HmacSHA256")) (.doFinal m data))]
    (check "HMAC is 32 bytes" (= 32 (alength mac1)))
    (check "HMAC is deterministic" (ba= mac1 mac1'))
    (check "HMAC is key-sensitive" (not (ba= mac1 mac2))))

  ;; Cross-provider known vectors. These catch a provider that returns the
  ;; wrong HMAC length or selects a plain digest pseudo-handle on Windows.
  (let [key (byte-array (map int "key"))
        data (byte-array (map int "The quick brown fox jumps over the lazy dog"))
        sha256 (let [m (Mac/getInstance "HmacSHA256")]
                 (.init m (SecretKeySpec. key "HmacSHA256"))
                 (.doFinal m data))
        sha1 (let [m (Mac/getInstance "HmacSHA1")]
               (.init m (SecretKeySpec. key "HmacSHA1"))
               (.doFinal m data))]
    (check "HMAC-SHA256 matches the known vector"
           (= "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
              (hex sha256)))
    (check "HMAC-SHA1 matches the known vector"
           (= "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
              (hex sha1)))
    (check "HMAC-SHA1 reports its 20-byte length"
           (= 20 (.getMacLength (doto (Mac/getInstance "HmacSHA1")
                                  (.init (SecretKeySpec. key "HmacSHA1")))))))

  ;; SHA-256 of "abc" — known vector ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  (let [md (MessageDigest/getInstance "SHA-256")
        d  (.digest md (byte-array (map int "abc")))
        hex (hex d)]
    (check "SHA-256(abc) matches NIST vector"
           (= hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")))

  ;; MD5 of "abc" — known vector 900150983cd24fb0d6963f7d28e17f72
  (let [md (MessageDigest/getInstance "MD5")
        d  (.digest md (byte-array (map int "abc")))
        hex (hex d)]
    (check "MD5(abc) matches known vector"
           (= hex "900150983cd24fb0d6963f7d28e17f72")))

  (let [md (MessageDigest/getInstance "SHA-1")
        d (.digest md (byte-array (map int "abc")))]
    (check "SHA-1(abc) matches the known vector"
           (= "a9993e364706816aba3e25717850c26c9cd0d89d"
              (hex d))))

  ;; jolt.bytes Window is a portable byte-region input without becoming a
  ;; runtime dependency of jolt-crypto. All three Java-compatible entry points
  ;; already coerce Seqable binary input through byte-array. Offset sentinels
  ;; prove that only the selected window reaches OpenSSL.
  (let [key-bytes (range 16)
        iv-bytes (range 16 32)
        msg-bytes (map int "windowed crypto input")
        key-window (byte-window key-bytes)
        iv-window (byte-window iv-bytes)
        msg-window (byte-window msg-bytes)
        cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")
        _ (.init cipher
                 Cipher/ENCRYPT_MODE
                 (SecretKeySpec. key-window "AES")
                 (IvParameterSpec. iv-window))
        ciphertext (.doFinal cipher msg-window)
        ciphertext-window (byte-window (seq ciphertext))
        decipher (Cipher/getInstance "AES/CBC/PKCS5Padding")
        _ (.init decipher
                 Cipher/DECRYPT_MODE
                 (SecretKeySpec. key-window "AES")
                 (IvParameterSpec. iv-window))
        plaintext (.doFinal decipher ciphertext-window)
        mac-window (let [m (Mac/getInstance "HmacSHA256")]
                     (.init m (SecretKeySpec. key-window "HmacSHA256"))
                     (.doFinal m msg-window))
        mac-array (let [m (Mac/getInstance "HmacSHA256")]
                    (.init m (SecretKeySpec. (byte-array key-bytes) "HmacSHA256"))
                    (.doFinal m (byte-array msg-bytes)))
        digest-window (.digest (MessageDigest/getInstance "SHA-256") msg-window)
        digest-array (.digest (MessageDigest/getInstance "SHA-256")
                              (byte-array msg-bytes))]
    (check "AES consumes only the selected byte windows"
           (ba= (byte-array msg-bytes) plaintext))
    (check "HMAC over a byte window matches its materialized bytes"
           (ba= mac-array mac-window))
    (check "MessageDigest over a byte window matches its materialized bytes"
           (ba= digest-array digest-window)))

  (if (zero? @failures)
    (println "\nALL CRYPTO TESTS PASSED")
    (do (println "\n" @failures "FAILURES") (System/exit 1))))
