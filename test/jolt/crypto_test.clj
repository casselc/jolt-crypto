(ns jolt.crypto-test
  "Drives the shims through the javax.crypto / java.security surface, exactly the
  way ring-core's session-cookie store does."
  (:require [jolt.crypto]))

(import '[javax.crypto Cipher Mac])
(import '[javax.crypto.spec SecretKeySpec IvParameterSpec])
(import '[java.security SecureRandom MessageDigest])

(def ^:private failures (atom 0))
(defn- check [label ok?] (println (if ok? "ok  " "FAIL") label) (when-not ok? (swap! failures inc)))

(defn- ba= [a b] (= (seq a) (seq b)))

(defn- hex [d] (apply str (map #(format "%02x" (bit-and % 0xff)) (seq d))))

(def ^:private foo (byte-array (map int "foo")))
(def ^:private k (byte-array (map int "k")))

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
  ;; SecureRandom fills a buffer with (probably) non-zero, varying bytes.
  (let [sr (SecureRandom.) a (byte-array 16) b (byte-array 16)]
    (.nextBytes sr a) (.nextBytes sr b)
    (check "SecureRandom fills" (= 16 (alength a)))
    (check "SecureRandom varies" (not (ba= a b))))

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

  ;; HMAC-SHA256: deterministic, 32 bytes, key-sensitive
  (let [data (byte-array (map int "message"))
        mac1 (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 16)) "HmacSHA256")) (.doFinal m data))
        mac1' (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 16)) "HmacSHA256")) (.doFinal m data))
        mac2 (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 1 17)) "HmacSHA256")) (.doFinal m data))]
    (check "HMAC is 32 bytes" (= 32 (alength mac1)))
    (check "HMAC is deterministic" (ba= mac1 mac1'))
    (check "HMAC is key-sensitive" (not (ba= mac1 mac2))))

  ;; SHA-256 of "abc" — known vector ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  (let [md (MessageDigest/getInstance "SHA-256")
        d  (.digest md (byte-array (map int "abc")))
        hex (apply str (map #(format "%02x" (bit-and % 0xff)) (seq d)))]
    (check "SHA-256(abc) matches NIST vector"
           (= hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")))

  ;; update-then-digest accumulates: digest(bytes) appends to the updated
  ;; state (the JVM contract clj-uuid's digest-bytes relies on), so the split
  ;; feed equals the one-shot digest of the concatenation.
  (let [one (.digest (MessageDigest/getInstance "SHA-256") (byte-array (map int "abc")))
        two (let [md (MessageDigest/getInstance "SHA-256")]
              (.update md (byte-array (map int "ab")))
              (.digest md (byte-array (map int "c"))))
        three (let [md (MessageDigest/getInstance "SHA-256")]
                (.update md (byte-array (map int "a")))
                (.update md (byte-array (map int "b")))
                (.digest md (byte-array (map int "c"))))]
    (check "update then digest equals one-shot" (ba= one two))
    (check "updates accumulate across calls" (ba= one three)))

  ;; MD5 of "abc" — known vector 900150983cd24fb0d6963f7d28e17f72
  (let [md (MessageDigest/getInstance "MD5")
        d  (.digest md (byte-array (map int "abc")))
        hex (apply str (map #(format "%02x" (bit-and % 0xff)) (seq d)))]
    (check "MD5(abc) matches known vector"
           (= hex "900150983cd24fb0d6963f7d28e17f72")))

  ;; SHA-2 family over "foo" — hex vectors measured on the reference JVM
  (doseq [[algo len expected]
          [["MD5"     16 "acbd18db4cc2f85cedef654fccc4a4d8"]
           ["SHA-1"   20 "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"]
           ["SHA-224" 28 "0808f64e60d58979fcb676c96ec938270dea42445aeefcd3a4e6f8db"]
           ["SHA-256" 32 "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"]
           ["SHA-384" 48 "98c11ffdfdd540676b1a137cb1a22b2a70350c9a44171d6b1180c6be5cbb2ee3f79d532c8a1dd9ef2e8e08e752a3babb"]
           ["SHA-512" 64 "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"]]]
    (let [d (.digest (MessageDigest/getInstance algo) foo)]
      (check (str algo "(foo) is " len " bytes") (= len (alength d)))
      (check (str algo "(foo) matches JVM vector") (= expected (hex d)))))

  ;; the dashless spelling resolves to the same digest
  (check "SHA512 alias matches SHA-512"
         (= (hex (.digest (MessageDigest/getInstance "SHA-512") foo))
            (hex (.digest (MessageDigest/getInstance "SHA512") foo))))

  ;; HMAC over "foo" with key "k" — hex vectors measured on the reference JVM
  ;; (HmacSHA384 measured via OpenSSL; its SHA-256/512 outputs match the JVM
  ;; vectors byte-for-byte, so the measurement is authoritative)
  (doseq [[algo len expected]
          [["HmacSHA1"   20 "7a19f035e2380ef9611f621a635ee1062418880a"]
           ["HmacSHA256" 32 "dc9652dbf73f8c8e4f8d522960bd624b011981816111ce435979a911e929aba5"]
           ["HmacSHA384" 48 "fbd8da1a4a002a279c5bfe96950f7c4b893467b63accb010bde2ec380169101a81f541e968e8ac71391fd4d2740e45c4"]
           ["HmacSHA512" 64 "5df9826d89479edcc2aa25c2336798fca37f760ddc249adc96843692bea2c71610d4e14ba2580181bd86ac6f0f71bf4b1e2bc1c15fe28a1c97a5bebd0b355166"]]]
    (let [m (Mac/getInstance algo)]
      (.init m (SecretKeySpec. k algo))
      (let [d (.doFinal m foo)]
        (check (str algo "(k, foo) is " len " bytes") (= len (alength d)))
        (check (str algo "(k, foo) matches JVM vector") (= expected (hex d)))
        (check (str algo " getMacLength") (= len (.getMacLength m))))))

  ;; unknown algorithms throw, naming the algorithm
  (let [msg (try (MessageDigest/getInstance "WHIRLPOOL") nil
                 (catch Exception e (.getMessage e)))]
    (check "unknown MessageDigest algorithm throws naming it"
           (= msg "unsupported MessageDigest algorithm: WHIRLPOOL")))
  (let [msg (try (Mac/getInstance "HmacWHIRLPOOL") nil
                 (catch Exception e (.getMessage e)))]
    (check "unknown Mac algorithm throws naming it"
           (= msg "unsupported Mac algorithm: HmacWHIRLPOOL")))

  (if (zero? @failures)
    (println "\nALL CRYPTO TESTS PASSED")
    (do (println "\n" @failures "FAILURES") (System/exit 1))))
