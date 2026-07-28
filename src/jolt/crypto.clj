(ns jolt.crypto
  "Symmetric crypto for Jolt, bound to the system OpenSSL (libcrypto) through
  jolt.ffi, and exposed as the small slice of the `javax.crypto` / `java.security`
  surface that real Clojure libraries touch:

    Cipher        AES/CBC/PKCS5Padding (128/192/256, key length picks the variant)
    Mac           HmacSHA256 / HmacSHA1
    MessageDigest SHA-256 / SHA-1 / MD5
    SecureRandom  RAND_bytes
    SecretKeySpec / IvParameterSpec   key + IV holders

  This is enough for ring-core's encrypted session-cookie store and the CSRF
  token machinery, so ring-defaults loads and runs. Shim objects are host
  tagged-tables (jolt.host/tagged-table) whose fields are read/written with
  ref-get / ref-put!; everything registers through Jolt's host-shim hooks
  (__register-class-ctor! / __register-class-statics! / __register-class-methods!),
  the same seam jolt-lang/http-client uses for its java.net / java.io shims.

  Platform-native calls are selected behind a four-operation provider map:
  OpenSSL on Linux/macOS and Windows CNG through bcrypt.dll on Windows."
  (:require [jolt.crypto.provider :as provider]))

;; --- helpers ----------------------------------------------------------------
(defn- tt [tag] (jolt.host/tagged-table tag))
(defn- tget [t k] (jolt.host/ref-get t k))
(defn- tput! [t k v] (jolt.host/ref-put! t k v))
(defn- table? [x] (jolt.host/table? x))

;; Binary bytes only — these objects never carry text, so coerce through
;; byte-array (a seq/byte-array round-trips; never the UTF-8 read/write-bytes).
(defn- ->ba [x]
  (cond
    (and (table? x) (#{:jolt.crypto/key :jolt.crypto/iv} (tget x :jolt/type))) (tget x :bytes)
    :else (byte-array x)))

(defn provider-info
  "Describe the selected native provider without exposing native handles."
  []
  (provider/info))

;; --- AES-CBC (PKCS5/PKCS7 padding is EVP's CBC default) ---------------------
(defn aes-cbc [encrypt? key iv data]
  (provider/aes-cbc encrypt? (->ba key) (->ba iv) (->ba data)))

;; --- HMAC -------------------------------------------------------------------
(defn hmac [algorithm key data]
  (provider/hmac algorithm (->ba key) (->ba data)))

;; --- digest -----------------------------------------------------------------
(defn digest [algorithm data]
  (provider/digest algorithm (->ba data)))

(defn random-bytes [n]
  (provider/random-bytes n))

;; --- algorithm name -> primitive --------------------------------------------
(defn- mac-md [algo]
  (case (str algo)
    ("HmacSHA256" "HMACSHA256") [:sha256 32]
    ("HmacSHA1" "HMACSHA1") [:sha1 20]
    (throw (ex-info (str "unsupported Mac algorithm: " algo) {:algo algo}))))
(defn- digest-spec [algo]
  (case (str algo)
    ("SHA-256" "SHA256") [:sha256 32]
    ("SHA-1" "SHA1") [:sha1 20]
    ("MD5") [:md5 16]
    (throw (ex-info (str "unsupported MessageDigest algorithm: " algo) {:algo algo}))))

;; --- host-class shims -------------------------------------------------------
(def ENCRYPT-MODE 1)
(def DECRYPT-MODE 2)

(defn install! []
  ;; javax.crypto.spec.SecretKeySpec / IvParameterSpec — key + IV holders.
  (doseq [nm ["SecretKeySpec" "javax.crypto.spec.SecretKeySpec"]]
    (__register-class-ctor! nm (fn [key & _] (doto (tt :jolt.crypto/key) (tput! :bytes (byte-array key))))))
  (doseq [nm ["IvParameterSpec" "javax.crypto.spec.IvParameterSpec"]]
    (__register-class-ctor! nm (fn [iv & _] (doto (tt :jolt.crypto/iv) (tput! :bytes (byte-array iv))))))
  (__register-class-methods! :jolt.crypto/key {"getEncoded" (fn [self] (tget self :bytes))
                                               "getAlgorithm" (fn [self] (or (tget self :algo) "AES"))})

  ;; javax.crypto.Cipher — getInstance + ENCRYPT_MODE/DECRYPT_MODE, then the
  ;; stateful init/doFinal pair (Java's Cipher is mutable: init sets key+iv+mode).
  (doseq [nm ["Cipher" "javax.crypto.Cipher"]]
    (__register-class-statics! nm {"getInstance" (fn [algo & _] (doto (tt :jolt.crypto/cipher) (tput! :algo (str algo))))
                                   "ENCRYPT_MODE" ENCRYPT-MODE
                                   "DECRYPT_MODE" DECRYPT-MODE}))
  (__register-class-methods! :jolt.crypto/cipher
    {"init" (fn [self mode key & more]
              (tput! self :mode mode)
              (tput! self :key (->ba key))
              (tput! self :iv (if (seq more) (->ba (first more)) (random-bytes 16)))
              nil)
     "doFinal" (fn [self data & _]
                 (aes-cbc (= ENCRYPT-MODE (tget self :mode)) (tget self :key) (tget self :iv) data))
     "getIV" (fn [self] (tget self :iv))
     "getBlockSize" (fn [self] 16)})

  ;; javax.crypto.Mac
  (doseq [nm ["Mac" "javax.crypto.Mac"]]
    (__register-class-statics!
     nm
     {"getInstance"
      (fn [algo & _]
        (let [[algorithm length] (mac-md algo)]
          (doto (tt :jolt.crypto/mac)
            (tput! :algorithm algorithm)
            (tput! :length length))))}))
  (__register-class-methods! :jolt.crypto/mac
    {"init" (fn [self key & _] (tput! self :key (->ba key)) nil)
     "doFinal" (fn [self data & _]
                 (hmac (tget self :algorithm) (tget self :key) data))
     "getMacLength" (fn [self] (tget self :length))})

  ;; java.security.MessageDigest
  (doseq [nm ["MessageDigest" "java.security.MessageDigest"]]
    (__register-class-statics! nm {"getInstance" (fn [algo & _]
                                                   (let [[mdf len] (digest-spec algo)]
                                                     (doto (tt :jolt.crypto/md) (tput! :md mdf) (tput! :len len) (tput! :acc []))))}))
  (__register-class-methods! :jolt.crypto/md
    {"update" (fn [self data & _] (tput! self :acc (into (tget self :acc) (seq (->ba data)))) nil)
     "digest" (fn [self & args]
                (let [body (if (seq args) (->ba (first args)) (byte-array (tget self :acc)))]
                  (tput! self :acc [])
                  (digest (tget self :md) body)))
     "reset" (fn [self] (tput! self :acc []) nil)})

  ;; java.security.SecureRandom — real RAND_bytes (http-client's stub only made
  ;; a table; this fills the buffer for genuine randomness).
  (doseq [nm ["SecureRandom" "java.security.SecureRandom"]]
    (__register-class-ctor! nm (fn [& _] (tt :jolt.crypto/secure-random))))
  (__register-class-methods! :jolt.crypto/secure-random
    {"nextBytes" (fn [self buf & _]
                   (let [n (alength buf) r (random-bytes n)]
                     (dotimes [i n] (aset buf i (aget r i)))
                     nil))
     "generateSeed" (fn [self n] (random-bytes n))})
  nil)

(install!)
