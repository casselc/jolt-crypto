(ns jolt.crypto
  "Symmetric crypto for Jolt, bound to the system OpenSSL (libcrypto) through
  jolt.ffi, and exposed as the small slice of the `javax.crypto` / `java.security`
  surface that real Clojure libraries touch:

    Cipher        AES/CBC/PKCS5Padding (128/192/256, key length picks the variant)
    Mac           HmacSHA512 / HmacSHA384 / HmacSHA256 / HmacSHA1
    MessageDigest SHA-512 / SHA-384 / SHA-256 / SHA-224 / SHA-1 / MD5
    SecureRandom  RAND_bytes
    SecretKeySpec / IvParameterSpec   key + IV holders
    KeyPairGenerator / KeyFactory / Signature   EC over the NIST P-curves,
                  with X509EncodedKeySpec / PKCS8EncodedKeySpec / ECGenParameterSpec

  This is enough for ring-core's encrypted session-cookie store and the CSRF
  token machinery, so ring-defaults loads and runs. Shim objects are host
  tagged-tables (jolt.host/tagged-table) whose fields are read/written with
  ref-get / ref-put!; everything registers through Jolt's host-shim hooks
  (__register-class-ctor! / __register-class-statics! / __register-class-methods!),
  the same seam jolt-lang/http-client uses for its java.net / java.io shims.

  libcrypto/libssl are declared in deps.edn :jolt/native and loaded before this
  namespace; an app that also pulls http-client shares the one loaded copy."
  (:require [jolt.ffi :as ffi]
            [clojure.string :as str]))

;; --- OpenSSL (libcrypto) bindings -------------------------------------------
(ffi/defcfn c-rand     "RAND_bytes"          [:pointer :int] :int)
(ffi/defcfn c-aes128   "EVP_aes_128_cbc"     [] :pointer)
(ffi/defcfn c-aes192   "EVP_aes_192_cbc"     [] :pointer)
(ffi/defcfn c-aes256   "EVP_aes_256_cbc"     [] :pointer)
(ffi/defcfn c-md5      "EVP_md5"             [] :pointer)
(ffi/defcfn c-sha1     "EVP_sha1"            [] :pointer)
(ffi/defcfn c-sha224   "EVP_sha224"          [] :pointer)
(ffi/defcfn c-sha256   "EVP_sha256"          [] :pointer)
(ffi/defcfn c-sha384   "EVP_sha384"          [] :pointer)
(ffi/defcfn c-sha512   "EVP_sha512"          [] :pointer)
(ffi/defcfn c-ctx-new  "EVP_CIPHER_CTX_new"  [] :pointer)
(ffi/defcfn c-ctx-free "EVP_CIPHER_CTX_free" [:pointer] :void)
(ffi/defcfn c-enc-init "EVP_EncryptInit_ex"  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-enc-upd  "EVP_EncryptUpdate"   [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-enc-fin  "EVP_EncryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-init "EVP_DecryptInit_ex"  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-upd  "EVP_DecryptUpdate"   [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-dec-fin  "EVP_DecryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac     "HMAC"   [:pointer :pointer :int :pointer :size_t :pointer :pointer] :pointer)
(ffi/defcfn c-digest   "EVP_Digest" [:pointer :size_t :pointer :pointer :pointer :pointer] :int)

;; EC keys and ECDSA. EVP_EC_gen is a macro rather than an exported symbol, so
;; keygen goes through EC_KEY and is then wrapped in an EVP_PKEY for encoding
;; and signing. i2d_*/d2i_* are the DER codecs: i2d_PUBKEY is X.509
;; SubjectPublicKeyInfo (what PublicKey.getEncoded returns) and EVP_PKEY2PKCS8 +
;; i2d_PKCS8_PRIV_KEY_INFO is PKCS#8 PrivateKeyInfo (PrivateKey.getEncoded).
(ffi/defcfn c-ec-new-curve "EC_KEY_new_by_curve_name" [:int] :pointer)
(ffi/defcfn c-ec-gen       "EC_KEY_generate_key"      [:pointer] :int)
(ffi/defcfn c-ec-free      "EC_KEY_free"              [:pointer] :void)
(ffi/defcfn c-pkey-new     "EVP_PKEY_new"             [] :pointer)
(ffi/defcfn c-pkey-set-ec  "EVP_PKEY_set1_EC_KEY"     [:pointer :pointer] :int)
(ffi/defcfn c-pkey-free    "EVP_PKEY_free"            [:pointer] :void)
(ffi/defcfn c-i2d-pubkey   "i2d_PUBKEY"               [:pointer :pointer] :int)
(ffi/defcfn c-d2i-pubkey   "d2i_PUBKEY"               [:pointer :pointer :long] :pointer)
(ffi/defcfn c-pkey->p8     "EVP_PKEY2PKCS8"           [:pointer] :pointer)
(ffi/defcfn c-i2d-p8       "i2d_PKCS8_PRIV_KEY_INFO"  [:pointer :pointer] :int)
(ffi/defcfn c-p8-free      "PKCS8_PRIV_KEY_INFO_free" [:pointer] :void)
(ffi/defcfn c-d2i-privkey  "d2i_AutoPrivateKey"       [:pointer :pointer :long] :pointer)
(ffi/defcfn c-md-ctx-new   "EVP_MD_CTX_new"           [] :pointer)
(ffi/defcfn c-md-ctx-free  "EVP_MD_CTX_free"          [:pointer] :void)
(ffi/defcfn c-dgst-sign-init   "EVP_DigestSignInit"   [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-sign        "EVP_DigestSign"       [:pointer :pointer :pointer :pointer :size_t] :int)
(ffi/defcfn c-dgst-verify-init "EVP_DigestVerifyInit" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-verify      "EVP_DigestVerify"     [:pointer :pointer :size_t :pointer :size_t] :int)

;; --- helpers ----------------------------------------------------------------
(defn- tt [tag] (jolt.host/tagged-table tag))
(defn- tget [t k] (jolt.host/ref-get t k))
(defn- tput! [t k v] (jolt.host/ref-put! t k v))
(defn- table? [x] (jolt.host/table? x))

;; binary bytes only — these objects never carry text, so coerce through
;; byte-array (a seq/byte-array round-trips; never the UTF-8 read/write-bytes).
(defn- ->ba [x]
  (cond
    (and (table? x) (#{:jolt.crypto/key :jolt.crypto/iv
                       :jolt.crypto/ec-public :jolt.crypto/ec-private
                       :jolt.crypto/x509-spec :jolt.crypto/pkcs8-spec}
                     (tget x :jolt/type)))
    (tget x :bytes)
    :else (byte-array x)))

(defn- with-ptrs
  "Alloc a C buffer per byte-array in `bas`, copy each in, run (f ptrs…), free all."
  [bas f]
  (let [ptrs (mapv (fn [ba] (let [n (max 1 (alength ba)) p (ffi/alloc n)]
                              (ffi/write-array p ba) p))
                   bas)]
    (try (apply f ptrs) (finally (doseq [p ptrs] (ffi/free p))))))

(defn- evp-cipher-for [keylen]
  (case keylen 16 (c-aes128) 24 (c-aes192) 32 (c-aes256)
    (throw (ex-info (str "AES key must be 16/24/32 bytes, got " keylen) {:keylen keylen}))))

;; --- AES-CBC (PKCS5/PKCS7 padding is EVP's CBC default) ---------------------
(defn aes-cbc [encrypt? key iv data]
  (let [key (->ba key) iv (->ba iv) data (->ba data)
        ctx (c-ctx-new) ciph (evp-cipher-for (alength key)) inlen (alength data)]
    (with-ptrs [key iv data]
      (fn [keyp ivp inp]
        (let [outp (ffi/alloc (+ inlen 32)) outlp (ffi/alloc 4)
              [init upd fin] (if encrypt? [c-enc-init c-enc-upd c-enc-fin]
                                          [c-dec-init c-dec-upd c-dec-fin])]
          (try
            (when (not= 1 (init ctx ciph ffi/null keyp ivp)) (throw (ex-info "cipher init failed" {})))
            (when (not= 1 (upd ctx outp outlp inp inlen)) (throw (ex-info "cipher update failed" {})))
            (let [n1 (ffi/read outlp :int)]
              (when (not= 1 (fin ctx (+ outp n1) outlp))
                (throw (ex-info (if encrypt? "cipher final failed" "bad padding / wrong key") {})))
              (ffi/read-array outp (+ n1 (ffi/read outlp :int))))
            (finally (c-ctx-free ctx) (ffi/free outp) (ffi/free outlp))))))))

;; --- HMAC -------------------------------------------------------------------
(defn hmac [md-fn outlen key data]
  (let [key (->ba key) data (->ba data) kl (alength key) dl (alength data)]
    (with-ptrs [key data]
      (fn [kp dp]
        (let [mdp (ffi/alloc 64)]
          (try (c-hmac (md-fn) kp kl dp dl mdp ffi/null) (ffi/read-array mdp outlen)
               (finally (ffi/free mdp))))))))

;; --- digest -----------------------------------------------------------------
(defn digest [md-fn outlen data]
  (let [data (->ba data) dl (alength data)]
    (with-ptrs [data]
      (fn [dp]
        (let [mdp (ffi/alloc 64) lenp (ffi/alloc 4)]
          (try (when (not= 1 (c-digest dp dl mdp lenp (md-fn) ffi/null))
                 (throw (ex-info "digest failed" {})))
               (ffi/read-array mdp outlen)
               (finally (ffi/free mdp) (ffi/free lenp))))))))

(defn random-bytes [n]
  (let [p (ffi/alloc (max 1 n))]
    (try (when (not= 1 (c-rand p n)) (throw (ex-info "RAND_bytes failed" {})))
         (ffi/read-array p n)
         (finally (ffi/free p)))))

;; --- EC keys ----------------------------------------------------------------
;; Curve NIDs from OpenSSL's obj_mac.h. The JDK's EC provider names these
;; "secp256r1" and "NIST P-256"; prime256v1 (the ANSI X9.62 spelling) and the
;; bare P-256 are accepted here too, so this is a superset of the JDK's set
;; rather than a divergence. secp256k1 is likewise more than the default JDK
;; provider offers.
(def ^:private curve-nids
  {"secp256r1" 415 "prime256v1" 415 "P-256" 415 "NIST P-256" 415
   "secp384r1" 715 "P-384" 715 "NIST P-384" 715
   "secp521r1" 716 "P-521" 716 "NIST P-521" 716
   "secp256k1" 714})

(defn- curve-nid [curve]
  (or (curve-nids (str curve))
      (throw (ex-info (str "unsupported EC curve: " curve) {:curve curve}))))

(def ^:private ptr-size (ffi/sizeof :pointer))

(defn- der-out
  "Run an i2d_* encoder over obj and return the DER bytes. Called once with a
  null output pointer it reports the length, which is how the buffer gets sized
  without needing OPENSSL_free (a macro, so not callable through the FFI)."
  [i2d-fn obj]
  (let [len (i2d-fn obj ffi/null)]
    (when (<= len 0) (throw (ex-info "DER encode failed" {:len len})))
    (let [buf (ffi/alloc len) holder (ffi/alloc ptr-size)]
      (try
        (ffi/write holder :pointer 0 buf)
        (let [n (i2d-fn obj holder)]
          (when (<= n 0) (throw (ex-info "DER encode failed" {:len n})))
          (ffi/read-array buf n))
        (finally (ffi/free buf) (ffi/free holder))))))

(defn- with-der-key
  "Decode DER key bytes with a d2i_* parser, run (f pkey), free the key. d2i
  advances the pointer it is handed, hence the separate holder cell."
  [d2i-fn der f]
  (let [der (->ba der) n (alength der)
        buf (ffi/alloc (max 1 n)) holder (ffi/alloc ptr-size)]
    (try
      (ffi/write-array buf der)
      (ffi/write holder :pointer 0 buf)
      (let [pkey (d2i-fn ffi/null holder n)]
        (when (ffi/null? pkey) (throw (ex-info "not a valid DER-encoded EC key" {})))
        (try (f pkey) (finally (c-pkey-free pkey))))
      (finally (ffi/free buf) (ffi/free holder)))))

(defn generate-ec-keypair
  "Generate an EC keypair on `curve`. Returns {:public <X.509 DER> :private <PKCS#8 DER>},
  the same two encodings the JVM's getEncoded hands back."
  [curve]
  (let [eck (c-ec-new-curve (curve-nid curve))]
    (when (ffi/null? eck) (throw (ex-info (str "EC key setup failed for curve " curve) {:curve curve})))
    (try
      (when (not= 1 (c-ec-gen eck)) (throw (ex-info "EC key generation failed" {:curve curve})))
      (let [pkey (c-pkey-new)]
        (try
          (when (not= 1 (c-pkey-set-ec pkey eck)) (throw (ex-info "EC key wrap failed" {})))
          (let [p8 (c-pkey->p8 pkey)]
            (when (ffi/null? p8) (throw (ex-info "PKCS#8 conversion failed" {})))
            (try {:public (der-out c-i2d-pubkey pkey) :private (der-out c-i2d-p8 p8)}
                 (finally (c-p8-free p8))))
          (finally (c-pkey-free pkey))))
      (finally (c-ec-free eck)))))

(defn ec-sign
  "Sign `data` with a PKCS#8 DER private key, digesting with md-fn. The result is
  a DER-encoded ECDSA SEQUENCE of r and s, which is what SHA*withECDSA produces
  on the JVM."
  [md-fn priv-der data]
  (with-der-key c-d2i-privkey priv-der
    (fn [pkey]
      (let [data (->ba data) dn (alength data)
            ctx (c-md-ctx-new) dp (ffi/alloc (max 1 dn)) lenp (ffi/alloc 8)]
        (try
          (ffi/write-array dp data)
          (when (not= 1 (c-dgst-sign-init ctx ffi/null (md-fn) ffi/null pkey))
            (throw (ex-info "signature init failed" {})))
          ;; a null signature buffer asks for the maximum size rather than signing
          (ffi/write lenp :size_t 0 0)
          (when (not= 1 (c-dgst-sign ctx ffi/null lenp dp dn))
            (throw (ex-info "signature sizing failed" {})))
          (let [sigp (ffi/alloc (ffi/read lenp :size_t))]
            (try
              (when (not= 1 (c-dgst-sign ctx sigp lenp dp dn))
                (throw (ex-info "signing failed" {})))
              (ffi/read-array sigp (ffi/read lenp :size_t))
              (finally (ffi/free sigp))))
          (finally (c-md-ctx-free ctx) (ffi/free dp) (ffi/free lenp)))))))

(defn ec-verify
  "Verify a DER ECDSA signature over `data` against an X.509 DER public key."
  [md-fn pub-der data sig]
  (with-der-key c-d2i-pubkey pub-der
    (fn [pkey]
      (let [data (->ba data) sig (->ba sig) dn (alength data) sn (alength sig)
            ctx (c-md-ctx-new) dp (ffi/alloc (max 1 dn)) sp (ffi/alloc (max 1 sn))]
        (try
          (ffi/write-array dp data)
          (ffi/write-array sp sig)
          (when (not= 1 (c-dgst-verify-init ctx ffi/null (md-fn) ffi/null pkey))
            (throw (ex-info "verification init failed" {})))
          ;; a bad signature is a false, not a throw: EVP reports both the same way
          (= 1 (c-dgst-verify ctx sp sn dp dn))
          (finally (c-md-ctx-free ctx) (ffi/free dp) (ffi/free sp)))))))

;; --- algorithm name -> primitive --------------------------------------------
(defn- mac-md [algo]
  (case (str algo) ("HmacSHA512" "HMACSHA512") [c-sha512 64] ("HmacSHA384" "HMACSHA384") [c-sha384 48]
    ("HmacSHA256" "HMACSHA256") [c-sha256 32] ("HmacSHA1" "HMACSHA1") [c-sha1 20]
    (throw (ex-info (str "unsupported Mac algorithm: " algo) {:algo algo}))))
;; SHA256withECDSA and friends. The JVM spells these without separators and
;; case-insensitively in practice, so match on the upcased form.
(defn- signature-md [algo]
  (case (str/upper-case (str algo))
    "SHA512WITHECDSA" c-sha512
    "SHA384WITHECDSA" c-sha384
    "SHA256WITHECDSA" c-sha256
    "SHA224WITHECDSA" c-sha224
    "SHA1WITHECDSA"   c-sha1
    (throw (ex-info (str "unsupported Signature algorithm: " algo) {:algo algo}))))

(defn- digest-spec [algo]
  (case (str algo) ("SHA-512" "SHA512") [c-sha512 64] ("SHA-384" "SHA384") [c-sha384 48]
    ("SHA-256" "SHA256") [c-sha256 32] ("SHA-224" "SHA224") [c-sha224 28] ("SHA-1" "SHA1") [c-sha1 20]
    ("MD5") [c-md5 16]
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
    (__register-class-statics! nm {"getInstance" (fn [algo & _] (doto (tt :jolt.crypto/mac) (tput! :md (mac-md algo))))}))
  (__register-class-methods! :jolt.crypto/mac
    {"init" (fn [self key & _] (tput! self :key (->ba key)) nil)
     "doFinal" (fn [self data & _] (let [[mdf len] (tget self :md)] (hmac mdf len (tget self :key) data)))
     "getMacLength" (fn [self] (let [[_ len] (tget self :md)] len))})

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
                  (digest (tget self :md) (tget self :len) body)))
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

  ;; --- EC keys and ECDSA ----------------------------------------------------
  ;; java.security.spec: the three holders that carry a curve name or DER bytes.
  (doseq [[nm tag] [["ECGenParameterSpec" :jolt.crypto/ec-params]
                    ["java.security.spec.ECGenParameterSpec" :jolt.crypto/ec-params]]]
    (__register-class-ctor! nm (fn [curve & _] (doto (tt tag) (tput! :curve (str curve))))))
  (__register-class-methods! :jolt.crypto/ec-params {"getName" (fn [self] (tget self :curve))})

  (doseq [[nm tag] [["X509EncodedKeySpec" :jolt.crypto/x509-spec]
                    ["java.security.spec.X509EncodedKeySpec" :jolt.crypto/x509-spec]
                    ["PKCS8EncodedKeySpec" :jolt.crypto/pkcs8-spec]
                    ["java.security.spec.PKCS8EncodedKeySpec" :jolt.crypto/pkcs8-spec]]]
    (__register-class-ctor! nm (fn [der & _] (doto (tt tag) (tput! :bytes (byte-array der))))))
  (__register-class-methods! :jolt.crypto/x509-spec
    {"getEncoded" (fn [self] (tget self :bytes)) "getFormat" (fn [self] "X.509")})
  (__register-class-methods! :jolt.crypto/pkcs8-spec
    {"getEncoded" (fn [self] (tget self :bytes)) "getFormat" (fn [self] "PKCS#8")})

  ;; PublicKey / PrivateKey. getEncoded is the DER the JVM hands back, which is
  ;; what makes these keys interchangeable with a real JVM's.
  (__register-class-methods! :jolt.crypto/ec-public
    {"getEncoded" (fn [self] (tget self :bytes))
     "getAlgorithm" (fn [self] "EC")
     "getFormat" (fn [self] "X.509")})
  (__register-class-methods! :jolt.crypto/ec-private
    {"getEncoded" (fn [self] (tget self :bytes))
     "getAlgorithm" (fn [self] "EC")
     "getFormat" (fn [self] "PKCS#8")})

  ;; java.security.KeyPairGenerator. Java's is stateful: getInstance picks the
  ;; algorithm, initialize picks the curve, generateKeyPair draws a key.
  (doseq [nm ["KeyPairGenerator" "java.security.KeyPairGenerator"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (when-not (= "EC" (str/upper-case (str algo)))
                         (throw (ex-info (str "unsupported KeyPairGenerator algorithm: " algo) {:algo algo})))
                       (doto (tt :jolt.crypto/keypair-gen) (tput! :curve "secp256r1")))}))
  (__register-class-methods! :jolt.crypto/keypair-gen
    {;; initialize(AlgorithmParameterSpec) names the curve; initialize(int) gives
     ;; a key size in bits, which for EC selects the P-curve of that size. The
     ;; curve is resolved here rather than at generate time because that is where
     ;; the JDK rejects an unknown one.
     "initialize" (fn [self spec & _]
                    (let [curve (if (and (table? spec) (= :jolt.crypto/ec-params (tget spec :jolt/type)))
                                  (tget spec :curve)
                                  (case (long spec)
                                    256 "secp256r1" 384 "secp384r1" 521 "secp521r1"
                                    (throw (ex-info (str "unsupported EC key size: " spec) {:keysize spec}))))]
                      (curve-nid curve)
                      (tput! self :curve curve))
                    nil)
     "generateKeyPair" (fn [self] (let [{:keys [public private]} (generate-ec-keypair (tget self :curve))]
                                    (doto (tt :jolt.crypto/keypair)
                                      (tput! :public public) (tput! :private private))))
     ;; genKeyPair is the older spelling of the same method
     "genKeyPair" (fn [self] (let [{:keys [public private]} (generate-ec-keypair (tget self :curve))]
                               (doto (tt :jolt.crypto/keypair)
                                 (tput! :public public) (tput! :private private))))})
  (__register-class-methods! :jolt.crypto/keypair
    {"getPublic" (fn [self] (doto (tt :jolt.crypto/ec-public) (tput! :bytes (tget self :public))))
     "getPrivate" (fn [self] (doto (tt :jolt.crypto/ec-private) (tput! :bytes (tget self :private))))})

  ;; java.security.KeyFactory — DER key spec in, key object out. Decoding once
  ;; here means malformed bytes are rejected at generate* time, as on the JVM,
  ;; rather than surfacing later as a mysterious verification failure.
  (doseq [nm ["KeyFactory" "java.security.KeyFactory"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (when-not (= "EC" (str/upper-case (str algo)))
                         (throw (ex-info (str "unsupported KeyFactory algorithm: " algo) {:algo algo})))
                       (tt :jolt.crypto/key-factory))}))
  (__register-class-methods! :jolt.crypto/key-factory
    {"generatePublic" (fn [self spec]
                        (let [der (->ba spec)]
                          (with-der-key c-d2i-pubkey der (fn [_] nil))
                          (doto (tt :jolt.crypto/ec-public) (tput! :bytes der))))
     "generatePrivate" (fn [self spec]
                         (let [der (->ba spec)]
                           (with-der-key c-d2i-privkey der (fn [_] nil))
                           (doto (tt :jolt.crypto/ec-private) (tput! :bytes der))))})

  ;; java.security.Signature — stateful like Cipher: init picks key and
  ;; direction, update accumulates, sign/verify consume and reset.
  (doseq [nm ["Signature" "java.security.Signature"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _] (doto (tt :jolt.crypto/signature)
                                      (tput! :md (signature-md algo))
                                      (tput! :algo (str algo))
                                      (tput! :acc [])))}))
  (__register-class-methods! :jolt.crypto/signature
    {"initSign" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "initVerify" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "update" (fn [self data & _] (tput! self :acc (into (tget self :acc) (seq (->ba data)))) nil)
     "sign" (fn [self & _]
              (let [body (byte-array (tget self :acc))]
                (tput! self :acc [])
                (ec-sign (tget self :md) (tget self :key) body)))
     "verify" (fn [self sig & _]
                (let [body (byte-array (tget self :acc))]
                  (tput! self :acc [])
                  (ec-verify (tget self :md) (tget self :key) body sig)))
     "getAlgorithm" (fn [self] (tget self :algo))})
  nil)

(install!)
