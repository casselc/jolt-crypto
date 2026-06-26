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

  libcrypto/libssl are declared in deps.edn :jolt/native and loaded before this
  namespace; an app that also pulls http-client shares the one loaded copy."
  (:require [jolt.ffi :as ffi]))

;; --- OpenSSL (libcrypto) bindings -------------------------------------------
(ffi/defcfn c-rand     "RAND_bytes"          [:pointer :int] :int)
(ffi/defcfn c-aes128   "EVP_aes_128_cbc"     [] :pointer)
(ffi/defcfn c-aes192   "EVP_aes_192_cbc"     [] :pointer)
(ffi/defcfn c-aes256   "EVP_aes_256_cbc"     [] :pointer)
(ffi/defcfn c-md5      "EVP_md5"             [] :pointer)
(ffi/defcfn c-sha1     "EVP_sha1"            [] :pointer)
(ffi/defcfn c-sha256   "EVP_sha256"          [] :pointer)
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

;; --- helpers ----------------------------------------------------------------
(defn- tt [tag] (jolt.host/tagged-table tag))
(defn- tget [t k] (jolt.host/ref-get t k))
(defn- tput! [t k v] (jolt.host/ref-put! t k v))
(defn- table? [x] (jolt.host/table? x))

;; binary bytes only — these objects never carry text, so coerce through
;; byte-array (a seq/byte-array round-trips; never the UTF-8 read/write-bytes).
(defn- ->ba [x]
  (cond
    (and (table? x) (#{:jolt.crypto/key :jolt.crypto/iv} (tget x :jolt/type))) (tget x :bytes)
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
(defn hmac [md-fn key data]
  (let [key (->ba key) data (->ba data) kl (alength key) dl (alength data)]
    (with-ptrs [key data]
      (fn [kp dp]
        (let [mdp (ffi/alloc 64)]
          (try (c-hmac (md-fn) kp kl dp dl mdp ffi/null) (ffi/read-array mdp 32)
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

;; --- algorithm name -> primitive --------------------------------------------
(defn- mac-md [algo]
  (case (str algo) ("HmacSHA256" "HMACSHA256") c-sha256 ("HmacSHA1" "HMACSHA1") c-sha1
    (throw (ex-info (str "unsupported Mac algorithm: " algo) {:algo algo}))))
(defn- digest-spec [algo]
  (case (str algo) ("SHA-256" "SHA256") [c-sha256 32] ("SHA-1" "SHA1") [c-sha1 20]
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
     "doFinal" (fn [self data & _] (hmac (tget self :md) (tget self :key) data))
     "getMacLength" (fn [self] 32)})

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
  nil)

(install!)
