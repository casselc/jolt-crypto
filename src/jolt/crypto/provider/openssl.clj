(ns jolt.crypto.provider.openssl
  "OpenSSL implementation of jolt-crypto's native primitive provider."
  (:require [jolt.ffi :as ffi]))

(ffi/defcfn c-rand     "RAND_bytes"          [:pointer :int] :int)
(ffi/defcfn c-aes128   "EVP_aes_128_cbc"     [] :pointer)
(ffi/defcfn c-aes192   "EVP_aes_192_cbc"     [] :pointer)
(ffi/defcfn c-aes256   "EVP_aes_256_cbc"     [] :pointer)
(ffi/defcfn c-md5      "EVP_md5"             [] :pointer)
(ffi/defcfn c-sha1     "EVP_sha1"            [] :pointer)
(ffi/defcfn c-sha256   "EVP_sha256"          [] :pointer)
(ffi/defcfn c-ctx-new  "EVP_CIPHER_CTX_new"  [] :pointer)
(ffi/defcfn c-ctx-free "EVP_CIPHER_CTX_free" [:pointer] :void)
(ffi/defcfn c-enc-init "EVP_EncryptInit_ex"
  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-enc-upd  "EVP_EncryptUpdate"
  [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-enc-fin  "EVP_EncryptFinal_ex"
  [:pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-init "EVP_DecryptInit_ex"
  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-upd  "EVP_DecryptUpdate"
  [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-dec-fin  "EVP_DecryptFinal_ex"
  [:pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac "HMAC"
  [:pointer :pointer :int :pointer :size_t :pointer :pointer] :pointer)
(ffi/defcfn c-digest "EVP_Digest"
  [:pointer :size_t :pointer :pointer :pointer :pointer] :int)

(defn- candidates []
  (case (:os (jolt.host/target))
    :darwin
    ["/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib"
     "/opt/homebrew/lib/libcrypto.dylib"
     "/usr/local/opt/openssl@3/lib/libcrypto.dylib"
     "/usr/lib/libcrypto.dylib"
     "libcrypto.dylib"]

    :linux
    ["libcrypto.so.3" "libcrypto.so.1.1" "libcrypto.so"]

    []))

(defn available?
  "Load the first OpenSSL libcrypto candidate for this target."
  []
  (boolean
   (some (fn [candidate]
           (try
             (ffi/load-library candidate)
             true
             (catch Throwable _ false)))
         (candidates))))

(defn- with-input-pointer
  "Borrow a non-empty array for one native call chain. Use owned one-byte
  storage for an empty value so APIs that reject NULL independently of length
  still receive a valid pointer."
  [data f]
  (let [length (alength data)]
    (if (zero? length)
      (let [pointer (ffi/alloc 1)]
        (try
          (f pointer 0)
          (finally (ffi/free pointer))))
      (ffi/with-byte-array-pointer data 0 length f))))

(defn- cipher-for [key-length]
  (case key-length
    16 (c-aes128)
    24 (c-aes192)
    32 (c-aes256)
    (throw
     (ex-info (str "AES key must be 16/24/32 bytes, got " key-length)
              {:type ::invalid-key-length
               :key-length key-length}))))

(defn aes-cbc
  "AES-CBC with OpenSSL's default PKCS#7 padding."
  [encrypt? key iv data]
  (let [key-length (alength key)
        iv-length (alength iv)
        input-length (alength data)]
    (when-not (= 16 iv-length)
      (throw
       (ex-info (str "AES-CBC IV must be 16 bytes, got " iv-length)
                {:type ::invalid-iv-length
                 :iv-length iv-length})))
    (with-input-pointer
      key
      (fn [key-pointer _]
        (with-input-pointer
          iv
          (fn [iv-pointer _]
            (with-input-pointer
              data
              (fn [input-pointer _]
                (let [context (c-ctx-new)
                      cipher (cipher-for key-length)
                      output-capacity (+ input-length 32)
                      output (ffi/alloc output-capacity)
                      output-length (ffi/alloc 4)
                      [initialize update finish]
                      (if encrypt?
                        [c-enc-init c-enc-upd c-enc-fin]
                        [c-dec-init c-dec-upd c-dec-fin])]
                  (when (ffi/null? context)
                    (ffi/free output)
                    (ffi/free output-length)
                    (throw
                     (ex-info "EVP_CIPHER_CTX_new returned NULL"
                              {:type ::cipher-context-failed})))
                  (try
                    (when-not (= 1 (initialize context cipher ffi/null
                                              key-pointer iv-pointer))
                      (throw
                       (ex-info "OpenSSL cipher initialization failed"
                                {:type ::cipher-initialization-failed})))
                    (when-not (= 1 (update context output output-length
                                          input-pointer input-length))
                      (throw
                       (ex-info "OpenSSL cipher update failed"
                                {:type ::cipher-update-failed})))
                    (let [first-length (ffi/read output-length :int)]
                      (when-not (= 1 (finish context
                                           (+ output first-length)
                                           output-length))
                        (throw
                         (ex-info
                          (if encrypt?
                            "OpenSSL cipher finalization failed"
                            "bad padding or wrong AES key")
                          {:type ::cipher-finalization-failed})))
                      (ffi/read-array
                       output
                       (+ first-length (ffi/read output-length :int))))
                    (finally
                      (c-ctx-free context)
                      (ffi/free output)
                      (ffi/free output-length))))))))))))

(defn- digest-function [algorithm]
  (case algorithm
    :md5 (c-md5)
    :sha1 (c-sha1)
    :sha256 (c-sha256)
    (throw
     (ex-info (str "unsupported OpenSSL digest " algorithm)
              {:type ::unsupported-digest
               :algorithm algorithm}))))

(defn- digest-length [algorithm]
  (case algorithm
    :md5 16
    :sha1 20
    :sha256 32
    (throw
     (ex-info (str "unsupported OpenSSL digest " algorithm)
              {:type ::unsupported-digest
               :algorithm algorithm}))))

(defn hmac [algorithm key data]
  (let [output-size (digest-length algorithm)]
    (with-input-pointer
      key
      (fn [key-pointer key-length]
        (with-input-pointer
          data
          (fn [data-pointer data-length]
            (let [output (ffi/alloc output-size)]
              (try
                (when
                  (ffi/null?
                   (c-hmac (digest-function algorithm)
                           key-pointer key-length
                           data-pointer data-length
                           output ffi/null))
                  (throw
                   (ex-info "OpenSSL HMAC returned NULL"
                            {:type ::hmac-failed
                             :algorithm algorithm})))
                (ffi/read-array output output-size)
                (finally (ffi/free output))))))))))

(defn digest [algorithm data]
  (let [output-size (digest-length algorithm)]
    (with-input-pointer
      data
      (fn [data-pointer data-length]
        (let [output (ffi/alloc output-size)
              actual-length (ffi/alloc 4)]
          (try
            (when-not
              (= 1 (c-digest data-pointer data-length output actual-length
                             (digest-function algorithm) ffi/null))
              (throw
               (ex-info "OpenSSL digest failed"
                        {:type ::digest-failed
                         :algorithm algorithm})))
            (when-not (= output-size (ffi/read actual-length :uint))
              (throw
               (ex-info "OpenSSL returned an unexpected digest length"
                        {:type ::invalid-digest-length
                         :algorithm algorithm
                         :expected output-size
                         :actual (ffi/read actual-length :uint)})))
            (ffi/read-array output output-size)
            (finally
              (ffi/free actual-length)
              (ffi/free output))))))))

(defn random-bytes [length]
  (when (neg? length)
    (throw
     (ex-info "random byte count must be non-negative"
              {:type ::invalid-random-length
               :length length})))
  (let [output (ffi/alloc (max 1 length))]
    (try
      (when-not (= 1 (c-rand output length))
        (throw
         (ex-info "OpenSSL RAND_bytes failed"
                  {:type ::random-failed
                   :length length})))
      (ffi/read-array output length)
      (finally (ffi/free output)))))

(def provider
  {:name :openssl
   :aes-cbc aes-cbc
   :hmac hmac
   :digest digest
   :random-bytes random-bytes})
