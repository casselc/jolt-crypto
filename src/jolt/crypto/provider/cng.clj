(ns jolt.crypto.provider.cng
  "Windows CNG implementation of jolt-crypto's native primitive provider.

  All algorithms use Windows 10+ pseudo-handles, so the implementation needs no
  UTF-16 algorithm identifiers and owns no provider handles."
  (:require [jolt.ffi :as ffi]))

(ffi/defcfn c-hash "BCryptHash"
  [:pointer :pointer :uint :pointer :uint :pointer :uint] :int)
(ffi/defcfn c-generate-random "BCryptGenRandom"
  [:pointer :pointer :uint :uint] :int)
(ffi/defcfn c-generate-symmetric-key "BCryptGenerateSymmetricKey"
  [:pointer :pointer :pointer :uint :pointer :uint :uint] :int)
(ffi/defcfn c-destroy-key "BCryptDestroyKey"
  [:pointer] :int)
(ffi/defcfn c-encrypt "BCryptEncrypt"
  [:pointer :pointer :uint :pointer :pointer :uint
   :pointer :uint :pointer :uint] :int)
(ffi/defcfn c-decrypt "BCryptDecrypt"
  [:pointer :pointer :uint :pointer :pointer :uint
   :pointer :uint :pointer :uint] :int)

;; Windows 10+ CNG algorithm pseudo-handles from bcrypt.h.
(def ^:private aes-cbc-handle 0x1a1)
(def ^:private md5-handle 0x21)
(def ^:private sha1-handle 0x31)
(def ^:private sha256-handle 0x41)
(def ^:private hmac-sha1-handle 0xa1)
(def ^:private hmac-sha256-handle 0xb1)

(def ^:private block-padding 0x1)
(def ^:private use-system-preferred-rng 0x2)

(defn available?
  "Load Windows' built-in CNG router."
  []
  (and
   (= :windows (:os (jolt.host/target)))
   (try
     (ffi/load-library "bcrypt.dll")
     true
     (catch Throwable _ false))))

(defn- check-status [operation status]
  (when-not (zero? status)
    (throw
     (ex-info (str operation " failed with NTSTATUS " status)
              {:type ::native-failure
               :operation operation
               :status status}))))

(defn- with-input-pointer
  "Borrow non-empty input for the dynamic extent of `f`; keep a valid owned
  pointer for empty inputs so CNG never has to interpret NULL independently of
  its zero length."
  [data f]
  (let [length (alength data)]
    (if (zero? length)
      (let [pointer (ffi/alloc 1)]
        (try
          (f pointer 0)
          (finally (ffi/free pointer))))
      (ffi/with-byte-array-pointer data 0 length f))))

(defn- digest-handle [algorithm]
  (case algorithm
    :md5 md5-handle
    :sha1 sha1-handle
    :sha256 sha256-handle
    (throw
     (ex-info (str "unsupported CNG digest " algorithm)
              {:type ::unsupported-digest
               :algorithm algorithm}))))

(defn- hmac-handle [algorithm]
  (case algorithm
    :sha1 hmac-sha1-handle
    :sha256 hmac-sha256-handle
    (throw
     (ex-info (str "unsupported CNG HMAC digest " algorithm)
              {:type ::unsupported-hmac
               :algorithm algorithm}))))

(defn- digest-length [algorithm]
  (case algorithm
    :md5 16
    :sha1 20
    :sha256 32
    (throw
     (ex-info (str "unsupported CNG digest " algorithm)
              {:type ::unsupported-digest
               :algorithm algorithm}))))

(defn- with-key [key f]
  (let [key-length (alength key)]
    (when-not (contains? #{16 24 32} key-length)
      (throw
       (ex-info (str "AES key must be 16/24/32 bytes, got " key-length)
                {:type ::invalid-key-length
                 :key-length key-length})))
    (with-input-pointer
      key
      (fn [key-pointer _]
        (let [handle-pointer (ffi/alloc (ffi/sizeof :pointer))]
          (try
            (check-status
             "BCryptGenerateSymmetricKey"
             (c-generate-symmetric-key aes-cbc-handle handle-pointer
                                       ffi/null 0
                                       key-pointer key-length
                                       0))
            (let [handle (ffi/read handle-pointer :pointer)]
              (when (ffi/null? handle)
                (throw
                 (ex-info "BCryptGenerateSymmetricKey returned a NULL handle"
                          {:type ::null-key-handle})))
              (try
                (f handle)
                (finally
                  (check-status "BCryptDestroyKey"
                                (c-destroy-key handle)))))
            (finally (ffi/free handle-pointer))))))))

(defn aes-cbc
  "AES-CBC with CNG BCRYPT_BLOCK_PADDING (PKCS#7 semantics)."
  [encrypt? key iv data]
  (let [iv-length (alength iv)
        input-length (alength data)]
    (when-not (= 16 iv-length)
      (throw
       (ex-info (str "AES-CBC IV must be 16 bytes, got " iv-length)
                {:type ::invalid-iv-length
                 :iv-length iv-length})))
    (with-key
      key
      (fn [key-handle]
        (with-input-pointer
          data
          (fn [input-pointer _]
            (let [iv-pointer (ffi/alloc iv-length)
                  output-capacity (+ input-length 16)
                  output (ffi/alloc output-capacity)
                  output-length (ffi/alloc 4)
                  operation (if encrypt? "BCryptEncrypt" "BCryptDecrypt")
                  cipher (if encrypt? c-encrypt c-decrypt)]
              (try
                ;; BCryptEncrypt/Decrypt mutate their IV buffer. Copying here is
                ;; part of the provider contract: callers retain their IV.
                (ffi/write-array iv-pointer iv)
                (check-status
                 operation
                 (cipher key-handle
                         input-pointer input-length
                         ffi/null
                         iv-pointer iv-length
                         output output-capacity
                         output-length
                         block-padding))
                (let [actual (ffi/read output-length :uint)]
                  (when (> actual output-capacity)
                    (throw
                     (ex-info "CNG returned output beyond the provided buffer"
                              {:type ::invalid-output-length
                               :operation operation
                               :capacity output-capacity
                               :actual actual})))
                  (ffi/read-array output actual))
                (finally
                  (ffi/free output-length)
                  (ffi/free output)
                  (ffi/free iv-pointer))))))))))

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
                (check-status
                 "BCryptHash(HMAC)"
                 (c-hash (hmac-handle algorithm)
                         key-pointer key-length
                         data-pointer data-length
                         output output-size))
                (ffi/read-array output output-size)
                (finally (ffi/free output))))))))))

(defn digest [algorithm data]
  (let [output-size (digest-length algorithm)]
    (with-input-pointer
      data
      (fn [data-pointer data-length]
        (let [output (ffi/alloc output-size)]
          (try
            (check-status
             "BCryptHash"
             (c-hash (digest-handle algorithm)
                     ffi/null 0
                     data-pointer data-length
                     output output-size))
            (ffi/read-array output output-size)
            (finally (ffi/free output))))))))

(defn random-bytes [length]
  (when (neg? length)
    (throw
     (ex-info "random byte count must be non-negative"
              {:type ::invalid-random-length
               :length length})))
  (let [output (ffi/alloc (max 1 length))]
    (try
      (check-status
       "BCryptGenRandom"
       (c-generate-random ffi/null output length use-system-preferred-rng))
      (ffi/read-array output length)
      (finally (ffi/free output)))))

(def provider
  {:name :cng
   :aes-cbc aes-cbc
   :hmac hmac
   :digest digest
   :random-bytes random-bytes})
