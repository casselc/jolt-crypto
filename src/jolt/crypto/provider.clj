(ns jolt.crypto.provider
  "Select and validate the native implementation behind jolt-crypto.

  The handler map is intentionally small. Portable Java-compatible shims above
  this namespace depend only on four operations with stable byte-array
  semantics; platform code owns library loading, handles, ABI calls, and native
  errors."
  (:require [jolt.crypto.provider.cng :as cng]
            [jolt.crypto.provider.openssl :as openssl]))

(def ^:private required-operations
  [:aes-cbc :hmac :digest :random-bytes])

(defn- validate-provider [provider]
  (when-not (keyword? (:name provider))
    (throw
     (ex-info "crypto provider must have a keyword :name"
              {:type ::invalid-provider
               :provider provider})))
  (doseq [operation required-operations]
    (when-not (fn? (get provider operation))
      (throw
       (ex-info (str "crypto provider is missing callable " operation)
                {:type ::invalid-provider
                 :provider (:name provider)
                 :operation operation}))))
  provider)

(defn- select-provider []
  (let [target (jolt.host/target)
        os (:os target)
        selected
        (cond
          (= :windows os)
          (when (cng/available?) cng/provider)

          (contains? #{:linux :darwin} os)
          (when (openssl/available?) openssl/provider)

          :else nil)]
    (when-not selected
      (throw
       (ex-info (str "no native crypto provider for " os)
                {:type ::provider-unavailable
                 :target target
                 :expected (if (= :windows os) :cng :openssl)})))
    (validate-provider selected)))

(def ^:private active-provider (select-provider))

(defn info
  "Stable diagnostic information; never exposes native handles."
  []
  {:name (:name active-provider)
   :target (jolt.host/target)
   :operations (set required-operations)})

(defn aes-cbc [encrypt? key iv data]
  ((:aes-cbc active-provider) encrypt? key iv data))

(defn hmac [algorithm key data]
  ((:hmac active-provider) algorithm key data))

(defn digest [algorithm data]
  ((:digest active-provider) algorithm data))

(defn random-bytes [length]
  ((:random-bytes active-provider) length))
