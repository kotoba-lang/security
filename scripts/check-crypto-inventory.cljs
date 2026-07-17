#!/usr/bin/env nbb
;; --- nbb shims (auto, ADR-2607173000) ---------------------------------
(def ^:private __fs (js/require "node:fs"))
(def ^:private __path (js/require "node:path"))
(def ^:private __cp (js/require "node:child_process"))
(def ^:private __os (js/require "node:os"))
(def ^:private __crypto (js/require "node:crypto"))
(defn- __sh [& args]
  (let [opts (when (map? (last args)) (last args))
        cmd (if opts (butlast args) args)
        r (.spawnSync __cp (first cmd) (to-array (rest cmd))
                      (clj->js (merge {:encoding "utf8"} (when opts {:cwd (:dir opts)}))))]
    {:exit (or (.-status r) 1) :out (or (.-stdout r) "") :err (or (.-stderr r) "")}))
(defn- __shell [& args]
  (let [opts (when (map? (first args)) (first args))
        cmd (if opts (rest args) args)
        r (.spawnSync __cp (first cmd) (to-array (rest cmd))
                      (clj->js (merge {:stdio "inherit" :encoding "utf8"}
                                      (when opts {:cwd (:dir opts)}))))]
    (when-not (zero? (or (.-status r) 1))
      (throw (js/Error. (str "shell failed: " (pr-str cmd)))))
    {:exit (or (.-status r) 0) :out "" :err ""}))
;; -----------------------------------------------------------------------
;; Crypto inventory gate (kotoba-lang/kotoba#264).
;;
;; Usage (run from the repo root):
;;   nbb scripts/check-crypto-inventory.nbb [crypto-policy.edn crypto-inventory.edn]
;;
;; Validates registers/crypto-inventory.edn against policy/crypto-policy.edn:
;; structure is always enforced; FIPS strictness (no :crypto/fips-status
;; :not-claimed entries) only when the policy mode is :fips-required.
;; Also structurally validates conformance/crypto/vectors/*.edn hybrid KEM
;; vector files (fields, kem list, hex shapes) — BC-free; cryptographic
;; recomputation runs under `clojure -M:vectors:vectors-test`.
;; Exit 1 on failure.
(require ']
         '[clojure.edn :as edn]
         ')

(def script-dir (-> *file* __path.resolve .getAbsoluteFile .getParentFile))
(def root (__path.dirname script-dir))
))

(require '[kotoba.security.crypto-policy :as policy]
         '[kotoba.security.hybrid-vectors :as hv])

(def args (vec *command-line-args*))

(def policy-file
  (if (first args)
    (__path.resolve (first args))
    (__path.resolve root "policy/crypto-policy.edn")))

(def inventory-file
  (if (second args)
    (__path.resolve (second args))
    (__path.resolve root "registers/crypto-inventory.edn")))

;; policy/crypto-policy.edn and registers/crypto-inventory.edn were
;; datomic/datascript-ized by edn-datomize.nbb (wrap-map-keep-ns): top level is
;; now `[{:db/id -1 ...}]` tx-data. Already-namespaced keys (:register/type,
;; :kotoba.security/crypto-policy-version, ...) are unchanged; bare keys
;; (:mode, :hybrid-epoch-floor, :modes, :allowed-providers, :inventory) were
;; promoted to the transform's ns ("policy.crypto-policy" /
;; "registers.crypto-inventory"). This reconstitutes the original raw map so
;; every existing call site below keeps working unchanged. conformance/crypto
;; vectors/*.edn is untouched by the transform (its top level is a vector of
;; vectors, not a map), so its reads stay plain.
(defn- unblob [v]
  (if (string? v)
    (try (let [parsed (edn/read-string v)] (if (coll? parsed) parsed v))
         (catch Exception _ v))
    v))

(defn- tx-data? [content]
  (and (vector? content) (seq content) (map? (first content)) (contains? (first content) :db/id)))

(defn- reconstitute-entity [ns-name tx-data]
  (into {} (map (fn [[k v]]
                  [(if (= ns-name (namespace k)) (keyword (name k)) k)
                   (unblob v)]))
        (dissoc (first tx-data) :db/id)))

(defn read-edn
  ([f] (read-edn f nil))
  ([f ns-name]
   (let [content (edn/read-string (slurp f))]
     (if (and ns-name (tx-data? content))
       (reconstitute-entity ns-name content)
       content))))

(let [crypto-policy (read-edn policy-file "policy.crypto-policy")
      inventory (read-edn inventory-file "registers.crypto-inventory")
      result (policy/check-inventory crypto-policy inventory)]
  (if (:valid? result)
    (do (doseq [entry (:inventory inventory)]
          (println "ok" (:crypto/use entry)
                   (str "pq=" (:crypto/pq-status entry))
                   (str "fips=" (:crypto/fips-status entry))))
        (println "ok crypto-inventory" (str "mode=" (:mode crypto-policy))))
    (do (println "FAIL" (:message result) (pr-str (:data result)))
        (.exit js/process 1))))

;; Hybrid KEM vector files (docs/hybrid-envelope-vectors.md): structural gate.
(let [vectors-dir (__path.resolve root "conformance/crypto/vectors")
      vector-files (->> (mapv #(__path.join vectors-dir %) (seq (__fs.readdirSync vectors-dir)))
                        (filter #(.endsWith (.getName ^java.io.File %) ".edn"))
                        (sort-by #(.getName ^java.io.File %)))]
  (when (empty? vector-files)
    (println "FAIL hybrid vector files required in conformance/crypto/vectors/")
    (.exit js/process 1))
  (doseq [f vector-files]
    (let [vectors (read-edn f)
          result (hv/check-vector-file vectors)]
      (if (:valid? result)
        (println "ok" (.getName ^java.io.File f)
                 (str "vectors=" (count vectors))
                 (str "kem=" (pr-str hv/hybrid-kem)))
        (do (println "FAIL" (.getName ^java.io.File f)
                     (:message result) (pr-str (:data result)))
            (.exit js/process 1))))))
