#!/usr/bin/env bb
;; Crypto inventory gate (kotoba-lang/kotoba#264).
;;
;; Usage (run from the repo root):
;;   bb scripts/check-crypto-inventory.bb [crypto-policy.edn crypto-inventory.edn]
;;
;; Validates registers/crypto-inventory.edn against policy/crypto-policy.edn:
;; structure is always enforced; FIPS strictness (no :crypto/fips-status
;; :not-claimed entries) only when the policy mode is :fips-required.
;; Also structurally validates conformance/crypto/vectors/*.edn hybrid KEM
;; vector files (fields, kem list, hex shapes) — BC-free; cryptographic
;; recomputation runs under `clojure -M:vectors:vectors-test`.
;; Exit 1 on failure.
(require '[babashka.classpath :refer [add-classpath]]
         '[clojure.edn :as edn]
         '[clojure.java.io :as io])

(def script-dir (-> *file* io/file .getAbsoluteFile .getParentFile))
(def root (.getParentFile script-dir))
(add-classpath (str (io/file root "src")))

(require '[kotoba.security.crypto-policy :as policy]
         '[kotoba.security.hybrid-vectors :as hv])

(def args (vec *command-line-args*))

(def policy-file
  (if (first args)
    (io/file (first args))
    (io/file root "policy/crypto-policy.edn")))

(def inventory-file
  (if (second args)
    (io/file (second args))
    (io/file root "registers/crypto-inventory.edn")))

(defn read-edn [f]
  (edn/read-string (slurp f)))

(let [crypto-policy (read-edn policy-file)
      inventory (read-edn inventory-file)
      result (policy/check-inventory crypto-policy inventory)]
  (if (:valid? result)
    (do (doseq [entry (:inventory inventory)]
          (println "ok" (:crypto/use entry)
                   (str "pq=" (:crypto/pq-status entry))
                   (str "fips=" (:crypto/fips-status entry))))
        (println "ok crypto-inventory" (str "mode=" (:mode crypto-policy))))
    (do (println "FAIL" (:message result) (pr-str (:data result)))
        (System/exit 1))))

;; Hybrid KEM vector files (docs/hybrid-envelope-vectors.md): structural gate.
(let [vectors-dir (io/file root "conformance/crypto/vectors")
      vector-files (->> (.listFiles vectors-dir)
                        (filter #(.endsWith (.getName ^java.io.File %) ".edn"))
                        (sort-by #(.getName ^java.io.File %)))]
  (when (empty? vector-files)
    (println "FAIL hybrid vector files required in conformance/crypto/vectors/")
    (System/exit 1))
  (doseq [f vector-files]
    (let [vectors (read-edn f)
          result (hv/check-vector-file vectors)]
      (if (:valid? result)
        (println "ok" (.getName ^java.io.File f)
                 (str "vectors=" (count vectors))
                 (str "kem=" (pr-str hv/hybrid-kem)))
        (do (println "FAIL" (.getName ^java.io.File f)
                     (:message result) (pr-str (:data result)))
            (System/exit 1))))))
