#!/usr/bin/env bb
;; Crypto inventory gate (kotoba-lang/kotoba#264).
;;
;; Usage (run from the repo root):
;;   bb scripts/check-crypto-inventory.bb [crypto-policy.edn crypto-inventory.edn]
;;
;; Validates registers/crypto-inventory.edn against policy/crypto-policy.edn:
;; structure is always enforced; FIPS strictness (no :crypto/fips-status
;; :not-claimed entries) only when the policy mode is :fips-required.
;; Exit 1 on failure.
(require '[babashka.classpath :refer [add-classpath]]
         '[clojure.edn :as edn]
         '[clojure.java.io :as io])

(def script-dir (-> *file* io/file .getAbsoluteFile .getParentFile))
(def root (.getParentFile script-dir))
(add-classpath (str (io/file root "src")))

(require '[kotoba.security.crypto-policy :as policy])

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
