(ns kotoba.security.release-gate-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kotoba.security.release-gate :as gate]))

;; conformance/release/{negative,positive}/*.edn, registers/evidence-index.edn
;; and registers/exception-register.edn were datomic/datascript-ized by
;; edn-datomize.bb (wrap-map-keep-ns): top level is now `[{:db/id -1 ...}]`
;; tx-data. Already-namespaced keys (:case/id, :register/type, ...) are
;; unchanged; bare keys (:now, :evidence-index, :exception-register,
;; :evidence, :exceptions) were promoted to the transform's directory-derived
;; namespace (e.g. "conformance.release.positive", "registers.evidence-index").
;; This reconstitutes the original raw map so every existing assertion below
;; keeps working unchanged.
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

(defn read-tx-edn
  "Reads an EDN file, reconstituting datomic/datascript tx-data back into its
  original raw map via `ns-name` (falls back to the parsed content unchanged
  if the file isn't tx-data)."
  [f ns-name]
  (let [content (edn/read-string (slurp f))]
    (if (tx-data? content)
      (reconstitute-entity ns-name content)
      content)))

(defn fixture-cases
  [dir]
  (->> (.listFiles (io/file dir))
       (filter #(str/ends-with? (.getName %) ".edn"))
       (sort-by #(.getName %))
       (map #(read-tx-edn % (str/replace dir "/" ".")))))

(defn evaluate-case
  [tc]
  (gate/evaluate-release {:evidence-index (:evidence-index tc)
                          :exception-register (:exception-register tc)
                          :now (:now tc)}))

(deftest positive-fixtures-pass
  (let [cases (fixture-cases "conformance/release/positive")]
    (is (seq cases))
    (doseq [tc cases]
      (let [result (evaluate-case tc)]
        (is (:kotoba.release/ok? result)
            (str (:case/id tc) " -> " (pr-str result)))))))

(deftest negative-fixtures-fail
  (let [cases (fixture-cases "conformance/release/negative")]
    (is (seq cases))
    (doseq [tc cases]
      (let [result (evaluate-case tc)]
        (is (not (:kotoba.release/ok? result))
            (str (:case/id tc) " should be rejected"))))))

(deftest complete-packet-has-no-missing-claims
  (let [tc (read-tx-edn (io/file "conformance/release/positive/complete-packet.edn")
                        "conformance.release.positive")
        result (evaluate-case tc)]
    (is (= [] (:kotoba.release/missing result)))
    (is (= [] (:kotoba.release/excepted result)))
    (is (= [] (:kotoba.release/problems result)))))

(deftest valid-exception-covers-sbom
  (let [tc (read-tx-edn (io/file "conformance/release/positive/valid-exception.edn")
                        "conformance.release.positive")
        result (evaluate-case tc)]
    (is (:kotoba.release/ok? result))
    (is (= [:sbom] (mapv :claim (:kotoba.release/excepted result))))
    (is (= "EX-0001" (:exception/id (first (:kotoba.release/excepted result)))))))

(deftest missing-sbom-is-reported
  (let [tc (read-tx-edn (io/file "conformance/release/negative/missing-sbom.edn")
                        "conformance.release.negative")
        result (evaluate-case tc)]
    (is (= [:sbom] (:kotoba.release/missing result)))))

(deftest expired-exception-does-not-excuse
  (let [tc (read-tx-edn (io/file "conformance/release/negative/expired-exception.edn")
                        "conformance.release.negative")
        result (evaluate-case tc)]
    (is (= [:sbom] (:kotoba.release/missing result)))
    (is (= [] (:kotoba.release/excepted result)))))

(deftest malformed-exception-never-excuses
  (testing "exception without owner"
    (let [tc (read-tx-edn (io/file "conformance/release/negative/exception-without-owner.edn")
                          "conformance.release.negative")
          result (evaluate-case tc)]
      (is (= [:sbom] (:kotoba.release/missing result)))
      (is (= [] (:kotoba.release/excepted result)))
      (is (some #(= :malformed-exception (:problem %))
                (:kotoba.release/problems result)))))
  (testing "exception without expires"
    (let [result (gate/evaluate-release
                  {:evidence-index {:register/type :kotoba.security/evidence-index
                                    :register/version 1
                                    :evidence []}
                   :exception-register {:register/type :kotoba.security/exception-register
                                        :register/version 1
                                        :exceptions [{:exception/id "EX-X"
                                                      :exception/claim :sbom
                                                      :exception/owner "security-owner"
                                                      :exception/reason "no expiry"}]}
                   :now "2026-07-02"})]
      (is (some #{:sbom} (:kotoba.release/missing result)))
      (is (= [] (:kotoba.release/excepted result))))))

(deftest failed-evidence-does-not-satisfy-claim
  (let [tc (read-tx-edn (io/file "conformance/release/negative/failed-evidence-result.edn")
                        "conformance.release.negative")
        result (evaluate-case tc)]
    (is (= [:sbom] (:kotoba.release/missing result)))))

(deftest register-type-and-version-are-validated
  (let [result (gate/evaluate-release
                {:evidence-index {:register/type :wrong/type
                                  :register/version 2
                                  :evidence []}
                 :exception-register {:register/type :kotoba.security/exception-register
                                      :register/version 1
                                      :exceptions []}
                 :now "2026-07-02"})]
    (is (not (:kotoba.release/ok? result)))
    (is (some #(= :register-type-mismatch (:problem %))
              (:kotoba.release/problems result)))
    (is (some #(= :register-version-unsupported (:problem %))
              (:kotoba.release/problems result)))))

(deftest real-registers-are-structurally-valid
  (let [evidence-index (read-tx-edn (io/file "registers/evidence-index.edn") "registers.evidence-index")
        exception-register (read-tx-edn (io/file "registers/exception-register.edn") "registers.exception-register")
        result (gate/evaluate-release {:evidence-index evidence-index
                                       :exception-register exception-register
                                       :now "2026-07-02"})]
    (is (= [] (:kotoba.release/problems result)))))
