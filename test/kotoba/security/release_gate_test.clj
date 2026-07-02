(ns kotoba.security.release-gate-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kotoba.security.release-gate :as gate]))

(defn fixture-cases
  [dir]
  (->> (.listFiles (io/file dir))
       (filter #(str/ends-with? (.getName %) ".edn"))
       (sort-by #(.getName %))
       (map #(edn/read-string (slurp %)))))

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
  (let [tc (edn/read-string (slurp "conformance/release/positive/complete-packet.edn"))
        result (evaluate-case tc)]
    (is (= [] (:kotoba.release/missing result)))
    (is (= [] (:kotoba.release/excepted result)))
    (is (= [] (:kotoba.release/problems result)))))

(deftest valid-exception-covers-sbom
  (let [tc (edn/read-string (slurp "conformance/release/positive/valid-exception.edn"))
        result (evaluate-case tc)]
    (is (:kotoba.release/ok? result))
    (is (= [:sbom] (mapv :claim (:kotoba.release/excepted result))))
    (is (= "EX-0001" (:exception/id (first (:kotoba.release/excepted result)))))))

(deftest missing-sbom-is-reported
  (let [tc (edn/read-string (slurp "conformance/release/negative/missing-sbom.edn"))
        result (evaluate-case tc)]
    (is (= [:sbom] (:kotoba.release/missing result)))))

(deftest expired-exception-does-not-excuse
  (let [tc (edn/read-string (slurp "conformance/release/negative/expired-exception.edn"))
        result (evaluate-case tc)]
    (is (= [:sbom] (:kotoba.release/missing result)))
    (is (= [] (:kotoba.release/excepted result)))))

(deftest malformed-exception-never-excuses
  (testing "exception without owner"
    (let [tc (edn/read-string (slurp "conformance/release/negative/exception-without-owner.edn"))
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
  (let [tc (edn/read-string (slurp "conformance/release/negative/failed-evidence-result.edn"))
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
  (let [evidence-index (edn/read-string (slurp "registers/evidence-index.edn"))
        exception-register (edn/read-string (slurp "registers/exception-register.edn"))
        result (gate/evaluate-release {:evidence-index evidence-index
                                       :exception-register exception-register
                                       :now "2026-07-02"})]
    (is (= [] (:kotoba.release/problems result)))))
