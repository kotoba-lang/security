(ns kotoba.security.crypto-policy-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kotoba.security.crypto-policy :as policy]))

(defn fixture-cases
  [dir]
  (->> (.listFiles (io/file dir))
       (filter #(str/ends-with? (.getName %) ".edn"))
       (sort-by #(.getName %))
       (map #(edn/read-string (slurp %)))))

(defn run-case
  [tc]
  (case (:case/check tc)
    :envelope (policy/check-envelope (:policy tc) (:envelope tc))
    :inventory (policy/check-inventory (:policy tc) (:inventory tc))))

(deftest positive-fixtures-pass
  (let [cases (fixture-cases "conformance/crypto/positive")]
    (is (seq cases))
    (doseq [tc cases]
      (let [result (run-case tc)]
        (is (:valid? result)
            (str (:case/id tc) " -> " (pr-str result)))))))

(deftest negative-fixtures-fail
  (let [cases (fixture-cases "conformance/crypto/negative")]
    (is (seq cases))
    (doseq [tc cases]
      (let [result (run-case tc)]
        (is (false? (:valid? result))
            (str (:case/id tc) " should be rejected"))))))

(deftest fips-required-rejects-nonfips-provider
  (let [tc (edn/read-string
            (slurp "conformance/crypto/negative/fips-required-rejects-nonfips-provider.edn"))
        result (run-case tc)]
    (is (= "fips-validated provider required" (:message result)))))

(deftest hybrid-required-rejects-classical-kem-new-epoch
  (let [tc (edn/read-string
            (slurp "conformance/crypto/negative/hybrid-required-rejects-classical-kem-new-epoch.edn"))
        result (run-case tc)]
    (is (= "hybrid kem required for new epochs" (:message result)))))

(deftest missing-provider-metadata-rejected-under-any-mode
  (doseq [mode [:crypto-agile :hybrid-required :fips-required]]
    (testing (str mode)
      (let [result (policy/check-envelope
                    {:kotoba.security/crypto-policy-version 1
                     :mode mode
                     :hybrid-epoch-floor 1}
                    {:envelope/algorithms [:ed25519]
                     :envelope/epoch 0
                     :envelope/hybrid? false})]
        (is (= "provider metadata required" (:message result)))))))

(deftest inventory-structure-is-enforced
  (let [base-policy {:kotoba.security/crypto-policy-version 1
                     :mode :crypto-agile
                     :hybrid-epoch-floor 1}]
    (testing "missing required field"
      (let [result (policy/check-inventory
                    base-policy
                    {:register/type :kotoba.security/crypto-inventory
                     :register/version 1
                     :inventory [{:crypto/use :object-encryption
                                  :crypto/current [:aes-256-gcm]
                                  :crypto/target [:aes-256-gcm]
                                  :crypto/pq-status :symmetric-ok-monitor}]})]
        (is (false? (:valid? result)))
        (is (= "missing required crypto inventory field" (:message result)))))
    (testing "empty current algorithms"
      (let [result (policy/check-inventory
                    base-policy
                    {:register/type :kotoba.security/crypto-inventory
                     :register/version 1
                     :inventory [{:crypto/use :object-encryption
                                  :crypto/current []
                                  :crypto/target [:aes-256-gcm]
                                  :crypto/pq-status :symmetric-ok-monitor
                                  :crypto/fips-status :not-claimed}]})]
        (is (= "crypto current algorithms required" (:message result)))))
    (testing "wrong register type"
      (let [result (policy/check-inventory
                    base-policy
                    {:register/type :wrong/type
                     :register/version 1
                     :inventory []})]
        (is (false? (:valid? result)))))))

(deftest real-inventory-passes-real-policy
  (let [crypto-policy (edn/read-string (slurp "policy/crypto-policy.edn"))
        inventory (edn/read-string (slurp "registers/crypto-inventory.edn"))]
    (is (= :crypto-agile (:mode crypto-policy)))
    (is (= {:valid? true} (policy/check-inventory crypto-policy inventory)))))

(deftest real-inventory-fails-under-fips-required
  (let [crypto-policy (assoc (edn/read-string (slurp "policy/crypto-policy.edn"))
                             :mode :fips-required)
        inventory (edn/read-string (slurp "registers/crypto-inventory.edn"))
        result (policy/check-inventory crypto-policy inventory)]
    (is (false? (:valid? result)))
    (is (= "fips status not-claimed forbidden under fips-required"
           (:message result)))))
