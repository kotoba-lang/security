(ns kotoba.security.crypto-policy-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [kotoba.security.crypto-policy :as policy]))

;; conformance/crypto/{negative,positive}/*.edn, policy/crypto-policy.edn and
;; registers/crypto-inventory.edn were datomic/datascript-ized by
;; edn-datomize.bb (wrap-map-keep-ns): top level is now `[{:db/id -1 ...}]`
;; tx-data. Already-namespaced keys (:case/id, :register/type,
;; :kotoba.security/crypto-policy-version, ...) are unchanged; bare keys
;; (:policy, :envelope, :inventory, :mode, :hybrid-epoch-floor,
;; :allowed-providers, ...) were promoted to the transform's directory-derived
;; namespace (e.g. "conformance.crypto.negative", "policy.crypto-policy").
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
  (let [tc (read-tx-edn
            (io/file "conformance/crypto/negative/fips-required-rejects-nonfips-provider.edn")
            "conformance.crypto.negative")
        result (run-case tc)]
    (is (= "fips-validated provider required" (:message result)))))

(deftest hybrid-required-rejects-classical-kem-new-epoch
  (let [tc (read-tx-edn
            (io/file "conformance/crypto/negative/hybrid-required-rejects-classical-kem-new-epoch.edn")
            "conformance.crypto.negative")
        result (run-case tc)]
    (is (= "hybrid kem required for new epochs" (:message result)))))

(deftest hybrid-flag-cannot-hide-algorithm-downgrade
  (let [p {:kotoba.security/crypto-policy-version 1
           :mode :hybrid-required :hybrid-epoch-floor 1}
        provider {:provider/id :test :provider/fips-validated false}
        current {:envelope/provider provider :envelope/kem? true
                 :envelope/hybrid? true :envelope/epoch 1
                 :envelope/algorithms [:x25519 :ml-kem-768]}
        downgraded (assoc current :envelope/epoch 2
                         :envelope/algorithms [:x25519])
        rotated (assoc current :envelope/epoch 2)]
    (is (false? (:valid? (policy/check-envelope p downgraded))))
    (is (= "envelope epoch must increase"
           (:message (policy/rotate-envelope p current current))))
    (is (= {:valid? true :previous-epoch 1 :current-epoch 2
            :algorithms [:x25519 :ml-kem-768]}
           (policy/rotate-envelope p current rotated)))))

(deftest production-boundary-rejects-legacy-epoch
  (let [p {:kotoba.security/crypto-policy-version 1
           :mode :hybrid-required :hybrid-epoch-floor 7}
        envelope {:envelope/provider {:provider/id :test
                                      :provider/fips-validated false}
                  :envelope/kem? true :envelope/hybrid? true
                  :envelope/algorithms [:x25519 :ml-kem-768]}]
    (is (false? (:valid? (policy/check-production-envelope
                          p (assoc envelope :envelope/epoch 6)))))
    (is (:valid? (policy/check-production-envelope
                  p (assoc envelope :envelope/epoch 7))))))

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
  (let [crypto-policy (read-tx-edn (io/file "policy/crypto-policy.edn") "policy.crypto-policy")
        inventory (read-tx-edn (io/file "registers/crypto-inventory.edn") "registers.crypto-inventory")]
    (is (= :crypto-agile (:mode crypto-policy)))
    (is (= {:valid? true} (policy/check-inventory crypto-policy inventory)))))

(deftest real-inventory-fails-under-fips-required
  (let [crypto-policy (assoc (read-tx-edn (io/file "policy/crypto-policy.edn") "policy.crypto-policy")
                             :mode :fips-required)
        inventory (read-tx-edn (io/file "registers/crypto-inventory.edn") "registers.crypto-inventory")
        result (policy/check-inventory crypto-policy inventory)]
    (is (false? (:valid? result)))
    (is (= "fips status not-claimed forbidden under fips-required"
           (:message result)))))
