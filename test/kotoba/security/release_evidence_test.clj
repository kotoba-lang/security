(ns kotoba.security.release-evidence-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.security.release-evidence :as release-evidence]
            [kotoba.security.signed-module :as signed-module]))

(def component-bytes (.getBytes "safe-component" "UTF-8"))
(def other-bytes (.getBytes "other-component" "UTF-8"))
(def seed (byte-array (range 32)))

(defn packet
  ([] (packet component-bytes))
  ([bytes]
   (let [envelope (signed-module/sign bytes {:seed seed
                                             :name "agent-program"
                                             :version "1.0.0"
                                             :exports ["run"]
                                             :capabilities [:clock/read]
                                             :module-graph-digest "sha256:graph"})
         signer (get-in envelope [:statement :signer])
         cid (signed-module/component-cid component-bytes)]
     {:package-receipt
      {:kotoba.package/verified? true
       :kotoba.package/problems []
       :kotoba.package/entries
       [{:package/id "agent-program"
         :package/result :accepted
         :package/component-cid cid}]}
      :signed-module envelope
      :component-bytes bytes
      :trust {:trusted-signers #{signer} :revoked-signers #{}}
      :key-register {:keys [{:key/id signer :key/status :active}]}
      :sbom {:digest "sha256:sbom"}
      :provenance {:digest "sha256:provenance"}
      :now "2026-08-15"
      :require-component-cid? true})))

(deftest complete-release-identity-is-admitted
  (is (:ok? (release-evidence/evaluate (packet)))))

(deftest unrelated-component-cannot-inherit-receipt
  (let [result (release-evidence/evaluate (packet other-bytes))]
    (is (false? (:ok? result)))
    (is (some #(= :release/component-not-in-receipt (:problem %))
              (:problems result)))))

(deftest trust-and-active-key-are-mandatory
  (testing "empty trust fails closed"
    (let [result (release-evidence/evaluate
                  (assoc (packet) :trust {:trusted-signers #{}}))]
      (is (false? (:ok? result)))
      (is (some #(= :signed-module/trust-required (:problem %))
                (:problems result)))))
  (testing "missing active signer fails closed"
    (let [result (release-evidence/evaluate
                  (assoc (packet) :key-register {:keys []}))]
      (is (false? (:ok? result)))
      (is (some #(= :release/signer-not-active (:problem %))
                (:problems result))))))

(deftest module-authority-metadata-is-signed
  (let [tampered (update-in (packet) [:signed-module :module :capabilities]
                            conj :network/fetch)
        result (release-evidence/evaluate tampered)]
    (is (false? (:ok? result)))
    (is (some #(= :signed-module/module-digest-mismatch (:problem %))
              (:problems result)))))

(deftest unsigned-exception-never-waives-required-evidence
  (let [result (release-evidence/evaluate
                (-> (packet)
                    (dissoc :sbom)
                    (assoc :exception-register
                           {:exceptions [{:kind :sbom
                                          :owner "self"
                                          :expires "2099-01-01"}]})))]
    (is (false? (:ok? result)))
    (is (some #(and (= :release/missing-evidence (:problem %))
                    (= :sbom (:kind %)))
              (:problems result)))))
