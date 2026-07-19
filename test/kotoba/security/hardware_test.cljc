(ns kotoba.security.hardware-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.security.hardware :as hardware]))

(def qualified
  {:provider-id :pkcs11/production :hardware-backed? true
   :attestation-verified? true :private-exported? false
   :sign-verified? true :kem-verified? true
   :rotation-drill-passed? true :outage-failed-closed? true})

(deftest complete-hardware-evidence-is-qualified
  (is (:hardware/qualified? (hardware/evaluate qualified))))

(deftest software-label-or-outage-success-cannot-claim-hsm
  (let [result (hardware/evaluate
                (assoc qualified :hardware-backed? false
                                 :outage-failed-closed? false))]
    (is (false? (:hardware/qualified? result)))
    (is (= [:hardware-backed :outage-fail-closed]
           (:hardware/violations result)))))
