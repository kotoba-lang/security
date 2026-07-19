(ns kotoba.security.abac-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.security.abac :as abac]))

(def attributes
  {:subject {:id "did:owner" :signer :release :role :owner
             :tenant "alpha" :clearance :restricted}
   :resource {:id :vault/primary :tenant "alpha" :trust :verified
              :classification :confidential :effects #{:storage}}
   :action {:id :item/reveal :capabilities #{:secret/reveal}}
   :environment {:surface :cloud :network-zone :private
                 :device-trusted? true :now "2026-07-19T12:00:00Z"}
   :purpose :operations :disclosure-bytes 64})

(def policy
  {:policy/id "common-v1" :subject/signers #{:release} :subject/roles #{:owner}
   :resource/ids #{:vault/primary}
   :resource/trust #{:verified} :resource/effects #{:storage}
   :action/ids #{:item/reveal} :action/capabilities #{:secret/reveal}
   :environment/surfaces #{:cloud} :environment/network-zones #{:private}
   :environment/require-device-trust? true :purpose/allowed #{:operations}
   :tenant/isolation? true :valid/not-before "2026-07-19T00:00:00Z"
   :valid/expires-at "2026-07-20T00:00:00Z" :disclosure/max-bytes 1024})

(deftest exact-four-axis-context-is-allowed
  (let [result (abac/evaluate attributes policy)]
    (is (:abac/allowed? result))
    (is (= "common-v1" (:abac/policy-id result)))))

(deftest declared-conditions-fail-closed
  (doseq [[label path value control]
          [[:signer [:subject :signer] :attacker :subject-signer]
           [:resource-id [:resource :id] :other :resource-id]
           [:tenant [:resource :tenant] "beta" :tenant-isolation]
           [:effect [:resource :effects] #{:storage :network} :resource-effects]
           [:action [:action :capabilities] #{:secret/export} :action-capabilities]
           [:surface [:environment :surface] :browser :environment-surface]
           [:device [:environment :device-trusted?] false :environment-device]
           [:clearance [:subject :clearance] :internal :classification]
           [:expiry [:environment :now] "2026-07-21T00:00:00Z" :expired]
           [:size [:disclosure-bytes] nil :disclosure-size]]]
    (testing (name label)
      (let [result (abac/evaluate (assoc-in attributes path value) policy)]
        (is (false? (:abac/allowed? result)))
        (is (some #(= control (:abac/control %)) (:abac/violations result)))))))
