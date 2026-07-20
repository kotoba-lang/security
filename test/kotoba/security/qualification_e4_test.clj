(ns kotoba.security.qualification-e4-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.security.qualification :as qualification]))

(defn digest-entry [entry]
  (str "digest:" (:evidence/id entry) ":" (:evidence/sequence entry) ":"
       (:evidence/previous-digest entry)))

(defn evidence-log [control artifact]
  (let [base {:evidence/version 1 :evidence/id "EV-E4-1"
              :evidence/sequence 1 :evidence/previous-digest "genesis"
              :evidence/artifact-digest artifact :evidence/control control
              :evidence/environment :production
              :evidence/authority-id :operations
              :evidence/log-id :production-log :evidence/issued-at-ms 1900
              :evidence/nonce (str "nonce-" (name control))}
        entry (assoc base :evidence/entry-digest (digest-entry base))
        signed (assoc entry :evidence/signature
                      [:valid (:evidence/entry-digest entry)])]
    {:entries [signed]
     :head {:head/log-id :production-log :head/sequence 1
            :head/authority-id :independent-auditor
            :storage/provider-id :qualified-remote-worm
            :head/entry-digest (:evidence/entry-digest signed)
            :head/signature [:valid-head (:evidence/entry-digest signed)]}
     :remote? true :immutable? true :seen-nonces #{}}))

(defn context [artifact]
  {:environment :production :authority-id :operations
   :log-id :production-log :artifact-digest artifact
   :now-ms 2000 :max-age-ms 500 :digest-entry-fn digest-entry
   :storage-provider-id :qualified-remote-worm
   :storage-provider-qualified? true
   :head-authority-id :independent-auditor
   :verify-signature-fn
   (fn [entry signature]
     (= signature [:valid (:evidence/entry-digest entry)]))
   :verify-head-signature-fn
   (fn [head signature]
     (= signature [:valid-head (:head/entry-digest head)]))})

(def hardware-evidence
  {:provider-id :pkcs11/production :hardware-backed? true
   :attestation-verified? true :private-exported? false
   :sign-verified? true :kem-verified? true
   :rotation-drill-passed? true :outage-failed-closed? true})

(def restore-receipt
  {:restore-drill/status :passed :restore-drill/destructive? true
   :restore-drill/sites #{:jp-east :jp-west}
   :restore-drill/backups-encrypted? true
   :restore-drill/backups-immutable? true
   :restore-drill/artifact-digest "sha256:backup"
   :restore-drill/digest-verified? true
   :restore-drill/rto-ms 40 :restore-drill/rto-limit-ms 100
   :restore-drill/rpo-ms 20 :restore-drill/rpo-limit-ms 60})

(def threshold-recovery
  {:threshold 2
   :shares [{:share/member-id :custodian-a :share/region :jp-east
             :share/hardware-protected? true :share/unwrap-verified? true}
            {:share/member-id :custodian-b :share/region :jp-west
             :share/hardware-protected? true :share/unwrap-verified? true}]})

(deftest hardware-e4-requires-provider-and-independent-evidence
  (let [artifact "sha256:hsm-attestation"
        deployment {:hardware-evidence hardware-evidence
                    :evidence-log (evidence-log :hsm artifact)}]
    (is (= :E4 (:qualification/evidence-level
                (qualification/verify-hardware-e4 deployment
                                                  (context artifact)))))
    (testing "provider outage failure cannot hide behind a valid log"
      (is (false? (:qualification/accepted?
                   (qualification/verify-hardware-e4
                    (assoc-in deployment
                              [:hardware-evidence :outage-failed-closed?] false)
                    (context artifact))))))
    (testing "local, replayed, or wrong-control logs fail closed"
      (doseq [bad [(assoc (:evidence-log deployment) :remote? false)
                   (assoc (:evidence-log deployment)
                          :seen-nonces #{"nonce-hsm"})
                   (evidence-log :unrecoverable-loss artifact)]]
        (is (false? (:qualification/accepted?
                     (qualification/verify-hardware-e4
                      (assoc deployment :evidence-log bad)
                      (context artifact)))))))))

(deftest recovery-e4-requires-geo-threshold-and-independent-evidence
  (let [artifact "sha256:backup"
        deployment {:restore-receipt restore-receipt
                    :threshold-recovery threshold-recovery
                    :evidence-log (evidence-log :unrecoverable-loss artifact)}]
    (is (= :E4 (:qualification/evidence-level
                (qualification/verify-recovery-e4 deployment
                                                  (context artifact)))))
    (doseq [bad-threshold
            [(assoc threshold-recovery :threshold 3)
             (assoc-in threshold-recovery [:shares 1 :share/member-id]
                       :custodian-a)
             (assoc-in threshold-recovery [:shares 1 :share/region] :jp-east)
             (assoc-in threshold-recovery
                       [:shares 1 :share/hardware-protected?] false)]]
      (is (false? (:qualification/accepted?
                   (qualification/verify-recovery-e4
                    (assoc deployment :threshold-recovery bad-threshold)
                    (context artifact))))))
    (testing "a region collapse or replayed evidence blocks E4"
      (is (false? (:qualification/accepted?
                   (qualification/verify-recovery-e4
                    (assoc-in deployment [:restore-receipt :restore-drill/sites]
                              #{:jp-east})
                    (context artifact)))))
      (is (false? (:qualification/accepted?
                   (qualification/verify-recovery-e4
                    (assoc-in deployment [:evidence-log :seen-nonces]
                              #{"nonce-unrecoverable-loss"})
                    (context artifact))))))))
