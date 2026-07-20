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

(def pq-module-digest "sha256:ml-kem-module")

(def pq-provider
  {:provider/id :ml-kem/production
   :provider/implementation-version "1.0.0"
   :provider/module-digest pq-module-digest
   :provider/algorithms [:ml-kem-768]
   :provider/known-answer-tests-passed? true
   :provider/encapsulation-verified? true
   :provider/decapsulation-verified? true
   :provider/invalid-ciphertext-rejected? true
   :provider/module-load-failed-closed? true})

(defn pq-envelope [epoch]
  {:envelope/provider {:provider/id :ml-kem/production
                       :provider/module-digest pq-module-digest
                       :provider/fips-validated false}
   :envelope/kem? true :envelope/hybrid? true
   :envelope/algorithms [:x25519 :ml-kem-768]
   :envelope/epoch epoch})

(def pq-policy
  {:kotoba.security/crypto-policy-version 1
   :mode :hybrid-required :hybrid-epoch-floor 1})

(def transport-artifact "sha256:ca-module")

(def transport-profile
  {:protocol :tls-1.3 :mutual-auth? true
   :peer-id "spiffe://kotoba/aiueos"
   :expected-peer-id "spiffe://kotoba/aiueos"
   :certificate-fingerprint "sha256:new-cert"
   :trusted-fingerprints #{"sha256:new-cert" "sha256:next-cert"}
   :revocation-checked? true :now "2026-07-20T02:00:00Z"
   :certificate-not-before "2026-07-20T01:00:00Z"
   :certificate-expires-at "2026-07-20T03:00:00Z"
   :require-rotation-overlap? true
   :next-certificate-fingerprint "sha256:next-cert"})

(def workload-identity
  {:workload-id "spiffe://kotoba/aiueos" :issuer :production-workload-ca
   :audience "kotoba-production" :issued-at-ms 1000 :expires-at-ms 1600
   :now-ms 1200 :max-ttl-ms 900 :revocation-status :active})

(def ca-custody
  {:ca-id :production-workload-ca :provider-id :hsm/production
   :hardware-backed? true :attestation-verified? true
   :private-exported? false :sign-verified? true
   :rotation-drill-passed? true :outage-failed-closed? true})

(def transport-rotation
  {:rotation-drill/status :passed
   :rotation-drill/current "sha256:new-cert"
   :rotation-drill/revoked #{"sha256:old-cert"}
   :rotation-drill/rollback-denied? true
   :rotation-drill/events [{:event :stage} {:event :promote} {:event :revoke}]})

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

(deftest pqc-e4-binds-provider-module-boundaries-and-drills
  (let [deployment {:provider-evidence pq-provider
                    :boundaries qualification/required-boundaries
                    :current-envelope (pq-envelope 10)
                    :next-envelope (pq-envelope 11)
                    :downgrade-rejected? true :rollback-rejected? true
                    :rotation-drill-passed? true
                    :evidence-log (evidence-log :pqc pq-module-digest)}]
    (is (= :E4 (:qualification/evidence-level
                (qualification/verify-pqc-e4
                 deployment pq-policy (context pq-module-digest)))))
    (doseq [candidate
            [(assoc-in deployment
                       [:next-envelope :envelope/algorithms] [:x25519])
             (assoc-in deployment
                       [:next-envelope :envelope/provider :provider/id]
                       :substituted-provider)
             (assoc-in deployment
                       [:provider-evidence :provider/module-digest]
                       "sha256:other-module")
             (assoc deployment :boundaries #{:transport})
             (assoc deployment :downgrade-rejected? false)
             (assoc deployment :rollback-rejected? false)
             (assoc deployment :rotation-drill-passed? false)
             (assoc-in deployment [:evidence-log :remote?] false)]]
      (is (false? (:qualification/accepted?
                   (qualification/verify-pqc-e4
                    candidate pq-policy (context pq-module-digest))))))))

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

(deftest transport-e4-requires-mtls-short-lived-identity-ca-and-rotation
  (let [deployment {:transport-profile transport-profile
                    :workload-identity workload-identity
                    :ca-custody ca-custody
                    :rotation-receipt transport-rotation
                    :evidence-log
                    (evidence-log :transport-confidentiality-integrity
                                  transport-artifact)}]
    (is (= :E4 (:qualification/evidence-level
                (qualification/verify-transport-e4
                 deployment (context transport-artifact)))))
    (doseq [candidate
            [(assoc-in deployment [:transport-profile :protocol] :tls-1.2)
             (assoc-in deployment [:transport-profile :mutual-auth?] false)
             (assoc-in deployment [:transport-profile :peer-id]
                       "spiffe://attacker/workload")
             (assoc-in deployment [:workload-identity :expires-at-ms] 3000)
             (assoc-in deployment [:workload-identity :revocation-status]
                       :revoked)
             (assoc-in deployment [:ca-custody :private-exported?] true)
             (assoc-in deployment [:ca-custody :outage-failed-closed?] false)
             (assoc-in deployment
                       [:rotation-receipt :rotation-drill/rollback-denied?]
                       false)
             (assoc-in deployment [:rotation-receipt :rotation-drill/events]
                       [{:event :promote} {:event :stage} {:event :revoke}])
             (assoc-in deployment [:evidence-log :immutable?] false)]]
      (is (false? (:qualification/accepted?
                   (qualification/verify-transport-e4
                    candidate (context transport-artifact))))))))
