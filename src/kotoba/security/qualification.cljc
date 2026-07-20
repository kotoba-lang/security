(ns kotoba.security.qualification
  "Evidence gates for production cryptography and resilience qualifications.

  Receipts are accepted only when bound to an expected environment, authority,
  immutable artifact digest and verifier-supplied signature check."
  (:require [clojure.set :as set]
            [kotoba.security.crypto-policy :as crypto]
            [kotoba.security.evidence-plane :as evidence-plane]
            [kotoba.security.hardware :as hardware]
            [kotoba.security.resilience :as resilience]))

(def required-boundaries
  #{:package-admission :compiler-artifact :deployment :transport :secret-store})

(defn- fail [violations]
  {:qualification/accepted? false :qualification/violations (vec violations)})

(defn verify-signed-receipt
  [receipt {:keys [environment authority-id now-ms max-age-ms verify-signature-fn]}]
  (let [violations
        (cond-> []
          (not= 1 (:receipt/version receipt)) (conj :receipt-version)
          (not= environment (:receipt/environment receipt)) (conj :environment)
          (not= authority-id (:receipt/authority-id receipt)) (conj :authority)
          (not (string? (:receipt/artifact-digest receipt))) (conj :artifact-digest)
          (not (integer? (:receipt/issued-at-ms receipt))) (conj :issued-at)
          (or (not (integer? (:receipt/issued-at-ms receipt)))
              (> (- now-ms (:receipt/issued-at-ms receipt 0)) max-age-ms)
              (> (:receipt/issued-at-ms receipt 0) now-ms)) (conj :freshness)
          (not (ifn? verify-signature-fn)) (conj :signature-verifier)
          (and (ifn? verify-signature-fn)
               (not (true? (verify-signature-fn
                            (dissoc receipt :receipt/signature)
                            (:receipt/signature receipt))))) (conj :signature))]
    (if (seq violations) (fail violations)
        {:qualification/accepted? true
         :qualification/artifact-digest (:receipt/artifact-digest receipt)})))

(defn verify-pqc-deployment
  [{:keys [boundaries current-envelope next-envelope downgrade-rejected?
           rollback-rejected? rotation-receipt]} policy receipt-context]
  (let [boundary-set (set boundaries)
        current-check (crypto/check-envelope policy current-envelope)
        rotation-check (crypto/rotate-envelope policy current-envelope next-envelope)
        receipt-check (verify-signed-receipt rotation-receipt receipt-context)
        violations (cond-> []
                     (not (set/subset? required-boundaries boundary-set))
                     (conj :production-boundaries)
                     (not (:valid? current-check)) (conj :current-envelope)
                     (not (:valid? rotation-check)) (conj :rotation)
                     (not= true downgrade-rejected?) (conj :downgrade)
                     (not= true rollback-rejected?) (conj :rollback)
                     (not (:qualification/accepted? receipt-check))
                     (conj :rotation-receipt))]
    (if (seq violations) (fail violations)
        {:qualification/accepted? true
         :qualification/control :pqc
         :qualification/boundaries boundary-set
         :qualification/current-epoch (:envelope/epoch next-envelope)})))

(defn verify-hsm-deployment
  [{:keys [hardware-evidence outage-receipt]} receipt-context]
  (let [hardware-check (hardware/evaluate hardware-evidence)
        receipt-check (verify-signed-receipt outage-receipt receipt-context)
        violations (cond-> []
                     (not (:hardware/qualified? hardware-check))
                     (into (:hardware/violations hardware-check))
                     (not (:qualification/accepted? receipt-check))
                     (conj :outage-receipt))]
    (if (seq violations) (fail violations)
        {:qualification/accepted? true
         :qualification/control :hsm
         :qualification/provider-id (:hardware/provider-id hardware-check)})))

(defn verify-resilience-deployment
  [{:keys [telemetry-remote? telemetry-immutable? containment-live?
           backup-regions restore-destructive? restore-digest-verified?
           rto-ms rpo-ms rto-limit-ms rpo-limit-ms operation-receipt]}
   receipt-context]
  (let [regions (set backup-regions)
        receipt-check (verify-signed-receipt operation-receipt receipt-context)
        violations (cond-> []
                     (not= true telemetry-remote?) (conj :remote-telemetry)
                     (not= true telemetry-immutable?) (conj :immutable-telemetry)
                     (not= true containment-live?) (conj :live-containment)
                     (< (count regions) 2) (conj :independent-regions)
                     (not= true restore-destructive?) (conj :destructive-restore)
                     (not= true restore-digest-verified?) (conj :restore-digest)
                     (or (not (number? rto-ms)) (> rto-ms rto-limit-ms))
                     (conj :rto)
                     (or (not (number? rpo-ms)) (> rpo-ms rpo-limit-ms))
                     (conj :rpo)
                     (not (:qualification/accepted? receipt-check))
                     (conj :operation-receipt))]
    (if (seq violations) (fail violations)
        {:qualification/accepted? true
         :qualification/control :resilience
         :qualification/regions regions
         :qualification/rto-ms rto-ms
         :qualification/rpo-ms rpo-ms})))

(defn verify-hardware-e4
  "Combine provider semantics with the shared production evidence plane."
  [{:keys [hardware-evidence evidence-log]} evidence-context]
  (let [hardware-check (hardware/evaluate hardware-evidence)
        evidence-check (evidence-plane/verify-log
                        evidence-log (assoc evidence-context :control :hsm))
        violations (cond-> []
                     (not (:hardware/qualified? hardware-check))
                     (into (:hardware/violations hardware-check))
                     (not (:evidence/accepted? evidence-check))
                     (conj :production-evidence))]
    (if (seq violations) (fail violations)
        {:qualification/accepted? true
         :qualification/control :hsm
         :qualification/evidence-level :E4
         :qualification/provider-id (:hardware/provider-id hardware-check)
         :qualification/evidence-head (:evidence/head-digest evidence-check)})))

(defn verify-pqc-e4
  "Combine deployed-provider, boundary, rotation, and E4 evidence checks."
  [{:keys [provider-evidence boundaries current-envelope next-envelope
           downgrade-rejected? rollback-rejected? rotation-drill-passed?
           evidence-log]}
   policy
   {:keys [artifact-digest] :as evidence-context}]
  (let [provider-check (crypto/evaluate-pq-provider
                        provider-evidence artifact-digest)
        provider-id (:pq-provider/id provider-check)
        boundary-set (set boundaries)
        current-check (crypto/check-production-envelope policy current-envelope)
        next-check (crypto/check-production-envelope policy next-envelope)
        rotation-check (crypto/rotate-envelope policy current-envelope next-envelope)
        provider-bound? (and (= provider-id
                                (get-in current-envelope
                                        [:envelope/provider :provider/id]))
                             (= provider-id
                                (get-in next-envelope
                                        [:envelope/provider :provider/id]))
                             (= artifact-digest
                                (get-in current-envelope
                                        [:envelope/provider :provider/module-digest]))
                             (= artifact-digest
                                (get-in next-envelope
                                        [:envelope/provider :provider/module-digest])))
        evidence-check (evidence-plane/verify-log
                        evidence-log (assoc evidence-context :control :pqc))
        violations
        (cond-> []
          (not (:pq-provider/qualified? provider-check))
          (into (:pq-provider/violations provider-check))
          (not provider-bound?) (conj :provider-substitution)
          (not (set/subset? required-boundaries boundary-set))
          (conj :production-boundaries)
          (not (:valid? current-check)) (conj :current-envelope)
          (not (:valid? next-check)) (conj :next-envelope)
          (not (:valid? rotation-check)) (conj :rotation)
          (not= true downgrade-rejected?) (conj :downgrade)
          (not= true rollback-rejected?) (conj :rollback)
          (not= true rotation-drill-passed?) (conj :rotation-drill)
          (not (:evidence/accepted? evidence-check))
          (conj :production-evidence))]
    (if (seq violations) (fail violations)
        {:qualification/accepted? true
         :qualification/control :pqc
         :qualification/evidence-level :E4
         :qualification/provider-id provider-id
         :qualification/module-digest artifact-digest
         :qualification/boundaries boundary-set
         :qualification/current-epoch (:envelope/epoch next-envelope)
         :qualification/evidence-head (:evidence/head-digest evidence-check)})))

(defn verify-recovery-e4
  "Combine destructive restore, threshold custody, and production evidence."
  [{:keys [restore-receipt threshold-recovery evidence-log]}
   {:keys [artifact-digest] :as evidence-context}]
  (let [restore-check (resilience/evaluate-restore-receipt
                       restore-receipt artifact-digest)
        threshold-check (resilience/evaluate-threshold-recovery
                         threshold-recovery)
        evidence-check (evidence-plane/verify-log
                        evidence-log
                        (assoc evidence-context :control :unrecoverable-loss))
        violations (cond-> []
                     (not (:restore-drill/qualified? restore-check))
                     (into (:restore-drill/violations restore-check))
                     (not (:threshold-recovery/qualified? threshold-check))
                     (into (:threshold-recovery/violations threshold-check))
                     (not (:evidence/accepted? evidence-check))
                     (conj :production-evidence))]
    (if (seq violations) (fail violations)
        {:qualification/accepted? true
         :qualification/control :unrecoverable-loss
         :qualification/evidence-level :E4
         :qualification/regions
         (set/union (:restore-drill/sites restore-check)
                    (:threshold-recovery/regions threshold-check))
         :qualification/threshold (:threshold-recovery/threshold threshold-check)
         :qualification/rto-ms (:restore-drill/rto-ms restore-check)
         :qualification/rpo-ms (:restore-drill/rpo-ms restore-check)
         :qualification/evidence-head (:evidence/head-digest evidence-check)})))
