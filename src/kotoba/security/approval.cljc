(ns kotoba.security.approval
  "Digest-bound, time-limited, independent approval quorum admission.")

(defn- signature-valid? [verify-signature-fn approval]
  (and (ifn? verify-signature-fn)
       (try
         (true? (verify-signature-fn
                 (dissoc approval :approval/signature)
                 (:approval/signature approval)))
         (catch #?(:clj Exception :cljs :default) _ false))))

(defn- approval-violations
  [approval {:keys [request-digest now-ms verify-signature-fn]}]
  (cond-> []
    (not= 1 (:approval/version approval)) (conj :version)
    (not (some? (:approval/approver approval))) (conj :approver)
    (not (keyword? (:approval/role approval))) (conj :role)
    (not= request-digest (:approval/request-digest approval))
    (conj :request-digest)
    (not (and (integer? now-ms)
              (integer? (:approval/not-before-ms approval))
              (integer? (:approval/expires-at-ms approval))
              (<= (:approval/not-before-ms approval) now-ms)
              (< now-ms (:approval/expires-at-ms approval))))
    (conj :validity)
    (not (signature-valid? verify-signature-fn approval)) (conj :signature)))

(defn evaluate
  "Require independent, signed approvals bound to one request digest.

  The initiator cannot approve their own operation. Approvers and roles must
  both be distinct; REQUIRED-ROLES must be covered and MIN-APPROVALS defaults
  to two."
  [approvals {:keys [initiator required-roles min-approvals] :as context}]
  (let [approvals (vec (or approvals []))
        minimum (or min-approvals 2)
        individual (mapv #(approval-violations % context) approvals)
        approvers (mapv :approval/approver approvals)
        roles (set (map :approval/role approvals))
        violations
        (cond-> []
          (some seq individual) (conj :invalid-approval)
          (< (count approvals) minimum) (conj :minimum-approvals)
          (not= (count approvers) (count (set approvers)))
          (conj :distinct-approvers)
          (some #{initiator} approvers) (conj :initiator-separated)
          (not (every? roles (set required-roles))) (conj :required-roles))]
    {:approval/allowed? (empty? violations)
     :approval/violations violations
     :approval/individual-violations individual
     :approval/approvers (set approvers)
     :approval/roles roles
     :approval/request-digest (:request-digest context)}))
