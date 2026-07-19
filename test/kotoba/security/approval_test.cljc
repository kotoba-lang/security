(ns kotoba.security.approval-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.security.approval :as approval]))

(def digest "sha256:release")

(defn signed [approver role]
  {:approval/version 1 :approval/approver approver :approval/role role
   :approval/request-digest digest
   :approval/not-before-ms 1000 :approval/expires-at-ms 2000
   :approval/signature [:valid approver digest]})

(def context
  {:initiator :release-bot :required-roles #{:security :release}
   :min-approvals 2 :request-digest digest :now-ms 1500
   :verify-signature-fn
   (fn [body signature]
     (= signature [:valid (:approval/approver body)
                   (:approval/request-digest body)]))})

(deftest independent-role-quorum-allows-bound-request
  (let [result (approval/evaluate [(signed :alice :security)
                                   (signed :bob :release)] context)]
    (is (:approval/allowed? result))
    (is (= #{:alice :bob} (:approval/approvers result)))
    (is (= #{:security :release} (:approval/roles result)))))

(deftest quorum-fails-closed-on-collusion-replay-expiry-or-forgery
  (doseq [approvals [[(signed :alice :security)]
                     [(signed :alice :security) (signed :alice :release)]
                     [(signed :release-bot :security) (signed :bob :release)]
                     [(signed :alice :security) (signed :bob :security)]
                     [(assoc (signed :alice :security)
                             :approval/request-digest "sha256:other")
                      (signed :bob :release)]
                     [(assoc (signed :alice :security)
                             :approval/expires-at-ms 1500)
                      (signed :bob :release)]
                     [(assoc (signed :alice :security)
                             :approval/signature [:forged])
                      (signed :bob :release)]]]
    (is (false? (:approval/allowed? (approval/evaluate approvals context))))))
