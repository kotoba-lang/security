(ns kotoba.security.promotion-test
  (:require [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.test :refer [deftest is]]
            [kotoba.security.promotion :as promotion]
            [kotoba.security.score :as score]))

(def model (edn/read-string (slurp "policy/security-assurance-model-v2.edn")))
(def promotion-policy
  (edn/read-string (slurp "policy/repo-grade-a-promotion.edn")))
(def required-workstreams (:required-workstreams promotion-policy))
(def now-ms 200000)
(def artifact "sha256:kagi-release")
(def controls (set (:assessment/controls (score/read-register))))
(def control-scores (zipmap controls (repeat 85)))
(def profile
  {:assurance/score 85 :assurance/maturity :L4 :assurance/grade :A
   :assurance/release-gate :partial :assurance/evidence :E4
   :assurance/residual-critical-gaps 1})

(defn receipt [workstream]
  {:qualification/accepted? true :qualification/workstream workstream
   :qualification/repo :kagi :qualification/artifact-digest artifact
   :qualification/evidence-level :E4 :qualification/issued-at-ms 199500
   :qualification/evidence-head (str "sha256:head-" (name workstream))})

(def qualifications
  (into {} (map (fn [workstream] [workstream (receipt workstream)]))
        (:kagi required-workstreams)))

(def context
  {:model model :required-workstreams required-workstreams
   :now-ms now-ms :max-age-ms 1000})

(def candidate
  {:repo :kagi :artifact-digest artifact :control-scores control-scores
   :profile profile :qualifications qualifications})

(deftest complete-repo-bound-bundle-can-promote
  (let [result (promotion/evaluate-grade-a candidate context)]
    (is (:promotion/allowed? result) (pr-str result))
    (is (= (:kagi required-workstreams)
           (:promotion/required-workstreams result)))))

(deftest partial-foreign-stale-or-reused-bundles-fail-closed
  (let [first-workstream (first (:kagi required-workstreams))
        second-workstream (second (:kagi required-workstreams))
        head (get-in qualifications
                     [first-workstream :qualification/evidence-head])]
    (doseq [bad [(update candidate :qualifications dissoc first-workstream)
                 (assoc-in candidate
                           [:qualifications first-workstream :qualification/repo]
                           :compiler)
                 (assoc-in candidate
                           [:qualifications first-workstream
                            :qualification/artifact-digest] "sha256:other")
                 (assoc-in candidate
                           [:qualifications first-workstream
                            :qualification/issued-at-ms] 1)
                 (assoc-in candidate
                           [:qualifications second-workstream
                            :qualification/evidence-head] head)
                 (assoc-in candidate
                           [:qualifications first-workstream
                            :qualification/accepted?] false)]]
      (is (false? (:promotion/allowed?
                   (promotion/evaluate-grade-a bad context)))))))

(deftest score-critical-maturity-and-evidence-guards-are-independent
  (doseq [bad [(assoc-in candidate [:profile :assurance/score] 84)
               (assoc candidate :control-scores
                      (assoc control-scores :hsm 59))
               (assoc-in candidate [:profile :assurance/maturity] :L3)
               (assoc-in candidate [:profile :assurance/evidence] :E3)
               (assoc-in candidate [:profile :assurance/release-gate] :fail)]]
    (is (false? (:promotion/allowed?
                 (promotion/evaluate-grade-a bad context))))))

(deftest policy-and-gap-register-cover-the-same-workstreams
  (let [gap-register
        (edn/read-string (slurp "registers/remaining-operational-gaps.edn"))
        gap-workstreams (set (map :workstream (:gaps gap-register)))
        policy-workstreams (apply set/union (vals required-workstreams))]
    (is (= :not-qualified (:operational/readiness gap-register)))
    (is (= policy-workstreams gap-workstreams))))
