(ns kotoba.security.grade-roadmap-test
  (:require [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.test :refer [deftest is]]
            [kotoba.security.score :as score]))

(def roadmap
  (edn/read-string (slurp "policy/grade-a-s-roadmap.edn")))

(deftest roadmap-covers-the-authoritative-stack
  (let [repos (set (keys (:assessment/repos (score/read-register))))]
    (is (= :kotoba.security/grade-a-s-roadmap (:roadmap/type roadmap)))
    (is (= 1 (:roadmap/version roadmap)))
    (is (= repos (set (keys (:repos roadmap)))))
    (doseq [[repo plan] (:repos roadmap)]
      (is (= (:current/score plan)
             (Math/round ((score/repo-averages (score/read-register)) repo))))
      (is (= (- 80 (:current/score plan)) (:to-A/points plan)))
      (is (= (- 90 (:current/score plan)) (:to-S/points plan)))
      (is (seq (:priority-controls plan)))
      (is (set/subset? (set (:priority-controls plan))
                       (set (:assessment/controls (score/read-register))))))))

(deftest promotion-contract-is-strictly-ordered
  (let [a (get-in roadmap [:promotion :A])
        s (get-in roadmap [:promotion :S])]
    (is (< (:score/minimum a) (:score/minimum s)))
    (is (< (:critical-control/minimum a)
           (:critical-control/minimum s)))
    (is (= #{:pass} (:release-gate/allowed s)))
    (is (zero? (:residual-critical-gaps s)))
    (is (= :E4 (:evidence/minimum a)))
    (is (= :E5 (:evidence/minimum s)))))

(deftest workstream-dependencies-reference-known-nodes
  (let [workstreams (:workstreams roadmap)
        ids (set (keys workstreams))]
    (doseq [[id workstream] workstreams]
      (is (set/subset? (:depends-on workstream) ids) (str id))
      (is (seq (:deliverables workstream)) (str id)))))

(deftest na-measurement-change-is-versioned-and-auditable
  (let [decision (:measurement-decision roadmap)]
    (is (= :model-v2-na-semantics (:required-decision decision)))
    (is (some :preferred? (:options decision)))
    (is (every? (set (:guardrails decision))
                [:version-model :publish-old-and-new-baselines
                 :never-relabel-a-gap-as-na :semantic-tests-required]))))
