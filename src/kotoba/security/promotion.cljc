(ns kotoba.security.promotion
  "Repo-wide assurance promotion gate. Individual control success cannot
  promote a repository without every declared workstream and profile guard."
  (:require [clojure.set :as set]
            [kotoba.security.assurance :as assurance]))

(def maturity-rank {:L0 0 :L1 1 :L2 2 :L3 3 :L4 4})
(def evidence-rank {:E0 0 :E1 1 :E2 2 :E3 3 :E4 4 :E5 5})

(defn receipt-problems
  [receipt {:keys [repo artifact-digest now-ms max-age-ms]} workstream]
  (let [issued (:qualification/issued-at-ms receipt)]
    (cond-> []
      (not= true (:qualification/accepted? receipt)) (conj :not-accepted)
      (not= workstream (:qualification/workstream receipt)) (conj :workstream)
      (not= repo (:qualification/repo receipt)) (conj :repo-binding)
      (not= artifact-digest (:qualification/artifact-digest receipt))
      (conj :artifact-binding)
      (< (get evidence-rank (:qualification/evidence-level receipt) -1)
         (evidence-rank :E4)) (conj :evidence-level)
      (not (and (integer? issued) (integer? now-ms) (integer? max-age-ms)
                (<= 0 (- now-ms issued) max-age-ms))) (conj :freshness)
      (not (and (string? (:qualification/evidence-head receipt))
                (seq (:qualification/evidence-head receipt))))
      (conj :evidence-head))))

(defn evaluate-grade-a
  [{:keys [repo artifact-digest control-scores profile qualifications]}
   {:keys [model required-workstreams now-ms max-age-ms]}]
  (let [required (set (get required-workstreams repo))
        supplied (set (keys qualifications))
        missing (set/difference required supplied)
        receipt-results
        (into {} (map (fn [workstream]
                        [workstream
                         (receipt-problems (get qualifications workstream)
                                           {:repo repo :artifact-digest artifact-digest
                                            :now-ms now-ms :max-age-ms max-age-ms}
                                           workstream)])) required)
        heads (keep :qualification/evidence-head (vals qualifications))
        score (assurance/rounded-score model control-scores)
        critical-values (map control-scores (:critical-controls model))
        violations
        (cond-> []
          (empty? required) (conj :unknown-repo)
          (seq missing) (conj [:missing-workstreams missing])
          (some seq (vals receipt-results)) (conj :invalid-workstream-receipt)
          (not= (count heads) (count (set heads))) (conj :reused-evidence-head)
          (not= score (:assurance/score profile)) (conj :score-provenance)
          (< score 80) (conj :score-minimum)
          (some #(< (or % 0) 60) critical-values) (conj :critical-control-floor)
          (< (get maturity-rank (:assurance/maturity profile) -1)
             (maturity-rank :L4)) (conj :maturity)
          (< (get evidence-rank (:assurance/evidence profile) -1)
             (evidence-rank :E4)) (conj :evidence)
          (not (contains? #{:partial :pass} (:assurance/release-gate profile)))
          (conj :release-gate)
          (not (contains? #{:A :S}
                          (assurance/expected-grade model control-scores score)))
          (conj :grade-band)
          (not (contains? #{:A :S} (:assurance/grade profile)))
          (conj :declared-grade))]
    {:promotion/allowed? (empty? violations)
     :promotion/target :A
     :promotion/repo repo
     :promotion/score score
     :promotion/required-workstreams required
     :promotion/receipt-problems receipt-results
     :promotion/violations violations}))
