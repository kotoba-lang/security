(ns kotoba.security.assurance
  (:require [clojure.set :as set]))

(def required-profile-fields
  #{:assurance/score :assurance/maturity :assurance/grade
    :assurance/release-gate :assurance/evidence
    :assurance/residual-critical-gaps})

(defn weights-valid? [model controls]
  (let [weights (get-in model [:score :weights])]
    (and (= (set controls) (set (keys weights)))
         (= 1 (reduce + (vals weights)))
         (every? pos? (vals weights)))))

(defn weighted-score [model scores]
  (reduce-kv (fn [total control weight]
               (+ total (* weight (get scores control 0))))
             0 (get-in model [:score :weights])))

(defn heat [model score]
  (some (fn [color]
          (let [minimum (get-in model [:heatmap color :minimum])]
            (when (and minimum (>= score minimum)) color)))
        [:green :yellow :orange :red]))

(defn model-problems [model controls]
  (cond-> []
    (not= :kotoba.security/assurance-model (:model/type model))
    (conj :model-type)
    (not= 1 (:model/version model)) (conj :model-version)
    (not (weights-valid? model controls)) (conj :weights)
    (not= required-profile-fields (set (:required-report-fields model)))
    (conj :report-fields)))

(defn profile-problems [model profile]
  (let [missing (set/difference required-profile-fields (set (keys profile)))
        maturity (set (map :id (:maturity model)))
        evidence (set (map :id (:evidence model)))
        grades (set (map :id (:grades model)))
        gates (set (:release-gates model))]
    (cond-> []
      (seq missing) (conj [:missing missing])
      (not (<= 0 (:assurance/score profile -1) 100)) (conj :score)
      (not (contains? maturity (:assurance/maturity profile))) (conj :maturity)
      (not (contains? evidence (:assurance/evidence profile))) (conj :evidence)
      (not (contains? grades (:assurance/grade profile))) (conj :grade)
      (not (contains? gates (:assurance/release-gate profile))) (conj :gate)
      (not (integer? (:assurance/residual-critical-gaps profile)))
      (conj :residual-critical-gaps))))
