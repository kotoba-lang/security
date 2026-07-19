(ns kotoba.security.assurance-test
  (:require [clojure.edn :as edn]
            [clojure.test :refer [deftest is]]
            [kotoba.security.assurance :as assurance]
            [kotoba.security.score :as score]))

(def model (edn/read-string (slurp "policy/security-assurance-model.edn")))

(deftest repo-wide-model-is-complete-and-normalized
  (let [register (score/read-register)
        controls (:assessment/controls register)]
    (is (= [] (assurance/model-problems model controls)))
    (doseq [[_ scores] (:assessment/repos register)]
      (is (<= 0 (assurance/weighted-score model scores) 100)))))

(deftest heatmap-bands-are-deterministic
  (is (= :green (assurance/heat model 80)))
  (is (= :yellow (assurance/heat model 60)))
  (is (= :orange (assurance/heat model 40)))
  (is (= :red (assurance/heat model 39))))

(deftest incomplete-profile-fails-closed
  (is (seq (assurance/profile-problems model {:assurance/score 100})))
  (is (= [] (assurance/profile-problems
             model
             {:assurance/score 66 :assurance/maturity :L3
              :assurance/grade :B :assurance/release-gate :partial
              :assurance/evidence :E3
              :assurance/residual-critical-gaps 5}))))

(deftest current-stack-profiles-conform-to-repo-wide-rule
  (let [register (edn/read-string
                  (slurp "registers/stack-security-assurance.edn"))]
    (is (= :kotoba.security/stack-assurance (:register/type register)))
    (is (= 8 (count (:register/profiles register))))
    (doseq [[repo profile] (:register/profiles register)]
      (is (= [] (assurance/profile-problems model profile))
          (str repo " assurance profile must satisfy the common rule")))))
