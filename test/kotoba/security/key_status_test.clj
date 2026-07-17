(ns kotoba.security.key-status-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.security.key-status :as key-status]))

(deftest blocked-and-active-partition
  (let [reg {:keys [{:key/id "a" :key/status :active}
                    {:key/id "r" :key/status :revoked}
                    {:key/id "p" :key/status :pre-active}]}]
    (is (= #{"a"} (key-status/active-signer-ids reg)))
    (is (= #{"r" "p"} (key-status/blocked-signer-ids reg)))))

(deftest evaluate-requires-an-active-key-when-keys-present
  (let [all-pre {:keys [{:key/id "x" :key/status :pre-active}]}
        mixed {:keys [{:key/id "x" :key/status :pre-active}
                      {:key/id "y" :key/status :active}]}]
    (is (false? (:kotoba.key/ok? (key-status/evaluate-key-register all-pre))))
    (is (true? (:kotoba.key/ok? (key-status/evaluate-key-register mixed))))))
