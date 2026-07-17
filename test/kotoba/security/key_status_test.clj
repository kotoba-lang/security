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

(deftest status-transition-ok-matrix
  (testing "pre-active may become active or revoked"
    (is (true? (key-status/status-transition-ok? :pre-active :active)))
    (is (true? (key-status/status-transition-ok? :pre-active :revoked)))
    (is (false? (key-status/status-transition-ok? :pre-active :retired))))
  (testing "active may retire, revoke, expire, suspend, compromise"
    (is (true? (key-status/status-transition-ok? :active :retired)))
    (is (true? (key-status/status-transition-ok? :active :revoked)))
    (is (true? (key-status/status-transition-ok? :active :expired)))
    (is (true? (key-status/status-transition-ok? :active :suspended)))
    (is (true? (key-status/status-transition-ok? :active :compromised)))
    (is (false? (key-status/status-transition-ok? :active :pre-active))))
  (testing "destroyed is terminal"
    (is (false? (key-status/status-transition-ok? :destroyed :active)))
    (is (false? (key-status/status-transition-ok? :destroyed :revoked))))
  (testing "seed nil -> pre-active only"
    (is (true? (key-status/status-transition-ok? nil :pre-active)))
    (is (false? (key-status/status-transition-ok? nil :active)))))

(deftest promote-to-active-is-pure-and-notes-oob-secrets
  (let [k {:key/id "demo"
           :key/status :pre-active
           :key/notes "Template only."}
        promoted (key-status/promote-to-active k "2026-07-17" "2026-10-17")]
    (is (= :active (:key/status promoted)))
    (is (= "2026-07-17" (:key/active-from promoted)))
    (is (= "2026-10-17" (:key/active-until promoted)))
    (is (re-find #"out-of-band" (:key/notes promoted)))
    (is (nil? (:key/private-key promoted)))
    (is (nil? (:key/secret promoted)))
    (is (nil? (:key/transition-error promoted)))))

(deftest promote-from-active-is-illegal
  (let [k {:key/id "already" :key/status :active}
        out (key-status/promote-to-active k "2026-07-17")]
    (is (= :active (:key/status out)))
    (is (= :illegal-status-transition
           (get-in out [:key/transition-error :problem])))))

(deftest revoke-key-records-reason
  (let [k {:key/id "a" :key/status :active :key/notes "live"}
        revoked (key-status/revoke-key k "rotation complete" "2026-07-17")]
    (is (= :revoked (:key/status revoked)))
    (is (= "rotation complete" (:key/revoke-reason revoked)))
    (is (= "2026-07-17" (:key/revoked-at revoked)))
    (is (re-find #"Revoked" (:key/notes revoked)))))

(deftest revoke-from-destroyed-is-illegal
  (let [k {:key/id "gone" :key/status :destroyed}
        out (key-status/revoke-key k "too late")]
    (is (= :destroyed (:key/status out)))
    (is (= :illegal-status-transition
           (get-in out [:key/transition-error :problem])))))

(deftest snapshot-includes-checked-at
  (let [reg {:register/type :kotoba.security/key-register
             :register/version 1
             :keys [{:key/id "a" :key/status :active}]}
        snap (key-status/snapshot-for-evidence reg "2026-07-17")]
    (is (= "2026-07-17" (:kotoba.key/checked-at snap)))
    (is (true? (:kotoba.key/ok? snap)))
    (is (= ["a"] (:kotoba.key/active snap)))))
