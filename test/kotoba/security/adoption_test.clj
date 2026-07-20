(ns kotoba.security.adoption-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.security.adoption :as adoption])
  (:import [java.time LocalDate]))

(def sha "65811c9d6878e881357e98f9f9fe6a60aeff7070")
(def today (LocalDate/parse "2026-07-20"))
(def valid-config
  {:adoption/version 2
   :consumer/id :kotoba
   :security/git-sha sha
   :required-control-namespaces ['kotoba.security.adoption]
   :security-sensitive-entrypoints
   {'kotoba.security.adoption-test ['kotoba.security.adoption]}
   :exceptions []})
(def valid-deps
  {:deps {'io.github.kotoba-lang/security
          {:git/url adoption/security-url :git/sha sha}}})

(deftest valid-contract-passes
  (is (empty? (adoption/violations valid-config valid-deps today))))

(deftest verifier-proves-a-real-dependency-edge
  (with-redefs [clojure.core/slurp
                (fn [path]
                  (pr-str (if (.endsWith path "deps.edn")
                            valid-deps valid-config)))]
    (is (= :pass (:security.adoption/status (adoption/verify! "."))))))

(deftest dependency-and-routing-drift-fail-closed
  (is (= [:security-pin-mismatch]
         (adoption/violations valid-config
                              (assoc-in valid-deps
                                        [:deps adoption/security-coordinate :git/sha]
                                        "main")
                              today)))
  (is (= [:missing-central-control-namespaces
          :missing-security-sensitive-entrypoints]
         (adoption/violations (assoc valid-config
                                     :required-control-namespaces
                                     ['consumer.local.security])
                              valid-deps today))))

(deftest exceptions-require-owner-reason-and-unexpired-date
  (testing "expired"
    (is (= [:invalid-or-expired-exception]
           (adoption/violations
            (assoc valid-config :exceptions
                   [{:owner "security" :reason "migration" :expires "2026-07-19"}])
            valid-deps today))))
  (testing "bounded"
    (is (empty?
         (adoption/violations
          (assoc valid-config :exceptions
                 [{:owner "security" :reason "migration" :expires "2026-07-21"}])
          valid-deps today)))))
