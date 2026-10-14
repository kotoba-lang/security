(ns kotoba.security.adoption-jvm-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.security.adoption :as adoption])
  (:import [java.time LocalDate]))

(def ^:private security-sha "65811c9d6878e881357e98f9f9fe6a60aeff7070")
(def ^:private today (LocalDate/parse "2026-07-20"))
(def ^:private valid-config
  {:adoption/version 3
   :consumer/id :example
   :security/git-sha security-sha
   :required-control-namespaces ['kotoba.security.adoption]
   :security-sensitive-entrypoints
   {'kotoba.security.adoption-jvm-test ['kotoba.security.adoption]}
   :sensitive-operations {}
   :exceptions []})
(def ^:private valid-deps
  {:deps {'io.github.kotoba-lang/security
          {:git/url adoption/security-url :git/sha security-sha}}})

(deftest contract-validation-fails-closed-on-pin-drift
  (is (empty? (adoption/violations valid-config valid-deps today)))
  (is (= [:security-pin-mismatch]
         (adoption/violations
          valid-config
          (assoc-in valid-deps
                    [:deps adoption/security-coordinate :git/sha]
                    "main")
          today))))

(deftest source-inventory-reads-conditional-clj-and-cljs-libspecs
  (is (= {'demo.core #{'kotoba.security.abac
                       'kotoba.security.crypto-policy}
          'demo.tagged #{'kotoba.security.redaction}}
         (adoption/source-security-inventory "test-fixtures/multifeature"))))

(deftest sensitive-operation-inventory-scans-cljk-files
  (let [operations (adoption/source-sensitive-inventory ".")]
    (is (contains? operations 'kotoba.security.aead/chacha20-poly1305-decrypt))
    (is (contains? operations 'kotoba.security.key-status/revoke-key))
    (is (contains? operations 'kotoba.security.x25519/private-key)))
)
