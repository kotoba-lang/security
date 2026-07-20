(ns kotoba.security.adoption
  "Fail-closed verifier for organization-wide use of the shared controls."
  (:require [clojure.edn :as edn]
            [clojure.string :as str])
  (:import [java.time LocalDate]))

(def security-coordinate 'io.github.kotoba-lang/security)
(def security-url "https://github.com/kotoba-lang/security.git")
(def full-sha-pattern #"[0-9a-f]{40}")

(defn- non-empty-string? [value]
  (and (string? value) (not (str/blank? value))))

(defn- active-exception? [today {:keys [owner reason expires]}]
  (and (non-empty-string? owner)
       (non-empty-string? reason)
       (non-empty-string? expires)
       (not (.isBefore (LocalDate/parse expires) today))))

(defn violations
  "Return contract violations without loading namespaces."
  [config deps today]
  (let [dependency (get-in deps [:deps security-coordinate])
        required-sha (:security/git-sha config)
        controls (:required-control-namespaces config)
        entrypoints (:security-sensitive-entrypoints config)
        exceptions (:exceptions config)]
    (cond-> []
      (not= 1 (:adoption/version config))
      (conj :unsupported-adoption-version)

      (not (keyword? (:consumer/id config)))
      (conj :missing-consumer-id)

      (not= security-url (:git/url dependency))
      (conj :wrong-security-repository)

      (not (and (string? required-sha)
                (re-matches full-sha-pattern required-sha)
                (= required-sha (:git/sha dependency))))
      (conj :security-pin-mismatch)

      (not (and (seq controls)
                (every? #(str/starts-with? (str %) "kotoba.security.") controls)))
      (conj :missing-central-control-namespaces)

      (not (seq entrypoints))
      (conj :missing-security-sensitive-entrypoints)

      (not (every? #(active-exception? today %) exceptions))
      (conj :invalid-or-expired-exception))))

(defn verify!
  "Verify files in ROOT and require declared controls and entrypoints."
  ([] (verify! "."))
  ([root]
   (let [config (edn/read-string (slurp (str root "/security-adoption.edn")))
         deps (edn/read-string (slurp (str root "/deps.edn")))
         problems (violations config deps (LocalDate/now))]
     (when (seq problems)
       (throw (ex-info "shared security adoption denied"
                       {:security.adoption/violations problems})))
     (doseq [namespace (concat (:required-control-namespaces config)
                               (:security-sensitive-entrypoints config))]
       (require namespace))
     {:security.adoption/status :pass
      :consumer/id (:consumer/id config)
      :security/git-sha (:security/git-sha config)})))

(defn -main [& [root]]
  (prn (verify! (or root "."))))
