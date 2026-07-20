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
      (not= 2 (:adoption/version config))
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

      (not (and (map? entrypoints)
                (seq entrypoints)
                (every? symbol? (keys entrypoints))
                (every? seq (vals entrypoints))
                (every? (fn [required]
                          (contains? (set controls) required))
                        (mapcat identity (vals entrypoints)))))
      (conj :missing-security-sensitive-entrypoints)

      (not (every? #(active-exception? today %) exceptions))
      (conj :invalid-or-expired-exception))))

(defn- namespace-dependencies [namespace]
  (let [loaded (the-ns namespace)]
    (set (concat (map (comp ns-name val) (ns-aliases loaded))
                 (keep (fn [[_ referred-var]]
                         (some-> referred-var meta :ns ns-name))
                       (ns-refers loaded))))))

(defn- dependency-edge-violations [entrypoints]
  (into []
        (comp
         (mapcat (fn [[entrypoint required-controls]]
                   (let [dependencies (namespace-dependencies entrypoint)]
                     (for [control required-controls
                           :when (not (contains? dependencies control))]
                       {:problem :missing-control-dependency-edge
                        :entrypoint entrypoint
                        :control control})))))
        entrypoints))

(defn verify!
  "Verify files, load declarations, and prove entrypoint-to-control edges."
  ([] (verify! "."))
  ([root]
   (let [config (edn/read-string (slurp (str root "/security-adoption.edn")))
         deps (edn/read-string (slurp (str root "/deps.edn")))
         problems (violations config deps (LocalDate/now))]
     (when (seq problems)
       (throw (ex-info "shared security adoption denied"
                       {:security.adoption/violations problems})))
     (doseq [namespace (concat (:required-control-namespaces config)
                               (keys (:security-sensitive-entrypoints config)))]
       (require namespace))
     (let [edge-problems
           (dependency-edge-violations (:security-sensitive-entrypoints config))]
       (when (seq edge-problems)
         (throw (ex-info "shared security dependency edge denied"
                         {:security.adoption/violations edge-problems}))))
     {:security.adoption/status :pass
      :consumer/id (:consumer/id config)
      :security/git-sha (:security/git-sha config)})))

(defn -main [& [root]]
  (prn (verify! (or root "."))))
