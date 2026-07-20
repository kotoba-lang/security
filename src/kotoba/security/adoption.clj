(ns kotoba.security.adoption
  "Fail-closed verifier for organization-wide use of the shared controls."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.set :as set]
            [clojure.string :as str])
  (:import [java.io PushbackReader]
           [java.time LocalDate]))

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

(defn- security-symbol? [value]
  (and (symbol? value)
       (str/starts-with? (str value) "kotoba.security.")))

(defn- ns-form [file]
  (with-open [reader (PushbackReader. (io/reader file))]
    (loop []
      (let [form (read {:read-cond :allow :features #{:clj} :eof nil} reader)]
        (cond
          (nil? form) nil
          (and (seq? form) (= 'ns (first form))) form
          :else (recur))))))

(defn source-security-inventory
  "Discover namespace-to-central-control import edges under ROOT/src."
  [root]
  (into {}
        (keep (fn [file]
                (when-let [form (ns-form file)]
                  (let [namespace (second form)
                        controls (into #{} (filter security-symbol?)
                                       (tree-seq coll? seq (drop 2 form)))]
                    (when (seq controls) [namespace controls])))))
        (filter (fn [file]
                  (and (.isFile file)
                       (re-find #"\.clj[cs]?$" (.getName file))))
                (file-seq (io/file root "src")))))

(defn inventory-violations
  "Compare declared entrypoint edges with imports discovered under src/."
  [config discovered]
  (let [declared (update-vals (:security-sensitive-entrypoints config) set)
        missing (sort (remove (set (keys declared)) (keys discovered)))
        stale (sort (remove (set (keys discovered)) (keys declared)))
        mismatched
        (into []
              (keep (fn [namespace]
                      (when (not= (get declared namespace)
                                  (get discovered namespace))
                        {:namespace namespace
                         :declared (get declared namespace)
                         :discovered (get discovered namespace)})))
              (sort (set/intersection (set (keys declared))
                                      (set (keys discovered)))))]
    (cond-> []
      (seq missing) (conj {:problem :unregistered-security-importers
                           :namespaces missing})
      (seq stale) (conj {:problem :stale-security-entrypoints
                         :namespaces stale})
      (seq mismatched) (conj {:problem :source-control-edge-mismatch
                              :edges mismatched}))))

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
     (let [inventory-problems
           (inventory-violations config (source-security-inventory root))]
       (when (seq inventory-problems)
         (throw (ex-info "shared security source inventory denied"
                         {:security.adoption/violations inventory-problems}))))
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
