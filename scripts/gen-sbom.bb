#!/usr/bin/env bb
;; CycloneDX-inspired EDN SBOM generator for the safe-release evidence packet
;; (docs/sbom-slsa.md, docs/operational-evidence.md).
;;
;; Usage:
;;   bb scripts/gen-sbom.bb <deps.edn-path> <repo-name> [out-path]
;;
;; Reads a Clojure deps.edn and emits an EDN SBOM:
;;   {:sbom/format :cyclonedx-edn
;;    :sbom/version 1
;;    :sbom/subject {:repo <repo-name> :commit <git HEAD of the deps.edn dir>}
;;    :sbom/components [{:type :maven :group .. :artifact .. :version ..}
;;                      {:type :git-dep :name .. :git/tag .. :git/sha ..}
;;                      {:type :local-sibling :name .. :local/root ..}]}
;;
;; Direct deps only (as written in deps.edn; transitive resolution is out of
;; scope). Top-level :deps carry :scope :runtime; every alias's :extra-deps
;; are included with :scope = the alias keyword (:test, :vectors, ...).
(require '[clojure.edn :as edn]
         '[clojure.java.io :as io]
         '[clojure.pprint :as pprint]
         '[clojure.string :as str]
         '[babashka.process :refer [shell]])

(defn fail! [msg]
  (binding [*out* *err*] (println "gen-sbom:" msg))
  (System/exit 1))

(def args (vec *command-line-args*))
(when (< (count args) 2)
  (fail! "usage: bb scripts/gen-sbom.bb <deps.edn-path> <repo-name> [out-path]"))

(def deps-file (io/file (first args)))
(def repo-name (second args))
(def out-path (nth args 2 nil))

(when-not (.isFile deps-file)
  (fail! (str "deps.edn not readable: " deps-file)))

(def repo-dir (.getParentFile (.getAbsoluteFile deps-file)))

(def commit
  (-> (shell {:out :string :dir (str repo-dir)} "git" "rev-parse" "HEAD")
      :out
      str/trim))

(defn component
  "One SBOM component for a deps.edn coordinate."
  [lib coord scope]
  (let [group (or (namespace lib) (name lib))
        artifact (name lib)
        base (cond
               (:mvn/version coord)
               {:type :maven
                :group group
                :artifact artifact
                :version (:mvn/version coord)}

               (or (:git/sha coord) (:git/tag coord) (:git/url coord))
               (cond-> {:type :git-dep
                        :name (str lib)}
                 (:git/url coord) (assoc :git/url (:git/url coord))
                 (:git/tag coord) (assoc :git/tag (:git/tag coord))
                 (:git/sha coord) (assoc :git/sha (:git/sha coord)))

               (:local/root coord)
               {:type :local-sibling
                :name (str lib)
                :local/root (:local/root coord)}

               :else
               {:type :unknown
                :name (str lib)
                :coord coord})]
    (assoc base :scope scope)))

(def deps-edn (edn/read-string (slurp deps-file)))

(def components
  (vec
   (concat
    (for [[lib coord] (sort-by (comp str key) (:deps deps-edn))]
      (component lib coord :runtime))
    (for [[alias {:keys [extra-deps]}] (sort-by (comp str key) (:aliases deps-edn))
          [lib coord] (sort-by (comp str key) extra-deps)]
      (component lib coord alias)))))

(def sbom
  {:sbom/format :cyclonedx-edn
   :sbom/version 1
   :sbom/subject {:repo repo-name
                  :commit commit
                  :deps-edn (str deps-file)}
   :sbom/components components})

(let [rendered (with-out-str (pprint/pprint sbom))]
  (if out-path
    (do (io/make-parents (io/file out-path))
        (spit out-path rendered)
        (println "ok sbom" repo-name "->" out-path
                 (str "(" (count components) " components)")))
    (print rendered)))
