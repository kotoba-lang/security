#!/usr/bin/env bb
;; Safe-release evidence gate (kotoba-lang/kotoba#265).
;;
;; Usage (run from the repo root):
;;   bb scripts/check-safe-release.bb
;;       Validate the conformance/release fixture matrix (positive fixtures
;;       must pass, negative fixtures must fail), structurally validate the
;;       real registers, and report the real release-packet status as
;;       :advisory without failing. This is the CI mode.
;;
;;   bb scripts/check-safe-release.bb --release [evidence-index.edn exception-register.edn]
;;       Enforce the release gate strictly against the real registers.
;;       Exit 1 when the release evidence packet is incomplete.
;;
;; Register paths may be overridden by positional argv (evidence index first,
;; exception register second).
(require '[babashka.classpath :refer [add-classpath]]
         '[clojure.edn :as edn]
         '[clojure.java.io :as io]
         '[clojure.string :as str])

(def script-dir (-> *file* io/file .getAbsoluteFile .getParentFile))
(def root (.getParentFile script-dir))
(add-classpath (str (io/file root "src")))

(require '[kotoba.security.release-gate :as gate])

(def args (vec *command-line-args*))
(def release? (boolean (some #{"--release"} args)))
(def path-args (vec (remove #{"--release"} args)))

(def evidence-file
  (if (first path-args)
    (io/file (first path-args))
    (io/file root "registers/evidence-index.edn")))

(def exception-file
  (if (second path-args)
    (io/file (second path-args))
    (io/file root "registers/exception-register.edn")))

(def today (str (java.time.LocalDate/now)))

;; registers/*.edn and conformance/release/{positive,negative}/*.edn were
;; datomic/datascript-ized by edn-datomize.bb (wrap-map-keep-ns): each file's
;; top level is now `[{:db/id -1 ...}]` tx-data, where keys that were already
;; namespaced (:register/type, :case/id, ...) are unchanged and bare keys
;; (:evidence, :exceptions, :now, :evidence-index, :exception-register, ...)
;; got promoted to `ns-name` (the transform's directory-derived namespace,
;; e.g. "registers.evidence-index" or "conformance.release.positive"). This
;; reconstitutes the original raw map so every existing call site below keeps
;; working unchanged. Non-scalar values were pr-str'd ("blob") by the
;; transform; unblob restores them via edn/read-string.
(defn- unblob [v]
  (if (string? v)
    (try (let [parsed (edn/read-string v)] (if (coll? parsed) parsed v))
         (catch Exception _ v))
    v))

(defn- tx-data? [content]
  (and (vector? content) (seq content) (map? (first content)) (contains? (first content) :db/id)))

(defn- reconstitute-entity [ns-name tx-data]
  (into {} (map (fn [[k v]]
                  [(if (= ns-name (namespace k)) (keyword (name k)) k)
                   (unblob v)]))
        (dissoc (first tx-data) :db/id)))

(defn read-edn
  "Reads an EDN file. If it's already tx-data (post edn-datomize.bb), the
  original map is reconstituted using `ns-name`; legacy raw-map files (e.g.
  a hand-supplied --release override) pass through unchanged."
  ([f] (read-edn f nil))
  ([f ns-name]
   (let [content (edn/read-string (slurp f))]
     (if (and ns-name (tx-data? content))
       (reconstitute-entity ns-name content)
       content))))

(defn fixture-files [dir]
  (->> (.listFiles (io/file root dir))
       (filter #(str/ends-with? (.getName %) ".edn"))
       (sort-by #(.getName %))))

(defn evaluate-case [tc]
  (gate/evaluate-release {:evidence-index (:evidence-index tc)
                          :exception-register (:exception-register tc)
                          :now (:now tc)}))

(defn run-fixtures! []
  (reduce
   (fn [failures [dir expect-ok?]]
     (reduce
      (fn [failures file]
        (let [tc (read-edn file (str/replace dir "/" "."))
              result (evaluate-case tc)
              ok? (:kotoba.release/ok? result)]
          (if (= expect-ok? ok?)
            (do (println (str "ok " (:case/id tc)
                              (when-not expect-ok? " -> rejected as expected")))
                failures)
            (do (println "FAIL" (:case/id tc)
                         (if expect-ok? "expected ok" "expected rejection")
                         (pr-str result))
                (conj failures (:case/id tc))))))
      failures
      (fixture-files dir)))
   []
   [["conformance/release/positive" true]
    ["conformance/release/negative" false]]))

(defn print-claim-lines [result prefix]
  (let [emit (fn [& parts]
               (println (str/join " " (if (str/blank? prefix)
                                        parts
                                        (cons prefix parts)))))]
    (doseq [claim gate/required-claims]
      (cond
        (some #{claim} (:kotoba.release/missing result))
        (emit "missing" claim)

        (some (fn [e] (= claim (:claim e))) (:kotoba.release/excepted result))
        (emit "ok" claim "(excepted)")

        :else
        (emit "ok" claim)))
    (doseq [problem (:kotoba.release/problems result)]
      (emit "problem" (pr-str problem)))))

(let [evidence-index (read-edn evidence-file "registers.evidence-index")
      exception-register (read-edn exception-file "registers.exception-register")
      result (gate/evaluate-release {:evidence-index evidence-index
                                     :exception-register exception-register
                                     :now today})]
  (if release?
    ;; Strict release gate: the evidence packet must be complete.
    (do (print-claim-lines result "")
        (if (:kotoba.release/ok? result)
          (println "ok safe-release packet complete")
          (do (println "FAIL safe-release packet incomplete"
                       (pr-str {:missing (:kotoba.release/missing result)
                                :problems (:kotoba.release/problems result)}))
              (System/exit 1))))
    ;; CI mode: fixture matrix + structural check of real registers +
    ;; advisory (non-failing) packet status.
    (let [fixture-failures (run-fixtures!)
          register-problems (:kotoba.release/problems result)]
      (println "ok fixtures" (str "(" (count (fixture-files "conformance/release/positive"))
                                  " positive, "
                                  (count (fixture-files "conformance/release/negative"))
                                  " negative)"))
      (print-claim-lines result ":advisory")
      (println ":advisory release-ready?" (:kotoba.release/ok? result))
      (when (seq register-problems)
        (println "FAIL register structure" (pr-str register-problems)))
      (when (seq fixture-failures)
        (println "FAIL fixtures" (pr-str fixture-failures)))
      (when (or (seq fixture-failures) (seq register-problems))
        (System/exit 1))
      (println "ok safe-release gate (advisory mode; use --release to enforce)"))))
