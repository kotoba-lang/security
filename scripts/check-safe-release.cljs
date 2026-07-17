#!/usr/bin/env nbb
;; --- nbb shims (auto, ADR-2607173000) ---------------------------------
(def ^:private __fs (js/require "node:fs"))
(def ^:private __path (js/require "node:path"))
(def ^:private __cp (js/require "node:child_process"))
(def ^:private __os (js/require "node:os"))
(def ^:private __crypto (js/require "node:crypto"))
(defn- __sh [& args]
  (let [opts (when (map? (last args)) (last args))
        cmd (if opts (butlast args) args)
        r (.spawnSync __cp (first cmd) (to-array (rest cmd))
                      (clj->js (merge {:encoding "utf8"} (when opts {:cwd (:dir opts)}))))]
    {:exit (or (.-status r) 1) :out (or (.-stdout r) "") :err (or (.-stderr r) "")}))
(defn- __shell [& args]
  (let [opts (when (map? (first args)) (first args))
        cmd (if opts (rest args) args)
        r (.spawnSync __cp (first cmd) (to-array (rest cmd))
                      (clj->js (merge {:stdio "inherit" :encoding "utf8"}
                                      (when opts {:cwd (:dir opts)}))))]
    (when-not (zero? (or (.-status r) 1))
      (throw (js/Error. (str "shell failed: " (pr-str cmd)))))
    {:exit (or (.-status r) 0) :out "" :err ""}))
;; -----------------------------------------------------------------------
;; Safe-release evidence gate (kotoba-lang/kotoba#265).
;;
;; Usage (run from the repo root):
;;   nbb scripts/check-safe-release.bb
;;       Validate the conformance/release fixture matrix (positive fixtures
;;       must pass, negative fixtures must fail), structurally validate the
;;       real registers, and report the real release-packet status as
;;       :advisory without failing. This is the CI mode.
;;
;;   nbb scripts/check-safe-release.nbb --release [evidence-index.edn exception-register.edn]
;;       Enforce the release gate strictly against the real registers.
;;       Exit 1 when the release evidence packet is incomplete.
;;
;; Register paths may be overridden by positional argv (evidence index first,
;; exception register second).
(require ']
         '[clojure.edn :as edn]
         '         '[clojure.string :as str])

(def script-dir (-> *file* __path.resolve .getAbsoluteFile .getParentFile))
(def root (__path.dirname script-dir))
))

(require '[kotoba.security.release-gate :as gate])

(def args (vec *command-line-args*))
(def release? (boolean (some #{"--release"} args)))
(def path-args (vec (remove #{"--release"} args)))

(def evidence-file
  (if (first path-args)
    (__path.resolve (first path-args))
    (__path.resolve root "registers/evidence-index.edn")))

(def exception-file
  (if (second path-args)
    (__path.resolve (second path-args))
    (__path.resolve root "registers/exception-register.edn")))

(def today (.slice (.toISOString (js/Date.)) 0 10))

;; registers/*.edn and conformance/release/{positive,negative}/*.edn were
;; datomic/datascript-ized by edn-datomize.nbb (wrap-map-keep-ns): each file's
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
  (->> (mapv #(__path.join (__path.resolve root dir %) (seq (__fs.readdirSync (__path.resolve root dir))))
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
              (.exit js/process 1))))
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
        (.exit js/process 1))
      (println "ok safe-release gate (advisory mode; use --release to enforce)"))))
