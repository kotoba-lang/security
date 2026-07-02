(ns kotoba.security.release-gate
  "Safe-release evidence gate (kotoba-lang/kotoba#265).

  A release is safe to cut only when every claim of the release evidence
  packet (docs/operational-evidence.md) is either backed by evidence in the
  evidence index or covered by an unexpired, owned entry in the exception
  register."
  (:require [clojure.string :as str]))

(def required-claims
  [:conformance-results
   :package-verification
   :sbom
   :provenance
   :key-status-snapshot
   :risk-review])

(defn non-empty-string?
  [x]
  (and (string? x) (not (str/blank? x))))

(defn iso-date?
  [x]
  (and (non-empty-string? x)
       (some? (re-matches #"\d{4}-\d{2}-\d{2}" x))))

(defn register-problems
  [register expected-type register-name]
  (cond-> []
    (not= expected-type (:register/type register))
    (conj {:problem :register-type-mismatch
           :register register-name
           :expected expected-type
           :actual (:register/type register)})

    (not= 1 (:register/version register))
    (conj {:problem :register-version-unsupported
           :register register-name
           :actual (:register/version register)})))

(defn claim-satisfied?
  "True when at least one evidence entry claims `claim` and its
  :evidence/result is not :failed."
  [evidence claim]
  (boolean
   (some (fn [entry]
           (and (some #{claim} (:evidence/claims entry))
                (not= :failed (:evidence/result entry))))
         evidence)))

(defn well-formed-exception?
  "Malformed exception entries (missing owner or expires) never excuse
  anything."
  [exception]
  (and (non-empty-string? (:exception/id exception))
       (keyword? (:exception/claim exception))
       (non-empty-string? (:exception/owner exception))
       (iso-date? (:exception/expires exception))
       (non-empty-string? (:exception/reason exception))))

(defn unexpired?
  [exception now]
  (>= (compare (:exception/expires exception) now) 0))

(defn active-exception
  "Returns the first well-formed, unexpired exception covering `claim`."
  [exceptions claim now]
  (some (fn [exception]
          (when (and (well-formed-exception? exception)
                     (= claim (:exception/claim exception))
                     (unexpired? exception now))
            exception))
        exceptions))

(defn malformed-exception-problems
  [exceptions]
  (into []
        (keep (fn [exception]
                (when-not (well-formed-exception? exception)
                  {:problem :malformed-exception
                   :exception exception})))
        exceptions))

(defn evaluate-release
  "Evaluates the release evidence packet.

  Input: {:evidence-index <parsed registers/evidence-index.edn>
          :exception-register <parsed registers/exception-register.edn>
          :now \"YYYY-MM-DD\"}

  Output: {:kotoba.release/ok? bool
           :kotoba.release/missing [claim ...]
           :kotoba.release/excepted [{:claim .. :exception/id .. :exception/expires ..} ...]
           :kotoba.release/problems [{:problem ..} ...]}"
  [{:keys [evidence-index exception-register now]}]
  (let [problems (-> []
                     (into (register-problems evidence-index
                                              :kotoba.security/evidence-index
                                              :evidence-index))
                     (into (register-problems exception-register
                                              :kotoba.security/exception-register
                                              :exception-register))
                     (into (malformed-exception-problems
                            (:exceptions exception-register))))
        evidence (:evidence evidence-index)
        exceptions (:exceptions exception-register)
        verdict (reduce
                 (fn [acc claim]
                   (if (claim-satisfied? evidence claim)
                     acc
                     (if-let [exception (active-exception exceptions claim now)]
                       (update acc :excepted conj
                               {:claim claim
                                :exception/id (:exception/id exception)
                                :exception/expires (:exception/expires exception)})
                       (update acc :missing conj claim))))
                 {:missing [] :excepted []}
                 required-claims)]
    {:kotoba.release/ok? (and (empty? (:missing verdict))
                              (empty? problems))
     :kotoba.release/missing (:missing verdict)
     :kotoba.release/excepted (:excepted verdict)
     :kotoba.release/problems problems}))
