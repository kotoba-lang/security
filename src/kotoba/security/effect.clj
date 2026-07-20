(ns kotoba.security.effect
  "One-shot, opaque authorization binding a control decision to an effect."
  (:import [java.util Collections IdentityHashMap]))

(defonce ^:private grants
  (Collections/synchronizedMap (IdentityHashMap.)))

(defn issue!
  "Evaluate REQUEST and return an opaque, one-shot grant only when APPROVED?
  accepts the evaluator result. Claims bind the grant to an action, resource,
  and optional digest."
  [{:keys [evaluate request approved? action resource digest]}]
  (let [decision (evaluate request)]
    (when-not (approved? decision)
      (throw (ex-info "effect authorization denied"
                      {:security.effect/problem :decision-denied})))
    (let [grant (Object.)]
      (.put grants grant {:action action :resource resource :digest digest})
      grant)))

(defn consume!
  "Consume GRANT exactly once and run EFFECT only when all bound claims match."
  [grant {:keys [action resource digest effect]}]
  (let [claims (.remove grants grant)]
    (when-not claims
      (throw (ex-info "effect authorization denied"
                      {:security.effect/problem :invalid-or-consumed-grant})))
    (when-not (= claims {:action action :resource resource :digest digest})
      (throw (ex-info "effect authorization denied"
                      {:security.effect/problem :claim-mismatch})))
    (effect)))

(defn guard!
  "Evaluate, bind, consume, and execute an effect without exposing a bypass gap."
  [{:keys [action resource digest effect] :as request}]
  (consume! (issue! request)
            {:action action :resource resource :digest digest :effect effect}))
