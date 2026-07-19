(ns kotoba.security.information-flow
  "Portable lattice and fail-closed egress/declassification decisions.")

(def ranks {:public 0 :internal 1 :confidential 2 :restricted 3})

(defn join
  "The output of a computation inherits the highest input classification.
  Unknown or missing labels conservatively become :restricted."
  [labels]
  (->> labels
       (map #(if (contains? ranks %) % :restricted))
       (apply max-key ranks :public)))

(defn evaluate-egress
  "Allow monotonic flows. A downgrade requires an exact, unexpired grant bound
  to subject, purpose, source and target classifications."
  [{:keys [subject purpose now input-classifications output-classification
           declassification-grant]}]
  (let [source (join input-classifications)
        target (if (contains? ranks output-classification)
                 output-classification :restricted)
        downgrade? (< (ranks target) (ranks source))
        grant declassification-grant
        valid-grant? (and grant
                          (= subject (:subject grant))
                          (= purpose (:purpose grant))
                          (= source (:from grant))
                          (= target (:to grant))
                          (string? now)
                          (string? (:expires-at grant))
                          (<= (compare now (:expires-at grant)) 0))
        violations (cond-> []
                     (and downgrade? (not valid-grant?))
                     (conj {:information-flow/control :declassification-required
                            :information-flow/message
                            "classification downgrade requires an exact valid grant"}))]
    {:information-flow/allowed? (empty? violations)
     :information-flow/source source
     :information-flow/target target
     :information-flow/downgrade? downgrade?
     :information-flow/grant-id (:id grant)
     :information-flow/violations violations}))
