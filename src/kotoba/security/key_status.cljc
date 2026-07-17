(ns kotoba.security.key-status
  "Key-register evaluation for R-002 (signer revocation / key expiry).

  A key may only authorize NEW package artifacts when its `:key/status` is
  `:active`. Historical verification of past receipts can use `:retired`
  keys elsewhere; admission of new locks must not."
  (:require [clojure.string :as str]))

(def allowed-for-new-artifacts
  #{:active})

(def blocked-for-new-artifacts
  #{:revoked :expired :compromised :retired :pre-active})

(defn non-empty-string?
  [x]
  (and (string? x) (not (str/blank? x))))

(defn key-id
  [k]
  (or (:key/id k) (:key/signer k)))

(defn blocked-key?
  [k]
  (contains? blocked-for-new-artifacts (:key/status k)))

(defn active-key?
  [k]
  (contains? allowed-for-new-artifacts (:key/status k)))

(defn blocked-signer-ids
  "Set of key/signer ids that must not sign new artifacts."
  [key-register]
  (into #{}
        (keep (fn [k]
                (when (blocked-key? k)
                  (key-id k))))
        (or (:keys key-register) [])))

(defn active-signer-ids
  [key-register]
  (into #{}
        (keep (fn [k]
                (when (active-key? k)
                  (key-id k))))
        (or (:keys key-register) [])))

(defn evaluate-key-register
  "Summarize a key-register for release evidence / admission.

  Returns
  {:kotoba.key/ok? bool  ;; true when every key has a known status and
                         ;; at least one :active key exists when keys are present
   :kotoba.key/blocked [id ...]
   :kotoba.key/active [id ...]
   :kotoba.key/problems [{:problem ..} ...]}"
  [key-register]
  (let [keys (or (:keys key-register) [])
        problems (cond-> []
                   (and (map? key-register)
                        (not= :kotoba.security/key-register
                              (:register/type key-register))
                        (some? (:register/type key-register)))
                   (conj {:problem :key-register-type-mismatch
                          :actual (:register/type key-register)}))
        unknown (into []
                      (keep (fn [k]
                              (when-not (or (active-key? k) (blocked-key? k))
                                {:problem :unknown-key-status
                                 :key/id (key-id k)
                                 :key/status (:key/status k)})))
                      keys)
        blocked (vec (blocked-signer-ids key-register))
        active (vec (active-signer-ids key-register))
        problems (into problems unknown)
        problems (cond-> problems
                   (and (seq keys) (empty? active))
                   (conj {:problem :no-active-signing-key}))]
    {:kotoba.key/ok? (empty? problems)
     :kotoba.key/blocked blocked
     :kotoba.key/active active
     :kotoba.key/problems problems}))

(defn snapshot-for-evidence
  "Machine-readable key-status snapshot map suitable for evidence packets."
  [key-register now]
  (let [eval (evaluate-key-register key-register)]
    (merge eval
           {:kotoba.key/checked-at now
            :kotoba.key/register-version (:register/version key-register)})))
