(ns kotoba.security.resilience
  "Portable compromise telemetry and destructive-restore drill primitives.")

(defn append-telemetry
  "Append one hash-linked immutable event. DIGEST-FN hashes canonical caller
  bytes; ENCODE-FN must deterministically encode plain EDN."
  [events event encode-fn digest-fn]
  (let [previous (:telemetry/hash (peek events))
        entry (assoc event :telemetry/index (count events)
                     :telemetry/previous-hash previous)
        hash (digest-fn (encode-fn entry))]
    (conj (vec events) (assoc entry :telemetry/hash hash))))

(defn telemetry-valid? [events encode-fn digest-fn]
  (loop [remaining events index 0 previous nil]
    (if-let [entry (first remaining)]
      (let [plain (dissoc entry :telemetry/hash)]
        (and (= index (:telemetry/index entry))
             (= previous (:telemetry/previous-hash entry))
             (= (:telemetry/hash entry) (digest-fn (encode-fn plain)))
             (recur (next remaining) (inc index) (:telemetry/hash entry))))
      true)))

(defn destructive-restore-drill!
  "Destroy TARGET, restore from independently located encrypted backups and
  verify the recovered digest. Times are injected monotonic milliseconds.
  RESTORE-FN decrypts one selected backup; DIGEST-FN hashes restored data."
  [{:keys [target backups restore-fn digest-fn clock-ms failure-at-ms
           checkpoint-at-ms rto-limit-ms rpo-limit-ms]}]
  (let [sites (set (map :backup/site backups))
        eligible (filter #(and (:backup/encrypted? %)
                               (:backup/artifact %)
                               (:backup/digest %)) backups)
        expected-digests (set (map :backup/digest eligible))]
    (when-not (and (>= (count sites) 2) (= (count backups) (count eligible))
                   (= 1 (count expected-digests)))
      (throw (ex-info "independent encrypted backups required"
                      {:sites sites :backup-count (count backups)})))
    (let [started (clock-ms)
          _ (reset! target {})
          destroyed? (empty? @target)
          restored (restore-fn (first eligible))
          _ (reset! target restored)
          ended (clock-ms)
          rto-ms (- ended started)
          rpo-ms (- failure-at-ms checkpoint-at-ms)
          digest-ok? (= (first expected-digests) (digest-fn @target))
          passed? (and destroyed? digest-ok?
                       (<= rto-ms rto-limit-ms) (<= rpo-ms rpo-limit-ms))]
      {:restore-drill/status (if passed? :passed :failed)
       :restore-drill/destructive? destroyed?
       :restore-drill/sites sites
       :restore-drill/digest-verified? digest-ok?
       :restore-drill/rto-ms rto-ms :restore-drill/rpo-ms rpo-ms
       :restore-drill/rto-limit-ms rto-limit-ms
       :restore-drill/rpo-limit-ms rpo-limit-ms})))
