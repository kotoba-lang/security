(ns kotoba.security.resilience-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.security.resilience :as resilience]))

(defn encode [x] (.getBytes (pr-str x) "UTF-8"))
(defn digest [x]
  (let [bytes (if (bytes? x) x (encode x))]
    (format "%064x" (BigInteger. 1 (.digest (java.security.MessageDigest/getInstance "SHA-256") bytes)))))

(deftest remote-telemetry-chain-detects-rewrite
  (let [events (-> []
                   (resilience/append-telemetry {:event :detect} encode digest)
                   (resilience/append-telemetry {:event :contain} encode digest))]
    (is (resilience/telemetry-valid? events encode digest))
    (is (false? (resilience/telemetry-valid?
                 (assoc-in events [0 :event] :forged) encode digest)))))

(deftest destructive-geo-restore-measures-rto-and-rpo
  (let [data {:vault {:ciphertext "sealed"} :revision 42}
        expected (digest data)
        target (atom data)
        ticks (atom [1000 1042])
        receipt (resilience/destructive-restore-drill!
                 {:target target
                  :backups [{:backup/site :region-a :backup/encrypted? true
                             :backup/immutable? true
                             :backup/artifact "cipher-a" :backup/digest expected}
                            {:backup/site :region-b :backup/encrypted? true
                             :backup/immutable? true
                             :backup/artifact "cipher-b" :backup/digest expected}]
                  :restore-fn (fn [_] data) :digest-fn digest
                  :clock-ms #(let [v (first @ticks)] (swap! ticks subvec 1) v)
                  :checkpoint-at-ms 900 :failure-at-ms 950
                  :rto-limit-ms 100 :rpo-limit-ms 60})]
    (is (= :passed (:restore-drill/status receipt)))
    (is (:restore-drill/destructive? receipt))
    (is (:restore-drill/digest-verified? receipt))
    (is (= 42 (:restore-drill/rto-ms receipt)))
    (is (= 50 (:restore-drill/rpo-ms receipt)))
    (is (:restore-drill/qualified?
         (resilience/evaluate-restore-receipt receipt expected)))
    (is (= data @target))))

(deftest restore-receipt-rejects-every-critical-claim-failure
  (let [digest "sha256:artifact"
        receipt {:restore-drill/status :passed
                 :restore-drill/destructive? true
                 :restore-drill/sites #{:region-a :region-b}
                 :restore-drill/backups-encrypted? true
                 :restore-drill/backups-immutable? true
                 :restore-drill/artifact-digest digest
                 :restore-drill/digest-verified? true
                 :restore-drill/rto-ms 40 :restore-drill/rto-limit-ms 100
                 :restore-drill/rpo-ms 20 :restore-drill/rpo-limit-ms 60}]
    (is (:restore-drill/qualified?
         (resilience/evaluate-restore-receipt receipt digest)))
    (doseq [bad [(assoc receipt :restore-drill/status :failed)
                 (assoc receipt :restore-drill/destructive? false)
                 (assoc receipt :restore-drill/sites #{:region-a})
                 (assoc receipt :restore-drill/backups-encrypted? false)
                 (assoc receipt :restore-drill/backups-immutable? false)
                 (assoc receipt :restore-drill/digest-verified? false)
                 (assoc receipt :restore-drill/artifact-digest "sha256:other")
                 (assoc receipt :restore-drill/rto-ms 101)
                 (assoc receipt :restore-drill/rpo-ms 61)]]
      (is (false? (:restore-drill/qualified?
                   (resilience/evaluate-restore-receipt bad digest)))))))

(deftest same-site-or-unencrypted-backups-fail-closed
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo #"independent encrypted backups"
       (resilience/destructive-restore-drill!
        {:target (atom {:x 1})
         :backups [{:backup/site :one :backup/encrypted? false
                    :backup/artifact "plain" :backup/digest "x"}]}))))

(deftest remote-telemetry-rejects-local-or-forged-ack
  (let [base {:events [] :event {:kind :compromise}
              :encode-fn encode :digest-fn digest
              :verify-ack-fn #(= :valid (:signature %))}
        append (fn [entry]
                 {:telemetry/hash (:telemetry/hash entry)
                  :telemetry/remote? true :telemetry/immutable? true
                  :signature :valid})]
    (is (= 1 (count (:telemetry/events
                     (resilience/append-remote-telemetry!
                      (assoc base :append-fn append))))))
    (is (thrown? clojure.lang.ExceptionInfo
                 (resilience/append-remote-telemetry!
                  (assoc base :append-fn
                         #(assoc (append %) :telemetry/remote? false)))))
    (is (thrown? clojure.lang.ExceptionInfo
                 (resilience/append-remote-telemetry!
                  (assoc base :append-fn #(assoc (append %) :signature :forged)))))))

(deftest containment-stops-on-first-failed-authority
  (let [called (atom [])
        actions (into {}
                      (map (fn [step]
                             [step #(do (swap! called conj step)
                                        {:status (if (= step :freeze-writes)
                                                   :failed :passed)})]))
                      resilience/containment-order)
        result (resilience/contain! actions)]
    (is (= :failed (:containment/status result)))
    (is (= :freeze-writes (:containment/failed-step result)))
    (is (= [:isolate-workload :revoke-credentials :freeze-writes] @called))))

(deftest geo-backups-require-distinct-failure-domains
  (let [backup {:backup/encrypted? true :backup/immutable? true
                :backup/artifact-digest "sha256:x"}]
    (is (:backup/qualified?
         (resilience/qualify-backup-sites
          [(assoc backup :backup/region :jp-east)
           (assoc backup :backup/region :jp-west)])))
    (is (false? (:backup/qualified?
                 (resilience/qualify-backup-sites
                  [(assoc backup :backup/region :jp-east)
                   (assoc backup :backup/region :jp-east)]))))))
