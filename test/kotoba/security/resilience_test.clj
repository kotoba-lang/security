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
                             :backup/artifact "cipher-a" :backup/digest expected}
                            {:backup/site :region-b :backup/encrypted? true
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
    (is (= data @target))))

(deftest same-site-or-unencrypted-backups-fail-closed
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo #"independent encrypted backups"
       (resilience/destructive-restore-drill!
        {:target (atom {:x 1})
         :backups [{:backup/site :one :backup/encrypted? false
                    :backup/artifact "plain" :backup/digest "x"}]}))))
