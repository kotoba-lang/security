(ns kotoba.security.transport
  "Fail-closed deployment transport profile checks shared by host adapters.")

(defn evaluate
  [{:keys [protocol mutual-auth? peer-id expected-peer-id
           certificate-fingerprint trusted-fingerprints revocation-checked?
           now certificate-not-before certificate-expires-at
           next-certificate-fingerprint require-rotation-overlap?]}]
  (let [violations
        (cond-> []
          (not= :tls-1.3 protocol)
          (conj {:transport/control :tls-version :transport/message "TLS 1.3 required"})
          (not= true mutual-auth?)
          (conj {:transport/control :mutual-auth :transport/message "mutual authentication required"})
          (or (nil? peer-id) (not= peer-id expected-peer-id))
          (conj {:transport/control :peer-identity :transport/message "peer identity mismatch"})
          (or (nil? certificate-fingerprint)
              (not (contains? (set trusted-fingerprints) certificate-fingerprint)))
          (conj {:transport/control :certificate-trust :transport/message "certificate fingerprint is not trusted"})
          (not= true revocation-checked?)
          (conj {:transport/control :revocation :transport/message "certificate revocation was not checked"})
          (or (not (string? now))
              (and certificate-not-before
                   (pos? (compare certificate-not-before now)))
              (and certificate-expires-at
                   (neg? (compare certificate-expires-at now))))
          (conj {:transport/control :certificate-validity :transport/message "certificate is outside validity window"})
          (and require-rotation-overlap? (nil? next-certificate-fingerprint))
          (conj {:transport/control :rotation-overlap :transport/message "next certificate is not staged"}))]
    {:transport/allowed? (empty? violations)
     :transport/violations violations
     :transport/peer-id peer-id
     :transport/certificate-fingerprint certificate-fingerprint
     :transport/next-certificate-fingerprint next-certificate-fingerprint}))

(defn rotation-state [current]
  {:rotation/current current :rotation/staged nil :rotation/previous nil
   :rotation/trusted #{current} :rotation/revoked #{} :rotation/events []})

(defn stage [state next-certificate at]
  (when (or (nil? next-certificate)
            (= next-certificate (:rotation/current state))
            (contains? (:rotation/revoked state) next-certificate))
    (throw (ex-info "invalid next certificate" {:certificate next-certificate})))
  (-> state
      (assoc :rotation/staged next-certificate)
      (update :rotation/trusted conj next-certificate)
      (update :rotation/events conj {:event :stage :certificate next-certificate :at at})))

(defn promote [state at]
  (let [next-certificate (:rotation/staged state)]
    (when-not (contains? (:rotation/trusted state) next-certificate)
      (throw (ex-info "staged certificate is not trusted" {})))
    (-> state
        (assoc :rotation/previous (:rotation/current state)
               :rotation/current next-certificate :rotation/staged nil)
        (update :rotation/events conj {:event :promote :certificate next-certificate :at at}))))

(defn revoke-previous [state at]
  (let [previous (:rotation/previous state)]
    (when-not previous (throw (ex-info "no previous certificate" {})))
    (-> state
        (update :rotation/trusted disj previous)
        (update :rotation/revoked conj previous)
        (update :rotation/events conj {:event :revoke :certificate previous :at at}))))

(defn rollback [state certificate at]
  (when (contains? (:rotation/revoked state) certificate)
    (throw (ex-info "rollback to revoked certificate denied"
                    {:certificate certificate :at at})))
  (when-not (contains? (:rotation/trusted state) certificate)
    (throw (ex-info "rollback certificate is not trusted" {:certificate certificate})))
  (-> state
      (assoc :rotation/previous (:rotation/current state)
             :rotation/current certificate)
      (update :rotation/events conj {:event :rollback :certificate certificate :at at})))

(defn rotation-drill
  "Execute overlap, promotion, old-certificate revocation and a required
  negative rollback attempt. Returns a reproducible operational receipt."
  [{:keys [current next staged-at promoted-at revoked-at rollback-tested-at]}]
  (let [final-state (-> (rotation-state current)
                        (stage next staged-at)
                        (promote promoted-at)
                        (revoke-previous revoked-at))
        rollback-denied?
        (try (rollback final-state current rollback-tested-at) false
             (catch #?(:clj Exception :cljs :default) _ true))]
    {:rotation-drill/status (if rollback-denied? :passed :failed)
     :rotation-drill/current (:rotation/current final-state)
     :rotation-drill/revoked (:rotation/revoked final-state)
     :rotation-drill/rollback-denied? rollback-denied?
     :rotation-drill/events (:rotation/events final-state)}))
