(ns kotoba.security.hardware
  "Fail-closed HSM/native-keystore qualification evidence checks.")

(defn evaluate
  [{:keys [provider-id hardware-backed? attestation-verified?
           private-exported? sign-verified? kem-verified?
           rotation-drill-passed? outage-failed-closed?]}]
  (let [violations
        (cond-> []
          (nil? provider-id) (conj :provider-id)
          (not= true hardware-backed?) (conj :hardware-backed)
          (not= true attestation-verified?) (conj :attestation)
          (not= false private-exported?) (conj :private-export)
          (not= true sign-verified?) (conj :sign-operation)
          (not= true kem-verified?) (conj :kem-operation)
          (not= true rotation-drill-passed?) (conj :rotation-drill)
          (not= true outage-failed-closed?) (conj :outage-fail-closed))]
    {:hardware/qualified? (empty? violations)
     :hardware/provider-id provider-id
     :hardware/violations violations}))
