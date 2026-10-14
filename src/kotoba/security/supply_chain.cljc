(ns kotoba.security.supply-chain
  "Fail-closed reproducibility, SBOM, and provenance qualification."
  (:require [clojure.string :as str]))

(def commit-pattern #"[0-9a-f]{40}")

(defn- digest? [value]
  (and (string? value) (str/starts-with? value "sha256:")
       (< 7 (count value))))

(defn evaluate-reproducibility
  [{:keys [fresh-clone? hermetic? local-overrides? source-commit
           first-artifact-digest second-artifact-digest dependencies]}]
  (let [violations
        (cond-> []
          (not= true fresh-clone?) (conj :fresh-clone)
          (not= true hermetic?) (conj :hermetic-build)
          (not= false local-overrides?) (conj :local-overrides)
          (not (and (string? source-commit)
                    (re-matches commit-pattern source-commit)))
          (conj :source-commit)
          (not (and (digest? first-artifact-digest)
                    (= first-artifact-digest second-artifact-digest)))
          (conj :artifact-reproducibility)
          (empty? dependencies) (conj :dependencies)
          (some #(not (and (string? (:dependency/repository %))
                           (str/starts-with? (:dependency/repository %) "https://")
                           (string? (:dependency/commit %))
                           (re-matches commit-pattern (:dependency/commit %))
                           (= :passed (:dependency/exact-fetch %))))
                dependencies)
          (conj :dependency-transparency))]
    {:reproducibility/qualified? (empty? violations)
     :reproducibility/artifact-digest first-artifact-digest
     :reproducibility/source-commit source-commit
     :reproducibility/violations violations}))

(defn- signature-valid? [verify-fn document signature-key]
  (and (ifn? verify-fn)
       (try
         (true? (verify-fn (dissoc document signature-key)
                           (get document signature-key)))
         (catch #?(:clj Exception :cljs :default) _ false))))

(defn evaluate-attestations
  [{:keys [sbom provenance]}
   {:keys [artifact-digest source-commit verify-sbom-signature-fn
           verify-provenance-signature-fn]}]
  (let [violations
        (cond-> []
          (not= 1 (:sbom/version sbom)) (conj :sbom-version)
          (not= artifact-digest (:sbom/artifact-digest sbom))
          (conj :sbom-artifact-binding)
          (not= source-commit (get-in sbom [:sbom/subject :commit]))
          (conj :sbom-source-binding)
          (empty? (:sbom/components sbom)) (conj :sbom-components)
          (not (digest? (:sbom/generator-digest sbom))) (conj :sbom-generator)
          (not (signature-valid? verify-sbom-signature-fn sbom :sbom/signature))
          (conj :sbom-signature)
          (not= 1 (:provenance/version provenance)) (conj :provenance-version)
          (not= artifact-digest (:provenance/artifact-digest provenance))
          (conj :provenance-artifact-binding)
          (not= source-commit (:provenance/source-commit provenance))
          (conj :provenance-source-binding)
          (not= (:sbom/digest sbom) (:provenance/sbom-digest provenance))
          (conj :provenance-sbom-binding)
          (not= true (:provenance/isolated-builder? provenance))
          (conj :isolated-builder)
          (not (digest? (:provenance/invocation-digest provenance)))
          (conj :invocation-binding)
          (not (signature-valid? verify-provenance-signature-fn
                                 provenance :provenance/signature))
          (conj :provenance-signature))]
    {:attestation/qualified? (empty? violations)
     :attestation/violations violations
     :attestation/artifact-digest artifact-digest}))
