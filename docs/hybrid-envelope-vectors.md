# Hybrid Envelope Test Vectors

Status: contract defined, vectors pending
Date: 2026-07-02

## Purpose

The PQC roadmap (docs/pqc-roadmap.md) requires a test fixture proving hybrid
key wrapping and epoch rotation: object/key wrapping migrates from
X25519/HPKE to hybrid X25519 + ML-KEM. This document defines the test-vector
file contract so that the crypto implementation and the conformance suite can
be developed against the same shape.

## Vector File Contract

Vector files live at `conformance/crypto/vectors/*.edn`, one vector per file.
Each vector is an EDN map with the following fields:

```edn
{:vector/id "hybrid-x25519-ml-kem-768-0001"
 :vector/epoch 1
 :vector/kem [:x25519 :ml-kem-768]
 :vector/inputs {:x25519/recipient-public "hex:..."
                 :x25519/ephemeral-secret "hex:..."
                 :ml-kem/encapsulation-key "hex:..."
                 :ml-kem/randomness "hex:..."
                 :plaintext-key "hex:..."}
 :vector/expected {:wrapped-key "hex:..."
                   :shared-secret "hex:..."
                   :envelope {:envelope/algorithms [:x25519 :ml-kem-768 :aes-256-gcm]
                              :envelope/epoch 1
                              :envelope/kem? true
                              :envelope/hybrid? true}}}
```

- `:vector/id` — stable unique string id.
- `:vector/epoch` — encryption epoch the vector exercises; vectors with
  epoch >= the policy `:hybrid-epoch-floor` must be hybrid.
- `:vector/kem` — the KEM combination, `[:x25519 :ml-kem-768]` for the
  hybrid target.
- `:vector/inputs` — deterministic inputs (keys, encapsulation randomness,
  plaintext key material) as hex strings so the wrapping is reproducible.
- `:vector/expected` — expected wrapped key, derived shared secret, and the
  envelope metadata the wrapper must emit; the emitted envelope must pass
  `kotoba.security.crypto-policy/check-envelope` under `:hybrid-required`.

## Follow-Up

Real vector values require the hybrid wrapping implementation (do not
hand-roll ML-KEM; use a standard implementation per docs/pqc-roadmap.md
non-goals). Until that implementation exists, this directory carries no
vector files, and the claim "PQC migration is ready" in
docs/evidence-gates.md remains open.
