# Post-Quantum Cryptography Roadmap

Status: proposed baseline
Date: 2026-07-01

## Objective

Kotoba should become crypto-agile before replacing all classical cryptography.
The first milestone is to make every cryptographic envelope, manifest, receipt,
and identity proof carry enough metadata to migrate.

## Target Algorithms

| Use | Classical today | PQ target | Migration form |
|---|---|---|---|
| Object/key wrapping | X25519/HPKE | ML-KEM | hybrid X25519 + ML-KEM |
| Package/component signatures | Ed25519 | ML-DSA | hybrid Ed25519 + ML-DSA |
| Long-lived fallback signatures | Ed25519 | SLH-DSA | optional detached SLH-DSA backup |
| Content hashing | SHA-256 multihash | hash-agile multihash | keep algorithm-tagged CID |

## Required Metadata

Every encrypted or signed security object should carry:

```edn
{:crypto/format 1
 :crypto/alg [...]
 :crypto/hash [...]
 :crypto/sig [...]
 :crypto/kem [...]
 :crypto/key-id "..."
 :crypto/recipient-set [...]
 :crypto/epoch 0
 :crypto/created-at "..."}
```

## Priority Order

1. Inventory all cryptographic uses: DID keys, CACAO verification, package
   signatures, manifests, custody grants, sealed object envelopes, audit commit
   signatures, transport keys.
2. Add algorithm-tagged envelope metadata without changing algorithms.
3. Add hybrid detached signatures for package manifests and component releases.
4. Add hybrid KEM wrapping for new object encryption epochs.
5. Add verification policy: accept classical, prefer hybrid, require hybrid for
   long-lived confidential content.
6. Re-encrypt high-value long-retention blobs into PQ/hybrid epochs.
7. Add revocation/expiry and key-status checks to signer registries.

## Non-Goals

- Do not invent new PQ algorithms.
- Do not hand-roll ML-KEM, ML-DSA, or SLH-DSA.
- Do not claim FIPS compliance unless using validated modules in the deployed
  boundary and retaining validation evidence.
- Do not migrate short-lived transport first if long-lived encrypted blobs are
  still classical-only.

## Acceptance Gates

- `crypto-inventory.edn` exists and is generated or checked in CI.
- New encrypted object envelopes contain algorithm metadata.
- Package manifest signatures support multiple algorithms.
- Verification policy can reject classical-only signatures for selected trust
  tiers.
- A test fixture proves hybrid key wrapping and epoch rotation.

