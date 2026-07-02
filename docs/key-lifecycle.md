# Key Lifecycle

Status: proposed baseline
Date: 2026-07-01

## Purpose

Kotoba uses keys for package/component signing, DID/CACAO verification,
encrypted object wrapping, custody grants, audit commits, and transport. These
uses must be separated, inventoried, rotated, and revocable.

## Key Classes

| Class | Use | Default status |
|---|---|---|
| package-signing | package manifests, component releases | required before safe execution |
| identity-delegation | DID/CACAO verification relationships | required for delegated access |
| object-wrapping | envelope encryption recipient keys | required for private data |
| custody-share | t-of-N key share wrapping/release | required for sealed cold tier |
| audit-signing | commit/receipt signing | required for non-repudiation |
| transport | session security | deployment-specific |

## Lifecycle States

```text
pre-active -> active -> suspended -> retired -> destroyed
                         -> compromised
```

State rules:

- `pre-active`: generated but not trusted for verification.
- `active`: may sign, wrap, or verify according to class policy.
- `suspended`: verify only while incident review is pending.
- `retired`: verify historical artifacts only; cannot sign or wrap new data.
- `destroyed`: private material destroyed; public verification metadata retained.
- `compromised`: reject new artifacts and assess historical impact.

## Crypto Periods

Initial target crypto periods:

| Key class | Signing/wrapping period | Verification/retention |
|---|---|---|
| package-signing | 90 days for release keys | life of release plus 7 years |
| identity-delegation | 90 days for delegated grants | grant lifetime plus audit retention |
| object-wrapping | per data epoch, rotate on access-policy change | protected object retention |
| custody-share | per deal/epoch | protected object retention |
| audit-signing | 180 days | audit retention period |
| transport | short-lived sessions | not used for long-term proof |

## Separation Rules

- A package signing key must not wrap object encryption keys.
- An audit signing key must not authorize runtime capabilities.
- Transport keys must not be used for artifact provenance.
- Custody share keys must be scoped to custodian identity and epoch.
- PQ/hybrid keys must carry algorithm metadata and policy status.

## Revocation

Revocation requires:

- key id and class;
- revocation reason;
- effective time;
- affected artifacts or object epochs;
- replacement key id if any;
- evidence index entry.

Runtime and package verifiers must treat revoked package-signing keys as invalid
for new artifacts. Historical artifacts require incident-specific assessment.

## FIPS Boundary

If a deployment claims FIPS compliance, key generation, signing, encryption, and
randomness must occur inside the validated cryptographic module boundary for the
claimed control. The default repository design does not claim this.

