# kotoba-lang/security

`kotoba-lang/security` is the governance and assurance layer for the Kotoba
language, runtime, package, and operating-system substrate. It does not replace
implementation-owned ADRs in `kotoba-lang/kotoba-lang`, `kotoba-lang/kotoba`,
or `kotoba-lang/aiueos`; it turns those design decisions into auditable security
claims, standards mappings, test gates, and open gaps.

## Scope

This repository owns:

- security architecture and threat model summaries across Kotoba language,
  Wasm execution, package distribution, identity, storage, and audit;
- standards mappings for NIST CSF 2.0, selected NIST SP 800 controls, DoDAF
  2.02 architecture products, and post-quantum cryptography migration;
- control evidence checklists that point back to implementation tests,
  conformance fixtures, ADRs, and run receipts;
- security acceptance gates for safe Kotoba, package locks, aiueos manifests,
  cryptographic envelopes, and release evidence packets;
- executable gates: a safe-release evidence gate over the evidence index and
  exception register (`src/kotoba/security/release_gate.cljc`) and a FIPS/PQC
  crypto policy over envelopes and the crypto inventory
  (`src/kotoba/security/crypto_policy.cljc`, `policy/crypto-policy.edn`).

This repository does not own:

- compiler implementation details;
- host runtime code;
- production key material;
- operational incident response authority for a deployed organization.

## Current Assessment

Kotoba's design is strong on containment:

- safe Kotoba is a Clojure-shaped, Wasm-first, capability-checked profile;
- host access is intended to be policy-derived and deny-by-default;
- package references are designed to be CID-pinned, signed, and capability
  bounded;
- aiueos enforces manifest capabilities, resource limits, and audited denials;
- private data is intended to put confidentiality at object encryption rather
  than peer trust or selective replication.

The initial assurance design now covers the NIST-class operating concerns that
language design alone cannot cover:

- governance roles, decision classes, cadence, and release sign-off;
- incident response severity, playbooks, and evidence preservation;
- continuous monitoring signals, metrics, alert rules, and retention;
- seeded risk, exception, key, crypto, and evidence registers;
- key lifecycle states, crypto periods, separation, and revocation;
- FIPS validation non-claim and deployment-boundary evidence requirements;
- SBOM/SLSA release artifact requirements;
- operational evidence packet requirements.

Implementation and compliance evidence remain incomplete:

- package lock enforcement, signer revocation, key expiry, and registry
  verification still need end-to-end implementation gates;
- PQC is designed as a crypto-agility and hybrid migration path, not yet
  implemented end-to-end;
- continuous monitoring and IR drills need live deployment evidence;
- formal verification and side-channel defenses are not present;
- FIPS validation is not claimed without a named validated module boundary.

## Documents

- [Security Architecture](docs/security-architecture.md)
- [Architecture Review 2026-07-01](docs/architecture-review-2026-07-01.md)
- [Standards Assessment](docs/standards-assessment.md)
- [Security Governance](docs/governance.md)
- [Incident Response](docs/incident-response.md)
- [Continuous Monitoring](docs/continuous-monitoring.md)
- [Risk Management](docs/risk-management.md)
- [Key Lifecycle](docs/key-lifecycle.md)
- [Production Key Ops](docs/key-ops-production.md)
- [Deployment Profiles](docs/deployment-profiles.md)
- [FIPS Validation Strategy](docs/fips-validation.md)
- [SBOM and SLSA Provenance](docs/sbom-slsa.md)
- [Operational Evidence](docs/operational-evidence.md)
- [PQC Roadmap](docs/pqc-roadmap.md)
- [DoDAF Viewpoints](docs/dodaf-viewpoints.md)
- [Evidence Gates](docs/evidence-gates.md)
- [Hybrid Envelope Test Vectors](docs/hybrid-envelope-vectors.md)

## Registers

- [Risk Register](registers/risk-register.edn)
- [Exception Register](registers/exception-register.edn)
- [Key Register](registers/key-register.edn)
- [Crypto Inventory](registers/crypto-inventory.edn)
- [Evidence Index](registers/evidence-index.edn)
- [Architecture Review Findings](registers/architecture-review-findings.edn)

## Verify

Run the tests and gates from the repo root (CI runs the same commands):

```sh
clojure -M:test                                              # unit + fixture tests
nbb --classpath src scripts/check-safe-release.cljs          # fixture matrix + advisory
nbb --classpath src scripts/check-safe-release.cljs --release --profile research
nbb --classpath src scripts/check-key-register.cljs          # active/blocked/problems
nbb --classpath src scripts/check-key-register.cljs --require-active  # regulated: need :active key
nbb --classpath src scripts/check-key-lifecycle-drill.cljs   # pure/synthetic revoke drill (R-002/R-005)
nbb --classpath src scripts/check-crypto-inventory.cljs      # crypto inventory vs policy
```

Production key path (public material only; secrets out-of-band): see
[docs/key-ops-production.md](docs/key-ops-production.md).
IR drill evidence: `evidence/2026-07-17/ir-tabletop-compromised-signer.edn`,
`evidence/2026-07-17/ir-technical-key-revoke-drill.edn`.

`nbb --classpath src scripts/check-safe-release.cljs --release` enforces the
release evidence packet strictly (kotoba-lang/kotoba#265): every required claim
— `:conformance-results`, `:package-verification`, `:sbom`, `:provenance`,
`:key-status-snapshot`, `:risk-review` — must be backed by evidence in
`registers/evidence-index.edn` or covered by an unexpired, owned entry in
`registers/exception-register.edn`, otherwise it exits non-zero.

Add `--profile regulated` to also hard-require the `:deployment-profile` claim
and a key-register with at least one `:active` key (template keys are
`:pre-active` and will fail until operators promote after out-of-band secret
provisioning — see [docs/key-lifecycle.md](docs/key-lifecycle.md)).

## Primary Design Inputs

- `kotoba-lang/kotoba-lang/docs/adr/ADR-safe-capability-language.md`
- `kotoba-lang/kotoba-lang/docs/adr/ADR-kotoba-package-cid-lock.md`
- `kotoba-lang/kotoba-lang/docs/adr/ADR-kotoba-rad-git-sovereign-repo.md`
- `kotoba-lang/kotoba/docs/SECURITY-ARCHITECTURE.md`
- `kotoba-lang/aiueos/SECURITY.md`
- `90-docs/adr/2606271600-kotoba-stack-equivalences.edn`
