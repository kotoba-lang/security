# Continuous Monitoring

Status: proposed baseline
Date: 2026-07-01

## Purpose

Monitoring must prove that Kotoba's intended security controls are active in
real deployments. A denied capability, trap, signer failure, or failed
conformance gate is a security signal, not just an application log.

## Signals

| Signal | Source | Minimum fields |
|---|---|---|
| Capability grant | aiueos broker / runtime | component, capability, resource, policy, receipt id |
| Capability denial | aiueos broker / runtime | component, attempted capability, reason, policy |
| Host trap | Wasm runtime | component, trap kind, fuel/memory state |
| Safe-build result | compiler gate | source CID, policy CID, component CID, gate status |
| Package verification | registry/installer | package, repo RID, signer, manifest CID, result |
| Key event | custody/KMS | key id, epoch, action, actor, receipt |
| Audit write failure | audit sink | sink id, queue length, last successful receipt |
| Crypto policy violation | envelope verifier | object id, algorithm, policy, decision |
| CI evidence failure | CI | gate, commit, artifact, failure digest |

## Metrics

- count of denied host calls by capability and component;
- count of successful grants by resource class;
- safe-build failure rate by gate class;
- package verification failures by signer/repo;
- unsigned or classical-only artifacts by release;
- audit sink lag and failed receipt writes;
- key rotation age and expired key count;
- unresolved critical/high risk count;
- incident mean time to triage and closure.

## Alert Rules

| Alert | Severity |
|---|---|
| host import bound without matching policy grant | SEV-1 |
| unauthorized key release or missing key-release receipt | SEV-1 |
| trusted signer verification failure for released artifact | SEV-1 |
| safe-build bypass suspected in released artifact | SEV-1 |
| package lock contains unsigned or CID-missing dependency in safe path | SEV-2 |
| audit sink unable to persist receipts for more than one release/run window | SEV-2 |
| key exceeds crypto period or expired signer still trusted | SEV-2 |
| SBOM/provenance missing from release candidate | SEV-3 |

## Evidence Retention

| Evidence | Retention |
|---|---|
| release SBOM/provenance/security note | life of release plus 7 years |
| incidents and postmortems | 7 years |
| access/key release receipts | data retention period of protected object |
| CI conformance evidence | 1 year minimum |
| monitoring aggregates | 1 year minimum |
| raw debug logs | shortest period compatible with privacy and forensics |

## Implementation Requirements

- Every monitor event must include a stable run or artifact id.
- Security events must be exportable as EDN and JSON.
- Alerts must link to evidence index entries.
- Monitoring must not require plaintext access to protected objects.
- Monitoring failures are themselves audit events.

