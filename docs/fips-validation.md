# FIPS Validation Strategy

Status: proposed baseline
Date: 2026-07-01

## Verdict

Kotoba must not claim FIPS validation today. The current design can be made
FIPS-aligned, but FIPS validation depends on deployed cryptographic modules,
module boundaries, algorithms, operating modes, and retained validation
evidence.

## Required Distinctions

| Term | Meaning for Kotoba |
|---|---|
| FIPS-approved algorithm | algorithm is allowed by FIPS/NIST guidance |
| FIPS-validated module | implementation and module boundary have validation certificate |
| FIPS mode | deployed module is configured to operate in approved mode |
| Kotoba compliance claim | only valid for a named deployment boundary |

Using AES-GCM, SHA-256, Ed25519, ML-KEM, or ML-DSA in source code does not by
itself create a FIPS-validated system.

## Crypto Boundary Inventory

Every deployment that wants a FIPS claim must identify:

- cryptographic module name and version;
- validation certificate id;
- operating system/platform;
- approved mode configuration;
- key generation boundary;
- signing/encryption/wrapping boundary;
- random source;
- logs proving the boundary was used.

## Kotoba Design Requirements

- abstract crypto providers behind capability interfaces;
- record crypto provider and module metadata in envelopes and receipts;
- fail closed when a policy requires FIPS mode and the provider cannot prove it;
- keep non-FIPS development providers clearly marked;
- forbid FIPS claims in release notes unless deployment evidence is attached.

## PQC and FIPS

NIST PQC FIPS documents define standardized algorithms, but a deployment still
needs validated implementations and module-boundary evidence before claiming
FIPS validation. PQC support and FIPS validation are related but separate claims.

## Acceptance Gate

A FIPS-enabled deployment must produce:

- `fips-boundary.edn`;
- module certificate references;
- algorithm allowlist;
- runtime policy requiring FIPS provider;
- test evidence that non-FIPS provider is rejected;
- release security note naming the exact boundary.

