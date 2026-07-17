# Deployment profiles

Security claims for kotoba-lang runtimes are **profile-specific**. Naming a
profile in a release evidence packet is required (`:deployment-profile` claim
in the safe-release gate).

| Profile | Intended use | Claims allowed | Non-claims |
|---------|--------------|----------------|------------|
| `research` | demos, local experiments | capability confinement, fuel/memory limits, audit receipts | no FIPS, no side-channel, no multi-tenant isolation, no formal verification |
| `sensitive-local` | single-tenant local systems | research + host hardening expectations, encrypted audit/data preferred | no FIPS, no side-channel, no co-tenant secrets |
| `regulated` | orgs needing evidence packs | sensitive-local + SBOM/SLSA, key lifecycle, monitoring, provider policy | FIPS only inside named module boundaries with evidence; PQC only when hybrid path is deployed |
| `high-assurance` | blocked until evidence exists | none by default | formal verification + side-channel controls required before use |

## Operator checklist

1. Pick a profile and put it in the release evidence claims.
2. For any network capability, set a non-empty origin/URL allowlist
   (`:kotoba.policy/capability-resources` / `:aiueos/net-allow`).
3. Pass a key-register into package admission (`--key-register`) so revoked /
   pre-active / compromised signers cannot authorize new locks.
4. Do not claim FIPS, PQC, side-channel resistance, or multi-tenant isolation
   unless the profile row above allows it **and** evidence exists.
