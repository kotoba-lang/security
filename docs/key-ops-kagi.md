# Key Operations via kagi

Status: operational runbook  
Date: 2026-07-17

## Purpose

Production private keys for the Kotoba fleet live in **kagi** (OS-Keychain
unlock, compartment `personal`). This repository may record **public** key
material and custody metadata only. Private PEMs must never be committed.

## Inventory (probed 2026-07-17)

| kagi item | Present | Public form recorded in key-register |
|---|---|---|
| `fleet-owner-key` | yes (private in vault) | `ed25519:7414dd47…` (`fleet-owner-key-2026-07-16`) |
| `fleet-owner-root` | yes | `did:key:z6Mkk13t…` |
| `fleet-gov1` | yes | `did:key:z6MkqmFd…` |
| `fleet-gov2` | yes | `did:key:z6MkqZim…` |
| `package-signing` / `package-signing-key` | **no** | demo row only (`example-package-signing-2026q3`) |
| `audit-signing` | **no** | demo row only (`example-audit-signing-2026h2`) |

Public fleet material is also the superproject SSOT
`manifest/fleet-keys.edn` (no private fields).

## CLI location

```sh
export FLEET_ROOT=/path/to/com-junkawasaki   # superproject root
KAGI="$FLEET_ROOT/orgs/kotoba-lang/kagi/bin/kagi"
```

kagi is not always on `PATH`; use the repo binary above (same path fleet CLI
uses for `--kagi`).

## Safe operations

```sh
# List items (names only; no secret material)
"$KAGI" ls --compartment personal

# Fetch private material only into a signing tool stdin — never into git
# or chat. Prefer fleet --kagi rather than printing PEM:
FLEET_ROOT=$FLEET_ROOT nbb --classpath orgs/kotoba-lang/kagami/src \
  orgs/kotoba-lang/kagami/bin/fleet.cljs pin-advance \
  --db manifest/fleet-db.edn --repo security --new <sha> \
  --kagi fleet-owner-key

# kagi has no --public export flag (2026-07-17). Public forms are taken from:
#   1) manifest/fleet-keys.edn (fleet pin + governance DIDs)
#   2) did:key derived at key-generation time and recorded immediately
# Never paste PEM private blocks into registers or evidence.
```

## Register a new production public key

1. Generate/custody the private key in kagi only (`kagi add <name>`).
2. Record **public** hex / `did:key` in `registers/key-register.edn` with:
   - `:key/status :active` (or `:pre-active` until first use)
   - `:key/storage :kagi`
   - `:key/kagi-name "<name>"`
   - `:key/kagi-compartment "personal"`
   - `:key/intent :production`
   - `:key/public` and/or `:key/did`
3. Run `bb scripts/check-key-register.bb` (forbids private PEM, requires
   public material for active production keys).
4. Refresh `evidence/<date>/key-status-snapshot.edn` and evidence-index.
5. Never commit private material; CI/key-register gate rejects PEM blocks.

## Dry-run validation

```sh
bb scripts/check-key-register.bb
clojure -M:test -n kotoba.security.key-lifecycle-test
```

Expected shape invariants are enforced by
`src/kotoba/security/key_lifecycle.cljc`.

## Residual (R-002)

- Package-signing and audit-signing **production** keys are not yet issued
  in kagi; only research-demo template rows exist for those classes.
- Fleet governance/pin keys are production-intent and active for fleet ops
  only — they must not sign package manifests.
