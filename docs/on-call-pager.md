# On-call / Pager Runbook

Status: operational baseline (local sinks proven; live Slack/PD optional)  
Date: 2026-07-18

## Purpose

Wire continuous-monitoring alerts (`kotoba.security.continuous-monitoring/v1`)
to human responders without inventing secrets or claiming a live roster when
none is configured.

Executable delivery lives in:

- `src/kotoba/security/alert_delivery.cljs` — file / webhook / stdout sinks
- `scripts/emit-alert.cljs` — CLI smoke + EDN replay
- `scripts/simulate-revoked-signer.cljs --write --deliver` — SEV-1 technical path

Evidence: `EV-0012` (`evidence/2026-07-18/pager-wiring-smoke.edn`).

## Severity → response

| Severity | Definition (IR) | Initial response | Pager expectation |
|---|---|---|---|
| SEV-1 | active compromise / private data exposure | freeze releases, rotate/revoke keys, preserve evidence | page immediately (if webhook configured) |
| SEV-2 | exploitable boundary failure | disable path, draft advisory | page within 15m (if configured) |
| SEV-3 | control degradation with workaround | track remediation | notify channel (business hours) |
| SEV-4 | doc/evidence gap | normal cadence | no page |

See [Incident Response](incident-response.md) for full playbooks.

## Environment template

Copy `.env.pager.example` (repo root) to a **gitignored** local file or export
in the shell. Never commit real webhook URLs.

```sh
# Required for live webhook delivery (optional; file sink always works)
export KOTOBA_SECURITY_ALERT_WEBHOOK='https://hooks.slack.com/services/XXX/YYY/ZZZ'
# or PagerDuty Events API v2 / custom bridge accepting JSON POST

# Optional overrides (future; currently unused by emit-alert)
# export KOTOBA_SECURITY_ALERT_CHANNEL='#security-oncall'
# export KOTOBA_SECURITY_PAGER_VENDOR=slack   # slack | pagerduty | custom
```

Honest behavior when unset:

```text
webhook skipped (KOTOBA_SECURITY_ALERT_WEBHOOK unset)
```

File sink still succeeds under `evidence/<date>/alerts/` (or `/tmp/kotoba-security-alerts/`).

## Local webhook fixture (mock HTTP 200)

No secrets required. Prove the webhook transport against a local sink:

```sh
# Terminal A — mock receiver
nbb --classpath src scripts/mock-webhook-sink.cljs --port 9876

# Terminal B — point smoke at mock
export KOTOBA_SECURITY_ALERT_WEBHOOK='http://127.0.0.1:9876/alert'
nbb --classpath src scripts/emit-alert.cljs --smoke --dir /tmp/kotoba-security-pager-smoke
```

Expected: smoke exits 0; mock logs a JSON body; sink result includes
`:sink :webhook` with HTTP 200.

## Live Slack / PagerDuty (credentials required)

1. Create an **incoming webhook** (Slack) or Events API integration (PagerDuty)
   in the vendor console. Store the URL only in kagi / OS Keychain / 1Password —
   **not** in git.
2. Export as `KOTOBA_SECURITY_ALERT_WEBHOOK` for the session (or inject via
   secrets-location-map workflow).
3. Run smoke:

   ```sh
   nbb --classpath src scripts/emit-alert.cljs --smoke
   ```

4. Confirm the channel/incident received the JSON payload (schema fields
   `alert/name`, `alert/severity`, `alert/reason`, …).
5. Record evidence under `evidence/<date>/pager-wiring-smoke.edn` (do **not**
   paste the webhook URL into evidence).

As of 2026-07-18: secrets-location-map has **no** Slack/PagerDuty webhook item
for this repo. Live vendor delivery remains residual until an owner provisions
the URL into kagi/Keychain.

## Roster template (human)

Fill when a real on-call rotation exists. Empty fields = no claim of coverage.

| Role | Primary | Backup | Timezone | Contact path |
|---|---|---|---|---|
| Security owner | _TBD_ | _TBD_ | _TBD_ | Slack DM / phone (out-of-band) |
| Package owner | _TBD_ | _TBD_ | _TBD_ | |
| Crypto owner | _TBD_ | _TBD_ | _TBD_ | |
| Operations owner | _TBD_ | _TBD_ | _TBD_ | |

Escalation: SEV-1 → Security owner → freeze releases per IR playbook.

## Routing rules (policy)

| Alert name | Severity | Route |
|---|---|---|
| `trusted-signer-verification-failure` | SEV-1 | page security + package owners |
| `host-capability-denial-spike` | SEV-2 | page runtime/ops |
| `pager-wiring-smoke` | SEV-3 | channel only (test) |

## Residual (R-005)

- File sink + local mock webhook: **proven** (EV-0012).
- Production Slack/PagerDuty URL: **unset** until vendor configured.
- Live human roster: **template only** until filled.
