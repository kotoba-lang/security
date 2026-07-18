# EV-0018 — Host-denial telemetry + metric collector (2026-07-18)

## What landed

- `src/kotoba/security/host_denial_telemetry.cljc` — pure aggregate + threshold
  evaluation over continuous-monitoring v1 alert maps.
- `scripts/aggregate-host-denial.cljs` — nbb scanner for `evidence/*/alerts`
  (or `--dir`), writes `host-denial-summary.edn`, optional spike alert emit.
- `scripts/metric-collect.cljs` — mini collector: counts by severity / name /
  signal / decision (extends heartbeat beyond stub).
- Unit tests + `test/fixtures/alerts/*` fixture EDN.

## Honest limits

- Input is **structured alert EDN already on disk** (synthetic samples from
  revoked-signer sim, pager smoke, heartbeat stub). Not a live aiueos host
  trap/denial receipt stream.
- No Slack/PagerDuty tokens invented; `--deliver` still skips webhook when
  `KOTOBA_SECURITY_ALERT_WEBHOOK` is unset.
- Default threshold: ≥1 `host-capability-denial-spike` **or** summed
  `:alert/denial-count` ≥ 50.

## Commands

```sh
nbb --classpath src scripts/aggregate-host-denial.cljs --dir evidence/2026-07-18
nbb --classpath src scripts/metric-collect.cljs --dir evidence/2026-07-18 --write
clojure -M:test -n kotoba.security.host-denial-telemetry-test
```
