# Phase 1-4 Handoff Audit

Date: 2026-06-05

This note captures the real repo state and the pasted working context from the
prior session, then adds the engineering judgement call: what was missed, what
to do differently, and what product bets still need attention.

## Ground Truth

- `origin/main` is still Phase 0 at `ee5087a`.
- The full Phase 1-4 body of work is on `origin/phase-1-4-backup` at `a1c915d`.
- The Phase 1-4 branch includes the response loop, metrics, reputation, broadcast,
  routing, scheduler, beacon signing, gazetteer, pagination, terrain, ABU-03
  coordinated-burst detection, `CHANGELOG.md`, and the gate scripts.
- The pasted session's "rate-limit stopped throttling" concern did not reproduce
  in this clean checkout. A 25-report burst against `/api/report` completed in
  about 2.5s and produced `13/25` throttled responses.
- The earlier `validate_response.py` failure was an env mismatch: that gate must
  run with `DEYSAFE_BROADCAST_SIM=1`, as documented in the script header, so it
  can verify honest simulated delivery receipts without real channel keys.

## Verification

Use:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1
```

The harness:

- starts each gate on its own local port;
- sets `OPERATOR_TOKEN=secgate-test-token`;
- sets `DEMO_MODE=1`;
- clears `DATABASE_URL` for SQLite verification;
- sets `DEYSAFE_INGEST_MINUTES=0`;
- sets `DEYSAFE_BROADCAST_SIM=1`;
- backs up any existing `data/`, runs each gate on a fresh DB, then restores the
  original `data/` directory.

Clean SQLite result on this checkout:

- `validate.py`: `56/56`
- `validate_security.py`: `17/17`
- `validate_response.py`: `19/19`
- `validate_quality.py`: `17/17`

Total: `109/109`.

Postgres release verification is now explicit:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1 -Postgres -DatabaseUrl "<disposable-postgres-url>"
```

Use a disposable Postgres database or Railway preview database. The gates write
test reports, missing-person cases, alerts, deliveries, and source-health rows.
When `-Postgres` is used the harness sets `DEYSAFE_REQUIRE_POSTGRES=1` and then
checks `/api/health` for `database.backend == "postgres"`, so a broken Postgres
run cannot silently pass on SQLite fallback.

Module self-tests run green for:

- `metrics.py`
- `broadcast.py`
- `response.py`
- `reputation.py`
- `routing.py`
- `terrain.py`
- `pagination.py`
- `beaconsign.py`
- `scheduler.py`

## What We Missed

1. Main was never advanced. The real work was safe on a branch, but deploy/main
   stayed Phase 0. That makes every later conversation confusing until someone
   checks commits instead of memory.
2. The gate environment was not encoded. `validate_response.py` needs broadcast
   SIM mode, but ad hoc runs omitted it and created false failures.
3. There was no single verification entrypoint. Multiple terminals, ports, and
   partial reruns made it too easy to blame the code for harness state.
4. SQLite-green is not production-green. Railway/Postgres needs a real Postgres
   gate, and the harness must fail hard if Postgres is requested but the app
   silently falls back to SQLite.
5. Runtime data hygiene was treated late. `data/` is correctly ignored now, but
   validation logs also needed ignoring because safety apps can leak sensitive
   context through logs.
6. The public repo posture raises the bar. Every change needs secret scanning,
   data exclusion, and explicit env documentation before push or deploy.
7. The hot report path still deserves load testing. It passes the current gate,
   but `/api/report` still performs synchronous recompute work; this should be
   measured under a large dataset and Postgres before production traffic.

## What I Would Do Differently

1. Make `main` boring: every merge must keep it deployable, verified, and backed
   by a branch/PR trail.
2. Put all gates behind one command and one CI job. No hand-built server runs for
   release decisions.
3. Run a two-database matrix: SQLite for local speed, Postgres for deploy truth.
   If `DATABASE_URL` is set and Postgres fails, the Postgres gate should fail,
   not silently pass on fallback.
4. Split accept-time and compute-time for `/api/report`: accept, rate-limit, store,
   and return fast; recompute incrementally or in a worker. Keep the current full
   recompute as a repair/backfill operation.
5. Add operator-facing observability before public launch: source health,
   delivery receipts, responder-task SLA, false-positive rate, verification lag,
   and active-alert age.
6. Keep production flags explicit: `DEMO_MODE=false`, operator auth required,
   broadcast real-send keys absent until approved, retention policy set before
   real missing-person/SOS data.

## Product Gaps And Missed Bets

- WhatsApp Business broadcast and inbound reports.
- Push notifications for the PWA/native app.
- Native app work: background BLE scanner, safer SOS flow, battery-aware location,
  and offline relay queue.
- Trusted-circle contact management, including consent and revocation.
- Responder/NGO roster management with availability, jurisdiction, and handoff
  audit trail.
- Operator dashboard for metrics, source reputation, source health, and SLA misses.
- Operator dashboard now includes metrics, source reputation, source health,
  responder tasks, public alerts, and delivery receipts.
- Real outbound WhatsApp and OneSignal push paths are now wired in
  `engine/broadcast.py`; they remain key-gated and degrade to honest
  `unconfigured` receipts when keys are absent.
- NDPA-grade retention, export, deletion, and incident redaction controls.
- Multilingual and low-literacy flows: Hausa/Yoruba/Igbo/Pidgin, voice-first
  warning summaries, and SMS-friendly phrasing.
- Public trust layer: clear alert provenance, confidence, age, and correction flow.
- Partner integrations: emergency services, vetted NGOs, community moderators,
  and road-safety groups.

## Immediate Recommendation

Merge `phase-1-4-backup` into `main`, run `scripts\verify_all.ps1`, then run the
same gate matrix with `-Postgres` against a disposable Postgres database before
Railway deploy. Do not run release gates without `DEYSAFE_BROADCAST_SIM=1`.
