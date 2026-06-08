# DeySafe - Know Before You Waka

A civilian, rights-preserving early-warning and find-people platform for
Nigeria's kidnapping and banditry crisis. It is a warning system, not a targeting
system: detect, locate, corroborate, warn, and help families search without
scoring people, tracking without consent, or auto-dispatching force.

- **DeySafe** - public PWA.
- **WakaSafe** - road and route safety.
- **FindMe** - missing-person triangulation.
- **SHIELD** - operator situation room and human-verification console at
  `/review.html`.

## Bright Lines

- Event-centric, not person-centric.
- Nothing is auto-verified; human review gates public RED alerts.
- Location stays on-device unless the user explicitly shares it.
- Public data only; no telecom, financial, RF, biometric, or force-targeting feed.
- No automatic dispatch to armed responders.
- Opt-in only for person-locating.
- Anonymous reporting by default, with redaction and operator gating.

## What It Does

**Public app**

- Map-first GREEN / YELLOW / ORANGE / RED safety view.
- Area safety report for any typed Nigerian town, village, LGA, ward, road, or
  landmark resolved through the offline gazetteer, OSM fallback, and optional
  Google Places suggestions.
- WakaSafe: type any `from -> to`, auto-render the map, road route when
  available, corridor fallback when not, spoken summary, Journey Guard, and
  foreground warnings.
- Profile / Safety Vault: phone OTP session, HttpOnly cookie support, encrypted
  server-side guardian storage, guardian verification, Safety PIN, Duress PIN,
  push test/confirm, and MySafe places/routes.
- Locate-me and proactive proximity warnings computed in the browser.
- Voice in and out. Critical SOS/readiness/profile phrases respect English,
  Nigerian Pidgin, Hausa, Yoruba, and Igbo profile choices.
- SOS: audible or silent, durable server event, Safety Vault escalation,
  PIN-gated close request, Duress PIN, and persistent decoy lock.
- Camera/video evidence: attach image/video fingerprint and file facts to an
  anonymous report; Cloudflare R2 upload is key-gated.
- AI evidence review: visible media triage from the home screen; honest
  `vision_ready=false` until a real vision adapter is configured.
- SafeMeet: say/type the risky meeting once, AI fills the form, and the phone
  foreground-watches arrival/check-ins/anomalies.
- Police-misconduct category, rights card, and area-tagged community channels.

**FindMe**

- Missing-person cases and crowdsourced sightings.
- Venn-style reachability triangulation: last-seen plus sightings become
  probability rings; densest overlap becomes a likely search zone.
- Movement prediction cone from the newest sighting trail.
- Backend beacon relay model with signed envelopes and replay checks; native BLE
  scanning remains a native-app milestone.

**SHIELD console**

- Operator sign-in, queue, verify/dismiss, live public feed pull, delivery
  receipts, source health, privacy retention dry-run, launch readiness,
  responder tasks, cases, evidence, GeoTrace, sentinels, safety points, and ops
  readiness.

## Run It

```bash
python engine/api.py
```

- Public app: `http://localhost:4500`
- SHIELD console: `http://localhost:4500/review.html`

Run the gates:

```bash
powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1
```

## Configuration

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Use PostgreSQL. SQLite is local fallback unless `DEYSAFE_REQUIRE_POSTGRES=1`. |
| `DEYSAFE_REQUIRE_POSTGRES` | Fail closed when production requires Postgres. |
| `DEYSAFE_SECRET` | Required for OTP/session/PIN HMACs and default vault encryption key. |
| `DEYSAFE_VAULT_KEY` | Optional separate Safety Vault encryption key. |
| `DEYSAFE_BEACON_SECRET` | Signs beacon relay envelopes. |
| `DEYSAFE_INGEST_MINUTES` | Optional live public RSS ingest interval. |
| `DEYSAFE_SAFETY_TICK_MINUTES` | Optional stale Journey/SafeMeet check interval. |
| `DEYSAFE_VAPID_PUBLIC_KEY`, `DEYSAFE_VAPID_PRIVATE_KEY` | Web Push subscription/testing. |
| `AT_USERNAME`, `AT_API_KEY` | Africa's Talking outbound SMS. |
| `WHATSAPP_TOKEN`, `WHATSAPP_PHONE_ID` | WhatsApp Cloud API alerts. |
| `CLOUDFLARE_R2_*`, `R2_*` | Cloudflare R2 direct browser upload for evidence. |
| `GOOGLE_PLACES_API_KEY`, `GOOGLE_MAPS_API_KEY` | Optional Google Places Autocomplete. |
| `CEREBRAS_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY` | AI extraction/intake providers. |
| `DEMO_MODE` | `0` for production/no synthetic data. |
| `PORT` | Server port, default `4500`. |

## Architecture

- Backend: Python standard library server, with optional `psycopg2-binary` only
  for Postgres mode.
- Storage: SQLite to PostgreSQL dual-mode, encrypted Safety Vault contacts for
  new guardian records.
- Frontend: vanilla JS PWA plus Leaflet, no build step.
- Nationwide data: generated offline table containing all 774 LGAs plus
  thousands of ward-level coordinate records, with OSM and optional Google
  suggestions.
- Deploy: Railway-ready `Procfile`, binding `0.0.0.0:$PORT`.

## Validation

`docs/WORK_INDEX.md` shows where recovered work lives. `docs/TRACEABILITY.md` and
`docs/LAUNCH_COMPLIANCE_CROSSWALK.md` are the source-of-truth matrices. Gates
must pass before release.

## Honest Scope

Built in the web/server stack when gates are green: the public PWA, WakaSafe,
FindMe, SHIELD, Safety Vault, retention dry-run, generated national gazetteer,
and launch-readiness checks.

Partial/provider-dependent: AI, SMS/WhatsApp delivery, Web Push provider
delivery, R2 raw media upload, Google Places, road-routing SLA, Railway/Postgres
live proof, and real provider receipts.

Not built in this repo yet: native app background BLE scanning, hardware button,
wearable activation, real video AI pipeline, staffed 24/7 operator coverage,
responder agreements, and field operations.

This repository folder is **DEYSAFE**; keep new work, docs, tests, and assets here.
