# DeySafe Work Index

Updated: 2026-06-06

This is the findability map for the current repository. Use it when work feels scattered across chats, branches, or Railway pushes.

## Git State

| Item | Status | Notes |
|---|---|---|
| `main` | Current release branch | Pulled from GitHub, then repaired in this working folder. |
| `phase-1-4-backup` | Included in `main` | Confirmed as an ancestor of `origin/main`. |
| `journey-triangulation-precision` | Included in `main` | Contains server Venn triangulation, movement cone, and route precision work. |
| `pre-launch-hardening` | Included in `main` | Contains security hardening, auth, GPS leak guardrails, and deploy warnings. |
| `railway/code-change-kQLTZ3` | Partially integrated | SafeMeet UI/API idea was useful, but had backend gaps; integrated with fixes here. |

## What Was Recovered Or Fixed

| Area | What happened | Corrective action |
|---|---|---|
| API contract drift | A later restore-style merge replaced the stronger API with a smaller handler while the app still called newer endpoints. | Restored the hardened API behavior and kept the useful static file serving. |
| Video evidence | App had Cloudflare R2 upload UI but the current API no longer served `/api/media/presign`. | Restored `/api/media/presign` and report evidence metadata handling. |
| Journey Guard | App expected `/api/journey/start`, `/api/journey/ping`, and `/api/journey/arrive` to return redacted journey state. | Restored richer Journey Guard endpoints and public-safe projections. |
| SafeMeet | Branch work added UI but was not fully wired and had DB insert placeholder bugs. | Added owner-scoped SafeMeet API endpoints, fixed DB inserts, added server-side check-ins/end/invite/anomaly flags, and enabled foreground auto-watch in the app. |
| Branding | Logos were outside the repo and not connected to PWA install assets. | Added PWA icon, favicon, apple-touch icon, and brand assets under `app/assets/brand/`. |
| Repository hygiene | `.env`, SQLite DBs, Python bytecode, and a backup API file were pushed to GitHub. | Removed them from Git tracking, fixed `.gitignore`, and added `.env.example`. |

## Product Surface Map

| User problem | Product surface | Main files |
|---|---|---|
| Know if the area around me is dangerous | Live map, live location marker, area report, spoken risk | `app/index.html`, `engine/api.py` `/api/risk`, `/api/geocode` |
| Know if a road trip is risky | WakaSafe route scan, automatic map rendering, Journey Guard | `app/index.html`, `engine/api.py` `/api/route`, `/api/journey/*`, `engine/routing.py` |
| Get help without angering a captor | SOS, silent mode, privacy decoy lock, trusted-circle share | `app/index.html`, `engine/api.py` `/api/sos`, `engine/response.py`, `engine/broadcast.py` |
| Report danger with video | Report form, camera/video evidence, hash metadata, optional Cloudflare R2 upload | `app/index.html`, `engine/api.py` `/api/media/presign`, `/api/report` |
| Find a missing person | FindMe case, sightings, Venn search zone, movement cone | `app/index.html`, `engine/api.py` `/api/missing`, `/api/sighting`, `/api/triangulate`, `engine/triangulate.py` |
| Stay safer during a risky meeting | SafeMeet session, auto-arrival check-in, periodic pings, anomaly flags | `app/index.html`, `engine/api.py` `/api/safemeet/*`, `engine/safety.py`, `engine/db.py` |
| Operator verification | SHIELD console, queue, evidence, GeoTrace, audit | `app/review.html`, `engine/api.py`, `engine/db.py` |
| Install on phone | PWA manifest, service worker, app icons | `app/manifest.json`, `app/sw.js`, `app/assets/brand/` |

## Still Not Magic

| Gap | Why it matters | What is needed |
|---|---|---|
| Real outbound delivery | SMS/WhatsApp/push only send when provider keys are configured. | Add provider keys in Railway and run delivery smoke tests. |
| Cloudflare R2 CORS | Browser direct upload needs bucket CORS allowing the Railway origin and `PUT`. | Configure R2 CORS and env vars from `.env.example`. |
| Native background BLE | Browser PWA cannot reliably scan BLE in the background. | Native app milestone for background Bluetooth mesh relay. |
| Production operators | RED alerts must remain human-gated. | Add trained operators, `OPERATOR_TOKEN`/roster, run drills. |
| Public launch data | Demo data is not launch evidence. | Set `DEMO_MODE=0`, use real verified sources, and run live pilot verification. |

## Verification Commands

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify_all.ps1
python validate_product.py http://localhost:4500
```

Latest local proof in this folder: `scripts/verify_all.ps1` passed 148 / 0 on 2026-06-06. Expected proof for a launch candidate: all gates pass, the PWA loads locally and on Railway, `/api/health` reports the intended database backend, and browser smoke tests show map, WakaSafe, report video, SafeMeet, FindMe, and SHIELD rendering.
