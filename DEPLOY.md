# Deploying DeySafe / SHIELD to Railway

Pure-Python (standard-library-only) web app — one web process, no build step. It runs
on **SQLite** out of the box and on **PostgreSQL** when `DATABASE_URL` is set.

## 1. Deploy
1. Push `guardian-ng/` to GitHub (or `railway up`).
2. Railway → **New Project → Deploy from repo** (root = `guardian-ng`).
3. Railway runs the `Procfile`: `web: python engine/api.py`. The server binds
   `0.0.0.0:$PORT` automatically and Railway gives you a public HTTPS URL.

## 2. Launch checklist — set these in Railway → Variables

These are the difference between a demo and a real, safe deployment. **Set all of the
"required for launch" ones before sharing the URL.**

| Variable | Required for launch | What it does |
|---|---|---|
| `DEMO_MODE` | **`0`** | Turns OFF the synthetic demo incidents. Default is ON — a public app showing fake RED alerts can cause real harm. `/api/health` must show `"demo": false`. |
| `DEYSAFE_OPERATORS` | **yes** | The operator roster for the SHIELD console sign-in. Format: `user:role:sha256pw` (comma-separated). Roles: `viewer<reviewer<verifier<admin`. **Without this the console has no working sign-in.** Make a line with:<br>`python -c "import hashlib;print('admin:admin:'+hashlib.sha256('YOURPASS'.encode()).hexdigest())"` |
| `DEYSAFE_SECRET` | **yes** | Long random string that signs operator sessions so logins survive restarts (without it, sessions reset every redeploy). |
| `DATABASE_URL` | **strongly** | Postgres connection string (Railway → add a Postgres plugin → it injects this). Persists data across redeploys. Without it, SQLite is used (add a **Volume** at `data/` so it survives, or data resets each deploy). Set `DEYSAFE_REQUIRE_POSTGRES=1` to refuse to boot on the SQLite fallback. |
| `DEYSAFE_BEACON_SECRET` | **yes (if FindMe/BLE used)** | Required to verify signed beacon relays. **Without it, anyone can POST a fake "Bluetooth relay" sighting and misdirect a missing-person search.** |
| `DEYSAFE_INGEST_MINUTES` | recommended | Minutes between automatic public-RSS pulls (e.g. `30`). Default OFF — without it (and without an operator clicking "Pull live public feeds"), the live map stays empty once `DEMO_MODE=0`. |
| `DEYSAFE_TRUST_XFF` | **`1` on Railway** | Trust `X-Forwarded-For` for caller identity (rate-limit / abuse). Railway puts a proxy in front, so set `1` there so each client is limited separately. Leave UNSET on a direct-connect host — otherwise an attacker forges the header to get a fresh rate-limit bucket per request. |

### Optional — flip features from "ready" to "live" as you get keys
| Variable(s) | Enables |
|---|---|
| `AT_USERNAME` + `AT_API_KEY` (+ `AT_SENDER`) | Real **SMS** alerts to the trusted circle (Africa's Talking — best for Nigeria). |
| `WHATSAPP_TOKEN` + `WHATSAPP_PHONE_ID` | **WhatsApp** alerts (Meta Cloud API). |
| `ONESIGNAL_API_KEY` + `ONESIGNAL_APP_ID` | Web/mobile **push**. |
| `CLOUDFLARE_R2_*` (account/bucket/access keys) | Real **video/photo evidence upload**. Without it the app still stores a custody hash + file facts (no raw upload). |
| `CEREBRAS_API_KEY` (or `GEMINI_API_KEY` / `GROQ_API_KEY`) | **AI** incident extraction (multi-language). Without a key it uses the rule-based parser. |
| `DEYSAFE_ROAD_ROUTING_URL` | A dedicated/self-hosted OSRM for WakaSafe road routing at scale (the free public demo is rate-limited). |

Everything is **safe-by-default**: with a feature's keys unset, that feature degrades
honestly (it never fakes a delivery/upload) — the rest of the app keeps working.

## 3. First operator sign-in
Open `https://<your-app>/review.html` → the **SHIELD operator sign-in** appears → log in
with a `DEYSAFE_OPERATORS` account. The console page is public (it's just the login
shell); all operator **data** is gated server-side (401 without a valid login).

## What's built and live after deploy
- Installable **PWA**: live-location area risk (GREEN→RED), anonymous reporting, **WakaSafe**
  real road routing (OSRM) + Journey Guard, **SOS** (silent/audible) with persistent
  decoy "kill switch", **FindMe** with server-side triangulation (probability zones +
  confidence), camera/video evidence capture, voice, offline outbox.
- **SHIELD** console: operator sign-in, review queue, verify/dismiss (human gate before any
  public alert), live-feed pull, cases + evidence gallery + GeoTrace.
- **774-LGA** offline gazetteer + open OpenStreetMap geocoding; Postgres dual-mode.

## Still needs build/hardware (not config)
- Native mobile app for **background Bluetooth mesh** scanning + a real **DeySafe Tag**.
- Raw video **object storage at scale** + a video-AI pipeline (capture + R2 metadata exist).
- Postgres **connection pooling** (pgbouncer) for high concurrent traffic.
- NDPA data **retention/erasure** policy + a staffed 24/7 operator + signed 112/NGO handoff.

## ⚠️ Launch posture
Go public **warning-only beta** first: `DEMO_MODE=0`, a human verifying before any public
RED alert, "developing/unverified" labels kept, and no promise of guaranteed rescue or
automatic dispatch. Prove one corridor (e.g. Kaduna–Abuja) before claiming national reach.
