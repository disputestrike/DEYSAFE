# Deploying DeySafe / SHIELD To Railway

Pure-Python web app: one web process, no build step. It runs on SQLite locally
and on PostgreSQL when `DATABASE_URL` is set.

## 1. Deploy

1. Push `DEYSAFE/` to GitHub, or run `railway up` from this folder.
2. Railway -> New Project -> Deploy from repo, with root set to `DEYSAFE`.
3. Railway runs the `Procfile`: `web: python engine/api.py`.
4. The server binds `0.0.0.0:$PORT` and Railway gives you a public HTTPS URL.

## 2. Required Launch Variables

These are the difference between demo mode and a safe public deployment.

| Variable | Required | What it does |
|---|---|---|
| `DEMO_MODE` | `0` | Turns off synthetic demo incidents. `/api/health` must show `"demo": false`. |
| `DEYSAFE_OPERATORS` | yes | Operator roster for SHIELD sign-in. Format: `user:role:sha256pw`, comma-separated. Roles: `viewer<reviewer<verifier<admin`. |
| `DEYSAFE_SECRET` | yes | Long random secret for OTP/session/PIN HMACs and default vault encryption key. |
| `DEYSAFE_VAULT_KEY` | recommended | Optional separate long random key for Safety Vault contact encryption. Falls back to `DEYSAFE_SECRET` if unset. |
| `DATABASE_URL` | yes for launch | Railway Postgres connection string. Set `DEYSAFE_REQUIRE_POSTGRES=1` to refuse SQLite fallback. |
| `DEYSAFE_REQUIRE_POSTGRES` | `1` | Fails closed in production when Postgres is not active. |
| `DEYSAFE_BEACON_SECRET` | yes if FindMe/BLE used | Verifies signed beacon relays and replay nonces. |
| `DEYSAFE_INGEST_MINUTES` | recommended | Automatic public RSS ingest interval, for example `30`. Default is off locally. |
| `DEYSAFE_SAFETY_TICK_MINUTES` | recommended | Automatic stale Journey/SafeMeet check interval, for example `5`. `/api/health` exposes `safety_tick`. |
| `DEYSAFE_TRUST_XFF` | `1` on Railway | Trust Railway proxy `X-Forwarded-For` for caller identity and abuse limits. |

Create an operator password hash:

```bash
python -c "import hashlib;print('admin:admin:'+hashlib.sha256('YOURPASS'.encode()).hexdigest())"
```

Preferred (P0-15): mint a slow, salted PBKDF2 hash (`pbkdf2$<iters>$<salt>$<hash>`) — `python -c "import sys;sys.path.insert(0,'engine');import auth;print('admin:admin:'+auth.make_pbkdf2('YOURPASS'))"` (legacy sha256 entries above keep working).

## 3. Optional Live Providers

| Variable(s) | Enables |
|---|---|
| `AT_USERNAME` + `AT_API_KEY` | Real SMS alerts through Africa's Talking. |
| `WHATSAPP_TOKEN` + `WHATSAPP_PHONE_ID` | WhatsApp Cloud API alerts. |
| `ONESIGNAL_API_KEY` + `ONESIGNAL_APP_ID` | Push provider fan-out. |
| `DEYSAFE_VAPID_PUBLIC_KEY` + `DEYSAFE_VAPID_PRIVATE_KEY` | **Real Web Push** to installed PWAs (iOS 16.4+, Android, desktop): the test alert AND verified-threat broadcasts. Needs the `pywebpush` dependency (already in requirements.txt). See the Web Push note below. |
| `CLOUDFLARE_R2_*` | Real image/video evidence upload. Without it the app stores custody hash and file facts only. |
| `CEREBRAS_API_KEY` or `GEMINI_API_KEY` or `GROQ_API_KEY` | AI incident extraction and intake. Without a key it uses rules. |
| `DEYSAFE_ROAD_ROUTING_URL` | Dedicated/self-hosted OSRM for WakaSafe road routing at scale. |
| `GOOGLE_PLACES_API_KEY` or `GOOGLE_MAPS_API_KEY` | Google Places Autocomplete for live place suggestions across Nigeria. The offline national gazetteer still works without it. |

The app is safe by default: when a provider key is missing, it reports
`unconfigured` and never fakes delivery, upload, or AI vision.

**Web Push setup (iOS 16.4+ PWA).** Generate a VAPID keypair once:
`pip install py-vapid && vapid --gen && vapid --applicationServerKey`. The printed
applicationServerKey is `DEYSAFE_VAPID_PUBLIC_KEY`; the base64url private key (from
`private_key.pem`) is `DEYSAFE_VAPID_PRIVATE_KEY`. Set both in Railway — `pywebpush`
installs automatically from requirements.txt. Optional `DEYSAFE_VAPID_SUBJECT`
(e.g. `mailto:safety@deysafe.app`). To verify on an iPhone: open the deployed URL in
Safari → Share → **Add to Home Screen**, open the installed app, then Profile →
**Enable alerts** → **Send test alert** → you should see a real notification → tap
**I received the alert**. Web Push works ONLY in the installed PWA on iOS, never in a
Safari tab. Without the keys or the dependency, push degrades to a local test
notification and verified alerts still reach people by SMS + in-app.

## 3b. Optional Security Hardening

All OFF by default so existing deploys and the gate suite are unaffected — turn them on
for a hardened public launch.

| Variable | Effect |
|---|---|
| `DEYSAFE_DUAL_APPROVAL` | `1` = TWO-PERSON RED approval (P0-08). `/api/verify` only *proposes*; a **different** operator must `POST /api/confirm` to publish. Needs ≥2 roster accounts. |
| `DEYSAFE_WEBHOOK_SECRET` | Shared secret required on inbound `/api/sms` + `/api/ussd` (P0-11). Provider must send it as the `X-Webhook-Secret` header or a `?wht=` query param, else the post is rejected. Unset = fail-open (dev only). |
| `DEYSAFE_ALLOWED_ORIGINS` | Comma-separated CORS allow-list (P0-13). Unset echoes a permissive `*` (dev); set it to your web origins in production. |
| `DEYSAFE_MEDIA_QUOTA_PER_DAY` | Per-identity daily cap on signed evidence-upload URLs (P0-16). Default `30`. Only enforced when R2 is configured. |
| `DEYSAFE_MEDIA_REQUIRE_SESSION` | `1` = `/api/media/presign` requires a citizen session (no anonymous uploads) when R2 is configured. |

Privacy/compliance endpoints added: `POST /api/subscribe` + `/api/unsubscribe` (geofenced
alert opt-in/out, NDPA consent), and `POST /api/erasure` (`confirm=ERASE`; admin by any
identifier, or a citizen self-serving their own session data) for NDPA right-to-erasure.
Graceful shutdown (P2-04) drains in-flight requests on SIGTERM so a Railway redeploy never
hard-kills mid-write.

## 4. Verify Railway/Postgres

Run the full local gate against a disposable Postgres or the Railway-provided URL:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1 -Postgres -DatabaseUrl "<DATABASE_URL>"
```

Pass criteria:

- `/api/health` reports `database.backend == "postgres"`.
- All validation gates pass.
- `launch_posture.errors` is empty when `DEYSAFE_ENV=production`.
- `safety_tick.enabled` is true when `DEYSAFE_SAFETY_TICK_MINUTES` is set.

## 5. What Is Live After Deploy

- Installable PWA: live-location area risk, anonymous reporting, WakaSafe road
  routing plus Journey Guard, SOS with Safety Vault and decoy lock, FindMe
  triangulation, camera/video evidence metadata, voice, and offline outbox.
- SHIELD console: operator sign-in, review queue, verify/dismiss human gate,
  live feed pull, cases, evidence gallery, GeoTrace, delivery receipts, source
  health, and ops readiness.
- Generated nationwide offline gazetteer: all 774 LGAs plus thousands of
  ward-level coordinate records, OpenStreetMap fallback, and optional Google
  Places suggestions.

## 6. Still Needs Native Or Operations Work

- Native mobile app for background Bluetooth scanning, hardware activation,
  push-to-talk, and stronger background location.
- Real video AI pipeline. Capture, R2 metadata, and custody facts exist, but
  pixel/frame-level vision still needs a provider adapter.
- Postgres connection pooling for high concurrent traffic.
- Staffed operator coverage, responder agreements, 112/NGO handoff, and public
  field operations.

## 7. Launch Posture

Go public as a warning-only beta first: `DEMO_MODE=0`, human verification before
any public RED alert, "developing/unverified" labels kept, no rescue guarantee,
and no automatic official dispatch claim.
