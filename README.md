# DeySafe — *Know before you waka*

A civilian, **rights-preserving early-warning + find-people platform** for Nigeria's
kidnapping / banditry crisis. **A warning system, not a targeting system.** It detects,
locates, corroborates, warns, and helps find missing people — it never tracks individuals
without consent, never auto-acts, and never cues force.

- **DeySafe** — the public app (calm, light, map-first).
- **WakaSafe** — road / route safety.
- **FindMe** — missing-person triangulation.
- **SHIELD** — the operator "situation room" + human-verification console (`/review.html`).

> Status: working **prototype**. The current source-of-truth map is
> `docs/WORK_INDEX.md`; gates must pass before public release. Not yet proven with
> real users/data — see *Honest scope*.

---

## Bright lines (encoded in the code, not just docs)
- **Event-centric, not person-centric** — we warn about *events at places*; we never score people.
- **Nothing is auto-verified** — the max automatic status is `needs_human_review`; a **human** confirms before any public RED alert.
- **Your location stays on your device** — "locate me" and proactive warnings are computed **on-device**; your GPS is never sent to or stored on the server.
- **Public data only** — no telecom / financial / RF / biometric ingestion.
- **No auto-dispatch to armed responders.** SOS shares only with people *you* choose.
- **Opt-in only** for any person-locating (a family registers a missing relative's beacon); unknown beacons are ignored.
- **Anonymous** reporting, no PII; parameterised queries; user content escaped.

---

## What it does

**Public app (DeySafe PWA)**
- Map-first home (Leaflet) with GREEN / YELLOW / ORANGE / RED severity.
- **Geofenced area report** — type *any* town/village (free-text geocoding via OpenStreetMap, no key) → a written report of incidents within range + a "drill-fence" circle.
- **WakaSafe** — type any *from -> to* once; road route risk when available, clearly labeled corridor fallback when not, automatic map render, spoken summary, foreground Journey Guard, warnings, check-ins, and arrival handling.
- **Profile / Safety Vault** — phone OTP session, Safety PIN, Duress PIN, server-side guardian vault, push-alert test/confirm, and MySafe places/routes. Guardian PII is not stored in browser localStorage.
- **📍 Locate-me** (Google-Maps style, on-device) + **🛡 proactive proximity warnings** (Waze-style: warns of danger near you as you move).
- **Voice in & out** — speak "am I safe in Kaduna" / "Lagos to Kano"; it reads the report back.
- **SOS** — *Automatic* (alarm + on-device location + shareable link) or *Hold-&-Speak* (auto-sends after dead air), with silent mode, Safety Vault guardian escalation, PIN-gated closure, Duress PIN, and a decoy privacy lock.
- **Camera/video evidence** — attach an image/video fingerprint and file facts to an anonymous report; optional Cloudflare R2 upload is available when storage keys and CORS are configured.
- **AI evidence review** — visible image/video triage from the home screen: validates media, captures custody facts, uses AI for written context when keys are present, and clearly flags that pixel/frame-level vision is not wired until a vision adapter is added.
- **SafeMeet** — say/type the meeting once, AI fills the form, then the phone auto-watches arrival in the foreground, records check-ins, and flags anomalies.
- **Report danger** (any town → geocoded, human-gated incident), **police-misconduct** category + **know-your-rights** card, **community channels** (area-tagged posts).

**FindMe — missing persons**
- Cases (incl. group / mass-abduction), crowdsourced **sightings** that re-anchor the search.
- **★ Venn-diagram triangulation** — each sighting is a reachability ring; the densest overlap = most-likely zone.
- **Movement prediction (Strava-style)** — heading cones + forward marker from the sighting trail.
- **Bluetooth crowd-relay (AirTag model, backend)** — register a beacon; any phone that hears it logs a sighting (the offline reach; the BLE scanner itself is the native-app milestone).

**Intelligence engine + SHIELD console**
- Ingest (samples + **live Nigerian news RSS**) → geo-parse → corroborate → **human gate** → tiered alerts.
- Operator triage queue, one-click **live scrape**, Verify / Dismiss, auto **decay** (stale incidents age off the map).
- **Real AI** (Cerebras round-robin, key-gated) extracts incidents from news + powers natural-language intake and evidence-context triage. Falls back to rule-based with no key; computer-vision analysis is a separate pending adapter.

**Reach**
- In-app alerts + **SMS inbound + USSD menu** (Ushahidi-style basic-phone access). Outbound SMS is key-gated (Africa's Talking).

---

## Run it

```bash
python engine/api.py
```
- Public app:      http://localhost:4500
- SHIELD console:  http://localhost:4500/review.html

Run the pre-release gate against the live server:
```bash
python validate.py            # 56 checks: endpoints + chaos + functional
```

(Original Day-1 CLI detection pass still works: `python engine/pipeline.py [--live]`.)

## Configuration (all via environment variables — never in code)
| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Use PostgreSQL (else SQLite). Falls back to SQLite if unreachable. |
| `CEREBRAS_API_KEY_1..5` (or `CEREBRAS_API_KEY`) | Turns on real AI extraction + intake. |
| `CEREBRAS_MODEL` | Override the model name (default `llama-3.3-70b`). |
| `AT_USERNAME`, `AT_API_KEY` | Africa's Talking — turns on **outbound** SMS. |
| `CLOUDFLARE_R2_*`, `R2_*` | Optional Cloudflare R2 direct browser upload for image/video evidence. See `.env.example`. |
| `DEYSAFE_SECRET` | Required in production for OTP/session/PIN HMACs. |
| `DEYSAFE_OTP_ECHO` | `1` only in validation/demo if you need the OTP returned by the API. |
| `DEYSAFE_BEACON_SECRET` | Signs beacon relay envelopes before FindMe/Bluetooth pilot use. |
| `DEYSAFE_VAPID_PUBLIC_KEY`, `DEYSAFE_VAPID_PRIVATE_KEY` | Web Push subscription/testing. Without these, the app only records permission/test intent. |
| `DEMO_MODE` | `0` for production/no synthetic data; local demo defaults may seed examples. |
| `PORT` | Server port (default 4500). |

---

## Architecture
- **Backend:** Python **standard library only** (`http.server`, `sqlite3`, `urllib`) — one optional dep, `psycopg2-binary`, used only in Postgres mode.
- **Storage:** dual-mode **SQLite ↔ PostgreSQL** (auto-selects on `DATABASE_URL`).
- **Frontend:** vanilla JS PWA + Leaflet (no build step). Install from browser: Android/desktop via Install/Add to Home Screen; iPhone via Safari Share -> Add to Home Screen.
- **Deploy:** Railway-ready (`Procfile`, binds `0.0.0.0:$PORT`, seed-if-empty). Connect the repo → it auto-deploys; add a Postgres plugin for persistence.

## Validation
`docs/WORK_INDEX.md` shows where the current work lives, what was recovered, and what still needs proof. `docs/TRACEABILITY.md` is the North Star matrix (every feature -> where it lives -> status -> how it's validated). `docs/LAUNCH_COMPLIANCE_CROSSWALK.md` is the public-release crosswalk and corrective-action matrix. The gates must pass before any release.

---

## Honest scope (where we really are)
**✅ Built & working:** everything above in the web + server stack when the local gates are green.
**◑ Partial:** AI (built; needs a key — verify on the deployment) · SMS/USSD *send* (needs Africa's Talking) · Web Push provider delivery (needs VAPID + receipt proof) · audit log (data only, no UI) · NDPA retention schedule.
**☐ Not built / native:** the native app (background **Bluetooth mesh** scanner + real-time **push-to-talk**) · user reputation · satellite + 72-h forecast · the production Next.js/Supabase stack · NRT integration.

We've out-*designed* the incumbents (Ushahidi / Zello / Govia ideas folded in); we have **not** yet out-*proven* them — that needs real deployment, verified data, operators, and the native client.

---

This repository folder is **DEYSAFE**; keep new work, docs, tests, and assets here.
