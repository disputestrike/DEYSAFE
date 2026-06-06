# DeySafe / SHIELD — Traceability & Validation Matrix (NORTH STAR)

**Purpose:** one source of truth that maps every feature we've discussed to *where it lives*,
*its status*, *how it's validated*, and *the result*. We build, measure, and accept work
against this document.

**Launch compliance crosswalk:** see `docs/LAUNCH_COMPLIANCE_CROSSWALK.md` for
the public-release matrix, PWA install instructions, route/voice corrections,
real-data gates, and corrective actions.

**Engineering process (every change):** MONITOR (run the gate) → CORRECT (fix fails) →
MEASURE (pass rate) → ADJUST. Nothing is "done" until it's in the matrix AND passes its gate.

**Run the automated gate:** `powershell -ExecutionPolicy Bypass -File scripts\verify_all.ps1`.
**Last full local run: 2026-06-06 -> 139 passed / 0 failed** (56 core + 17 security + 19 response + 17 quality + 30 product).
Postgres verification is encoded in `scripts\verify_all.ps1 -Postgres -DatabaseUrl "<url>"` and must be run against Railway or a disposable Postgres database before production promotion.

Legend: ✅ built & validated · ◑ partial · ☐ not built · 🔑 needs your account/key · ⛔ excluded by a safety bright-line

---

## 1. Feature traceability

### A. Intelligence engine
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Signal ingestion (samples + live RSS) | Doc P6 | `engine/ingest.py` + `api` `/api/ingest-live` + console "⟳ Pull live public feeds" | ✅ (live: 8 public NG feeds, operator-triggered) | `POST /api/ingest-live` gate + live: 124 items → real incidents | PASS |
| Geo-parse (type + NG location + language) | Doc P5 | `engine/geoparse.py` | ✅ | `/api/classify` rule-based | PASS |
| **Classifier precision (DATA-05)** — word-boundary matching + STRONG-signal gating + negative-context suppression (politics/economics/sport/entertainment/legal); missing_person gated on person/abduction phrasing | live RSS false positives | `engine/geoparse.py` (`_WEAK_TERMS`/`_STRONG`/`_NEG`/`_SUPPRESS_RE`/`_MISSING_PERSON_RE`) | ✅ verified live | `geoparse.py` self-test: live-RSS junk suppressed, real incidents + all demo samples retained | PASS |
| Corroboration · confidence · abstention | Doc P3.3 | `engine/corroborate.py` | ✅ | functional flow C | PASS |
| Human-gate (nothing auto-verifies) | Doc P3.3 / P4(human ctrl) | `corroborate.py` + `api.verify` | ✅ | verify required to confirm | PASS |
| Append-only audit | Doc P3.9 | `db.audit` | ◑ (data only, no UI) | table writes | PARTIAL |
| Storage — **dual-mode SQLite + PostgreSQL** (auto-selects on `DATABASE_URL`; graceful SQLite fallback if PG unreachable) | Doc P2 | `engine/db.py` | ✅ | full gate 42/42 on BOTH (Docker PG + SQLite) | PASS |
| **Auto drop-off / decay** — incidents age out by status TTL (unverified 48h → verified 240h), read-time, NO cron; each carries `age_hours` | user "how do things drop off" | `api._fresh`/`_age_hours` in `public_incidents`+`review_queue` | ✅ | gate: all incidents within TTL | PASS |
| **Full severity ladder visible** — a seeded human-verified RED so GREEN→RED all show | user "why no red?" | `ensure_seed` idempotent verify (respects operator) | ✅ | gate: a verified incident is present | PASS |

### B. Public app — DeySafe PWA
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Map-first home (Leaflet + markers) | Doc P3.1 | `app/index.html` | ✅ | served HTML / browser | PASS |
| **Geofenced area report** ("drill fence") — type area → written report: level + N incidents within radius + per-incident type/status/distance + circle on map | Doc P4 / GDACS + user "drill fence" | `api.risk_at` (radius+distance) + index `loadLevel`/`areaLayer` | ✅ | `GET /api/risk?lat&lng` + browser (Kaduna ORANGE, Gusau RED) | PASS |
| Anonymous incident reporting — typed place → geocoded map incident (ANY town, human-gated `candidate_unverified`) | Doc P3.2 | `api.report` (geocode + structured `recompute`) + index | ✅ | `POST /api/report` + off-gazetteer incident + chaos | PASS |
| Public alert banner (top of screen) | Doc P3.1 | `index.renderBanner` + `api.alerts` | ✅ | `/api/alerts` + verify fires | PASS |
| WakaSafe route detail — type ANY from/to (road route when available; corridor fallback when not); **in-process road-route cache + one retry** for reliability vs the flaky public OSRM demo | DeySafe add | `engine/api.py` `/api/route` + `road_route_waypoints` (retry) + `_ROUTE_CACHE` + `route_scan_between` + `index.checkRoute` | ✅ | auto map render + route metadata gate; cached/retried road survives a brief OSRM outage, miss still falls back (never closed) | PASS |
| **Automatic Journey Guard** — one WakaSafe action starts route, voice, guard, foreground warnings/check-ins, and arrival detection; **first-class + always-visible banner on every screen, survives reload** | user "too manual" / "make it visible" | `index.checkRoute` + `startJourneyAutoWatch` + `renderJourneyBanner`/`#journeyBanner` + `restoreJourney` + `/api/journey/start`/`ping`/`arrive` | ✅ foreground, visible, verified live | `validate_product.py` + persistent banner on every render + `restoreJourney` at boot from `ds_journey_id` | PASS |
| **Free-text location** — type ANY town/village (not a 48-item dropdown) | user CAPA #1 | `api.geocode` gazetteer→OSM/Nominatim (no key) + index `geocodeClient` + shared `<datalist>` | ✅ | `/api/geocode` + `/api/risk?lat&lng` + off-centroid pin | PASS |
| Tap-map-to-report | DeySafe add | `index.onMapTap` | ✅ | manual | PASS |
| 📍 Locate-me + ⤢ reset view (Google-Maps style control) — **GPS computed ON-DEVICE, coordinate never sent to server** | user ask + privacy bright-line | `index` Leaflet ctrl + `locateMe`/`riskAtClient`/`resetView` | ✅ | browser: 0 network calls on locate, private marker + report | PASS |
| Voice talk-back (TTS) — area + route spoken like a nav app | user ask | `index` `speak`/`sayArea`/`sayRoute` (Web Speech) | ✅ | browser: utterance composed | PASS |
| Voice input (speech→text) — "Kaduna" / "Lagos to Kano" → runs area/route + speaks back | user ask | `index` `startVoice`/`handleVoice` (SpeechRecognition; Chrome/Android, hidden if unsupported) | ✅ | browser: intent routing both cases, 0 errors | PASS |
| **Proactive proximity warnings** (Waze/Google style) — watch location as you move, warn of danger within 40 km (banner + voice), dedup; **GPS stays ON-DEVICE** | user "Waze proactive warning" | `index` `toggleWatch`/`checkProximity`/`proWarn` (`watchPosition`, client-side) | ✅ | browser: near-Kaduna → fires kidnapping warning, dedupes, 0 errors | PASS |
| Action buttons 2×2 grid (no sideways scroll) | user feedback | `index .chips` | ✅ | manual | PASS |
| Responsive desktop (no page-scroll) | user feedback | `index @media` (`#v-home.active`) | ✅ | manual | PASS |
| Installable PWA (manifest + install prompt) | Doc P7 | `app/manifest.json` + `index.installApp` | ✅ | product gate | PASS |
| Service worker (offline shell, live API network-first) | launch fix | `app/sw.js` | ✅ | product gate | PASS |
| **SOS** — Automatic (alarm + on-device location + share link) / Hold-&-Speak (dead-air auto-send + AI) | DeySafe add + user | `index` `sosAuto`/`sosVoice`/`sosActivate` | ✅ (send-to-stored-circle needs a channel ⛔ no armed auto-dispatch) | browser: alarm+location+share, 0 errors | PASS |
| **Privacy/decoy lock (kill switch)** — hides the app behind harmless Trip Notes after silent SOS or manual lock; **PERSISTS across reload/reopen** | user coercion safety | `index.panicLock`/`panicUnlock` (`localStorage ds_locked`) + boot re-lock | ✅ client-side, persistent, verified live | `validate_product.py` decoy markers + `ds_locked` set on lock / cleared on covert unlock / re-applied at boot | PASS |
| **Policing accountability** (Govia) — "report bad policing" category + know-your-rights card | user research | `api` TYPES `police_misconduct` + index `.rights` | ✅ | gate: type available; browser grid+card | PASS |
| **Camera/video evidence capture metadata** — attach image/video hash + file facts to an anonymous report | user evidence ask | `index.rMedia`/`mediaMetaFromInput` + `/api/report` `evidence_meta` | ✅ metadata; raw storage pending | `validate_product.py` | PASS |
| **Community channels** (Zello, light) — area-tagged posts + 🎤 dictation, newest-first feed, XSS-safe | user research | `db.channel` + `api` `/api/channel` + index `renderChannels` | ✅ | gate: post/feed/empty; browser escape | PASS |

### C. FindMe — missing persons
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Missing-person case (name/age/place/exact/vehicle/clothing/direction) | DeySafe add | `db.missing` + `api` + index | ✅ | `POST /api/missing` | PASS |
| GROUP / mass-abduction headcount | user feedback | `db.count` + index | ✅ | missing `count` | PASS |
| Crowdsourced sightings (re-anchor + tighten) | DeySafe add | `db.sightings` + `api` + index | ✅ | sighting tightens radius | PASS |
| Time-based search radius (single circle) | DeySafe add | `api.missing_with_radius` | ✅ | flow C | PASS |
| **Venn-diagram triangulation** — last-seen + every sighting = a reachability ring; intersection (densest overlap) = most-likely zone + 🎯 marker + spoken stat; more sightings → tighter | user "triangulation shape" / Venn | **server `engine/triangulate.py` (`search_zones`)** + `GET /api/triangulate` + `index.drawBackendTriangulation` | ✅ server-side, verified live | `triangulate.py` self-test (pure, confidence 0..1, disclaimer, never "exact") + `/api/triangulate` returns ranked zones; frontend overlays zone + confidence + disclaimer | PASS |
| **Movement prediction (Strava)** — heading cone + ➡️ forward marker from the sighting trail / direction text | user research | server `engine/triangulate.py` `_movement_cone` (via `/api/triangulate`) + `index.drawBackendTriangulation` + danger heatmap toggle | ✅ server-side | `triangulate.py` self-test: cone reads freshest leg, length-capped; rendered by `drawBackendTriangulation` | PASS |
| **Bluetooth crowd-relay (AirTag model)** — register a beacon; any phone that hears it → a sighting → tighter search; offline store-and-forward | user "Bluetooth mesh" | `api` `/api/beacon-relay` + `db.beacon_id` | ✅ backend (native BLE scanner = native-app milestone) | gate: relay→sighting on SQLite+PG | PASS |
| Case states (active/located/recovered) | DeySafe add | `api.case-status` | ✅ | `POST /api/case-status` | PASS |
| Shareable flyer · map trail | DeySafe add | `index.shareFlyer/drawMarkers` | ✅ | manual | PASS |
| Type ANY last-seen / sighting place (real coords, not centroid) | user CAPA #1 | `api.coords_for` (gazetteer→OSM) + index inputs | ✅ | gate: off-centroid pin | PASS |

### D. SHIELD operator console
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Triage queue (review-worthy, undecided) | Doc P3.5 | `api.review_queue` + `app/review.html` | ✅ | `GET /api/queue` | PASS |
| Operator-triggered live scrape (public NG news → queue) | user ask "is this scraping?" | `api` `/api/ingest-live` + console button | ✅ | gate + live (124 items, never-500) | PASS |
| Verify / Dismiss (the human gate) | Doc P3.5 | `api.verify` + review.html | ✅ | verify flow | PASS |
| Alert generation on verify (L1–4 + radius + guidance + reach) | Doc P3.3 | `api.verify` → `alerts` | ✅ | verify fires alert | PASS |
| Pattern intel · 72h forecast · source health · satellite review | Doc P3.5/P3.8 | — | ☐ / 🔑 | — | N/A |

### E. AI (real LLM)
**(see also: AI natural-language intake below)**
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| LLM classifier — Cerebras **round-robin 5 keys** + failover (Gemini/Groq alt) | Doc P5 | `engine/ai.py` | ✅ built, **OFF (no key)** 🔑 | `/api/ai-status` + `/api/classify` | PASS (off→rule-based) |
| **Live news → AI extraction** (AI reads news geoparse can't place → type+place → geocode → structured incident; capped 30/pull, key-gated) | Doc P5 | `api` `/api/ingest-live` (`ai.classify`+`coords_for`+`db.update_signal_geo`) | ◑ built, **needs key to prove** 🔑 | gate: no-key path green; `ai_on`/`ai_used` in response | PASS (off→rule-based) |
| Multi-language extraction (EN/HA/YO/Pidgin) | Doc P5 | `ai.SYSTEM` | ◑ built, unproven w/o key | — | needs key |
| **AI natural-language intake** — speak/type plain words → AI fills Report & FindMe forms (de-manualizes). Rule-based fallback w/o key | user "too manual, AI chat" | `api` `/api/intake` (`ai.classify`/`extract_missing`) + index `nlIntake`/`nlMic` + 🎤 | ✅ (AI path needs key) | gate: report+auto-missing+empty; browser: Gusau/Kankara pre-fill, 0 errors | PASS |

### F. Broadcast / channels
| Feature | Source | Where it lives | Status | Result |
|---|---|---|---|---|
| In-app alert + reach estimate | Doc P3.3 | `api.alerts` | ✅ | PASS |
| **SMS + USSD reach** (Ushahidi-style) — inbound SMS report + full USSD menu work NOW; outbound send key-gated | Doc P2/P3.7 | `engine/sms.py` + `api` `/api/sms` `/api/ussd` | ✅ inbound+USSD; outbound needs AT key 🔑 | gate: sms inbound + ussd flow | PASS |
| **Outbound delivery provider layer** — multi-channel `send`/`fan_out` (Africa's Talking SMS + WhatsApp Cloud + OneSignal push), key-gated, SIM-able; never fakes a real send | Doc P2/P3.7 | `engine/broadcast.py` (+ `engine/sms.py`) | ✅ built, **key-gated** 🔑 (needs provider keys) | `broadcast.py` self-test: SIM delivers all channels flagged sim=1; no-key path → `unconfigured` | PASS (SIM/no-key) |
| Push / WhatsApp (live send) | Doc P2/P3.7 | `engine/broadcast.py` `_send_whatsapp_real`/`_send_push_real` | ◑ built, **needs keys** 🔑 | needs WHATSAPP_* / ONESIGNAL_* to go live |
| Responder routing + acknowledgement | DeySafe add | — | ☐ | — |

### G. Deploy / ops
| Feature | Where it lives | Status | Result |
|---|---|---|---|
| Railway-ready ($PORT/0.0.0.0, seed-if-empty, data-dir, Procfile, requirements) | `Procfile`, `api.py` | ✅ | PASS |
| Deploy guide | `DEPLOY.md` | ✅ | PASS |
| Git repo (branch `main`, committed) | repo | ✅ | PASS |
| Persistent local server | `python engine/api.py` (detached) | ✅ | PASS |
| Production DB (Postgres dual-mode via `DATABASE_URL`) | `engine/db.py` (psycopg2) | ✅ | 42/42 on Docker Postgres | PASS |
| Connection pooling for PG at scale (pgbouncer) | — | ☐ follow-up (per-request conn ok for now) | — |

---

### H. Product priority layer (Journey Guard / SHIELD growth)
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Journey Guard trip sessions, check-ins, anomaly/overdue flags, explicit exact-location consent | user 8 priorities | `engine/safety.py`, `engine/db.py`, `/api/journey/start`, `/api/journey/ping`, `/api/journey`, `/api/journeys`, `app/index.html`, `app/review.html` | built | `validate_product.py` Journey Guard section | PASS when gate green |
| Phone Safety Readiness checklist (Find My/Find Hub, trusted circle, silent SOS, SMS fallback, wearable, offline pack) | user product gaps | `/api/readiness`, `db.safety_readiness`, Settings panel | built | `validate_product.py` readiness section | PASS when gate green |
| SHIELD case workspace with family liaison, incident commander, analyst owner, restricted updates | user weak ops gaps | `shield_cases`, `case_updates`, `/api/cases`, `/api/case-update`, review console panel | built | `validate_product.py` case section | PASS when gate green |
| Restricted evidence vault + GeoTrace annotations (probability zones, not exact locator claims) | user danger controls | `evidence_items`, `geotrace_annotations`, `/api/evidence`, `/api/evidence-public`, `/api/geotrace` | built | `validate_product.py` evidence/GeoTrace section | PASS when gate green |
| Safety Points + Sentinel Network (public exposes only vetted active points) | user network ideas | `safety_points`, `sentinels`, `/api/safety-points`, `/api/sentinels` | built | `validate_product.py` Safety Points/Sentinel section | PASS when gate green |
| Guardian Mesh software records (consent-scoped devices) | user mesh idea | `mesh_devices`, `mesh_relays`, `/api/mesh/devices`, `/api/mesh/relays` | built (registry) | `validate_product.py` mesh section | PASS when gate green |
| Hardware tracker registry (stable IDs hashed; public projection omits stable hash) | user DeySafe Tag / tracker idea | `tracker_devices`, `/api/trackers` | built (registry) | `validate_product.py` tracker section | PASS when gate green |
| Ops agreements and drills for responder handoff, drills, escalation coverage | user weak ops gaps | `ops_agreements`, `ops_drills`, `/api/ops-agreements`, `/api/ops-drills`, `/api/ops-readiness` | built | `validate_product.py` ops section | PASS when gate green |

## 2. Compliance & safety bright-lines (QC gate)
| Requirement | Status | Evidence |
|---|---|---|
| Warning system, NOT a targeting/surveillance system (event-centric) | ✅ | design; no person-tracking endpoints |
| Nothing auto-verified — human authorizes high-impact | ✅ | `validate.py` verify-required |
| No telecom / financial / RF / biometric ingestion | ⛔ excluded | not built by design |
| No auto-dispatch to armed/military responders | ⛔ excluded | SOS copy: "never auto-dispatches armed responders" |
| Public data only | ✅ | `ingest.py` (RSS) |
| Anonymous reporting, no PII stored | ✅ | `api.report` stores text only |
| No naming individuals (locations/descriptions only) | ✅ | design |
| SQL-injection safe (parameterized queries) | ✅ | chaos test: injection string + DB-intact PASS |
| Input validation — never 500-crash on bad input | ✅ | 14/14 chaos checks PASS |
| App shell installable/offline without caching live API safety data | ✅ | `app/sw.js` |
| No secrets hardcoded (env only) | ✅ / ⚠️ | code uses env; **doc's 5 Cerebras keys are exposed → ROTATE** |
| NDPA (Nigeria Data Protection Act) | ◑ | anonymous ✅; retention schedule + erasure ☐ |

---

## 3. NOT built yet (honest scope — ~a third of the master doc done)
Production stack (Next.js + Supabase/PostGIS + Vercel) · **house-level GPS precision** (✅ typed places now resolve ANYWHERE in Nigeria via OSM/Nominatim — the 48-town wall is gone — but pins are town-centroid accurate, not house-number) · ✅ **report→incident now geocodes** (a typed report of ANY town creates a human-gated `candidate_unverified` map incident) · ✅ **live news → AI extraction wired** (when a Cerebras key is set, news the gazetteer can't place is AI-read → geocoded → mapped; capped 30/pull; **needs your key to prove**) · user accounts & auth · reputation system · live push/WhatsApp/SMS · satellite SAR/VIIRS pipeline · 72-hour risk forecast · NRT integration · scheduled cron scrapers · Telegram/Facebook/YouTube monitors · predictive model · evidentiary chain-of-custody.

**Recently completed (this session):** ✅ Strava movement-prediction + danger heatmap · ✅ SMS/USSD reach (receive now, send key-gated) · ✅ Bluetooth crowd-relay BACKEND (AirTag model) · ✅ SOS redesign · ✅ policing accountability · ✅ community channels · ✅ **server-side triangulation** (`engine/triangulate.py` + `/api/triangulate` + `drawBackendTriangulation`, verified live) · ✅ **classifier precision DATA-05** (geoparse word-boundary/strong-signal/negative-suppression, verified live) · ✅ **persistent coercion kill-switch** (`ds_locked`, verified live) · ✅ **first-class visible Journey Guard** (persistent banner + reload restore, verified live) · ✅ **road-route cache + retry** · ✅ **outbound delivery provider layer** (`broadcast.py`: AT SMS / WhatsApp Cloud / OneSignal, key-gated).

**Gated on YOU / native:** an AI key (verify live on Railway) · **Africa's Talking** acct (`AT_USERNAME`/`AT_API_KEY`) → turns ON SMS/USSD *send* via the now-built `broadcast.py` layer · `WHATSAPP_*` / `ONESIGNAL_*` → turns ON the already-built WhatsApp/push channels · `DEMO_MODE=0` + live-ingest activation for real-data · a **native app** → background BLE mesh scanner + real DeySafe Tag hardware + real-time push-to-talk · 24/7 operator staffing + signed handoff agreements · NDPA retention/erasure policy · production accounts (Supabase/Vercel).

---

## 4. Pre-release gates (run before every release)
1. **Click-through** — every endpoint returns correctly (`validate.py` section A). ✅ 22/22
2. **Chaos** — bad/empty/huge/malformed/injection inputs validate, never crash (section B). ✅ 16/16
3. **Functional** — corroboration raises level, sighting tightens search, verify fires alert, typed off-gazetteer report maps (section C). ✅ 4/4
4. **Visual/manual** — open `http://localhost:4500`; the in-tool screenshot can't capture the live Leaflet map (tool limitation), verified via served HTML + DOM.

5. **Product priorities** - readiness, Journey Guard, SHIELD cases, restricted evidence/GeoTrace, Safety Points/Sentinel, mesh/tracker registry, agreements/drills (`validate_product.py`).

**To accept a new feature:** add its row here, give it a validation in `validate.py`, and it must PASS.
