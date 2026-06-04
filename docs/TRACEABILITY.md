# DeySafe / SHIELD — Traceability & Validation Matrix (NORTH STAR)

**Purpose:** one source of truth that maps every feature we've discussed to *where it lives*,
*its status*, *how it's validated*, and *the result*. We build, measure, and accept work
against this document.

**Engineering process (every change):** MONITOR (run the gate) → CORRECT (fix fails) →
MEASURE (pass rate) → ADJUST. Nothing is "done" until it's in the matrix AND passes its gate.

**Run the automated gate:** `python validate.py` (against the live server).
**Last run: 2026-06-03 → 42 passed / 0 failed** (22 endpoint + 16 chaos + 4 functional).

Legend: ✅ built & validated · ◑ partial · ☐ not built · 🔑 needs your account/key · ⛔ excluded by a safety bright-line

---

## 1. Feature traceability

### A. Intelligence engine
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Signal ingestion (samples + live RSS) | Doc P6 | `engine/ingest.py` + `api` `/api/ingest-live` + console "⟳ Pull live public feeds" | ✅ (live: 8 public NG feeds, operator-triggered) | `POST /api/ingest-live` gate + live: 124 items → real incidents | PASS |
| Geo-parse (type + NG location + language) | Doc P5 | `engine/geoparse.py` | ✅ | `/api/classify` rule-based | PASS |
| Corroboration · confidence · abstention | Doc P3.3 | `engine/corroborate.py` | ✅ | functional flow C | PASS |
| Human-gate (nothing auto-verifies) | Doc P3.3 / P4(human ctrl) | `corroborate.py` + `api.verify` | ✅ | verify required to confirm | PASS |
| Append-only audit | Doc P3.9 | `db.audit` | ◑ (data only, no UI) | table writes | PARTIAL |
| Storage | Doc P2 | `engine/db.py` (SQLite) | ✅ (Postgres ☐) | all endpoints + injection test | PASS |
| **Auto drop-off / decay** — incidents age out by status TTL (unverified 48h → verified 240h), read-time, NO cron; each carries `age_hours` | user "how do things drop off" | `api._fresh`/`_age_hours` in `public_incidents`+`review_queue` | ✅ | gate: all incidents within TTL | PASS |
| **Full severity ladder visible** — a seeded human-verified RED so GREEN→RED all show | user "why no red?" | `ensure_seed` idempotent verify (respects operator) | ✅ | gate: a verified incident is present | PASS |

### B. Public app — DeySafe PWA
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Map-first home (Leaflet + markers) | Doc P3.1 | `app/index.html` | ✅ | served HTML / browser | PASS |
| **Geofenced area report** ("drill fence") — type area → written report: level + N incidents within radius + per-incident type/status/distance + circle on map | Doc P4 / GDACS + user "drill fence" | `api.risk_at` (radius+distance) + index `loadLevel`/`areaLayer` | ✅ | `GET /api/risk?lat&lng` + browser (Kaduna ORANGE, Gusau RED) | PASS |
| Anonymous incident reporting — typed place → geocoded map incident (ANY town, human-gated `candidate_unverified`) | Doc P3.2 | `api.report` (geocode + structured `recompute`) + index | ✅ | `POST /api/report` + off-gazetteer incident + chaos | PASS |
| Public alert banner (top of screen) | Doc P3.1 | `index.renderBanner` + `api.alerts` | ✅ | `/api/alerts` + verify fires | PASS |
| WakaSafe route detail — type ANY from/to (level + summary + incidents-on-corridor + map) | DeySafe add (Tesla) | `index.checkRoute` (geocoded) + `distToSeg` | ✅ | Abuja→Kaduna detail | PASS |
| **Free-text location** — type ANY town/village (not a 48-item dropdown) | user CAPA #1 | `api.geocode` gazetteer→OSM/Nominatim (no key) + index `geocodeClient` + shared `<datalist>` | ✅ | `/api/geocode` + `/api/risk?lat&lng` + off-centroid pin | PASS |
| Tap-map-to-report | DeySafe add | `index.onMapTap` | ✅ | manual | PASS |
| 📍 Locate-me + ⤢ reset view (Google-Maps style control) — **GPS computed ON-DEVICE, coordinate never sent to server** | user ask + privacy bright-line | `index` Leaflet ctrl + `locateMe`/`riskAtClient`/`resetView` | ✅ | browser: 0 network calls on locate, private marker + report | PASS |
| Action buttons 2×2 grid (no sideways scroll) | user feedback | `index .chips` | ✅ | manual | PASS |
| Responsive desktop (no page-scroll) | user feedback | `index @media` (`#v-home.active`) | ✅ | manual | PASS |
| Installable PWA (manifest) | Doc P7 | `app/manifest.json` | ✅ | served | PASS |
| Service worker (kill-switch, no stale cache) | bugfix | `app/sw.js` | ✅ | manual | PASS |
| SOS / Help one-tap | DeySafe add | `index` | ◑ STUB (no real dispatch ⛔) | manual | PARTIAL (honest stub) |

### C. FindMe — missing persons
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| Missing-person case (name/age/place/exact/vehicle/clothing/direction) | DeySafe add | `db.missing` + `api` + index | ✅ | `POST /api/missing` | PASS |
| GROUP / mass-abduction headcount | user feedback | `db.count` + index | ✅ | missing `count` | PASS |
| Crowdsourced sightings (re-anchor + tighten) | DeySafe add | `db.sightings` + `api` + index | ✅ | sighting tightens radius | PASS |
| Time-based search radius (single circle) | DeySafe add | `api.missing_with_radius` | ✅ | flow C | PASS |
| **Venn-diagram triangulation** — last-seen + every sighting = a reachability ring; intersection (densest overlap) = most-likely zone + 🎯 marker + spoken stat; more sightings → tighter | user "triangulation shape" / Venn | `index.triangulate` (client-side) | ✅ | browser: 3/3 sources → ~24 km zone, 0 errors | PASS |
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
| Feature | Source | Where it lives | Status | Validation | Result |
|---|---|---|---|---|---|
| LLM classifier — Cerebras **round-robin 5 keys** + failover (Gemini/Groq alt) | Doc P5 | `engine/ai.py` | ✅ built, **OFF (no key)** 🔑 | `/api/ai-status` + `/api/classify` | PASS (off→rule-based) |
| **Live news → AI extraction** (AI reads news geoparse can't place → type+place → geocode → structured incident; capped 30/pull, key-gated) | Doc P5 | `api` `/api/ingest-live` (`ai.classify`+`coords_for`+`db.update_signal_geo`) | ◑ built, **needs key to prove** 🔑 | gate: no-key path green; `ai_on`/`ai_used` in response | PASS (off→rule-based) |
| Multi-language extraction (EN/HA/YO/Pidgin) | Doc P5 | `ai.SYSTEM` | ◑ built, unproven w/o key | — | needs key |

### F. Broadcast / channels
| Feature | Source | Where it lives | Status | Result |
|---|---|---|---|---|
| In-app alert + reach estimate | Doc P3.3 | `api.alerts` | ✅ | PASS |
| Push / WhatsApp / SMS-USSD (live send) | Doc P2/P3.7 | — | ☐ 🔑 | needs OneSignal/Meta/Africa's-Talking |
| Responder routing + acknowledgement | DeySafe add | — | ☐ | — |

### G. Deploy / ops
| Feature | Where it lives | Status | Result |
|---|---|---|---|
| Railway-ready ($PORT/0.0.0.0, seed-if-empty, data-dir, Procfile, requirements) | `Procfile`, `api.py` | ✅ | PASS |
| Deploy guide | `DEPLOY.md` | ✅ | PASS |
| Git repo (branch `main`, committed) | repo | ✅ | PASS |
| Persistent local server | `python engine/api.py` (detached) | ✅ | PASS |
| Production DB (Postgres dual-mode via `DATABASE_URL`) | — | ☐ next | — |

---

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
| No stale cached app served (kill-switch SW) | ✅ | `sw.js` |
| No secrets hardcoded (env only) | ✅ / ⚠️ | code uses env; **doc's 5 Cerebras keys are exposed → ROTATE** |
| NDPA (Nigeria Data Protection Act) | ◑ | anonymous ✅; retention schedule + erasure ☐ |

---

## 3. NOT built yet (honest scope — ~a third of the master doc done)
Production stack (Next.js + Supabase/PostGIS + Vercel) · **house-level GPS precision** (✅ typed places now resolve ANYWHERE in Nigeria via OSM/Nominatim — the 48-town wall is gone — but pins are town-centroid accurate, not house-number) · ✅ **report→incident now geocodes** (a typed report of ANY town creates a human-gated `candidate_unverified` map incident) · ✅ **live news → AI extraction wired** (when a Cerebras key is set, news the gazetteer can't place is AI-read → geocoded → mapped; capped 30/pull; **needs your key to prove**) · user accounts & auth · reputation system · live push/WhatsApp/SMS · satellite SAR/VIIRS pipeline · 72-hour risk forecast · NRT integration · scheduled cron scrapers · Telegram/Facebook/YouTube monitors · predictive model · evidentiary chain-of-custody.

**Gated on YOU:** an AI key (turns on real AI) · production accounts (Supabase/Vercel) · channel keys (push/WhatsApp/SMS).

---

## 4. Pre-release gates (run before every release)
1. **Click-through** — every endpoint returns correctly (`validate.py` section A). ✅ 16/16
2. **Chaos** — bad/empty/huge/malformed/injection inputs validate, never crash (section B). ✅ 14/14
3. **Functional** — corroboration raises level, sighting tightens search, verify fires alert (section C). ✅ 3/3
4. **Visual/manual** — open `http://localhost:4500`; the in-tool screenshot can't capture the live Leaflet map (tool limitation), verified via served HTML + DOM.

**To accept a new feature:** add its row here, give it a validation in `validate.py`, and it must PASS.
