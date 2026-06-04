# DeySafe — Master Audit Register (EXHAUSTIVE — every item, 4 sources)

Four audit voices, all read in full:
- **A1** — "Full System Audit" (pasted): adversarial tests, unauthenticated power, fake/misleading, 10 missing items, 7/30/90-day plan, test suite, school early-warning.
- **A2** — "What Is Real/Fake" (pasted): security defects A–H with code refs, response loop (3 loops), privacy 3-scope, operating model, Phase 0–4.
- **A3** — "Executive Summary / line-by-line" PDF (14 pp): What works / fake / missing / **code-level 4.x** / **didn't-think-about 5.x** / 8 phases / 20-item table / trust.
- **A4** — "Comprehensive Audit, Gap Analysis & Roadmap" PDF (Manus, 7 pp): last-mile alerting, anonymity/metadata, **Fusion-Cell integration**, **economic/bounty**, continuous AI training, append-only decisions, 2G/3G.

**Root cause (all four agree):** built the visible feature surface before the **trust + response + data-reality** core. *Visibility ≠ rescue.* And our gate measured "doesn't crash," not "is it safe / private / real."

Sev: 🔴 blocker · 🟠 high · 🟡 medium. ✅ = I reproduced it live. Src in [brackets].

---

## A. AUTHENTICATION & AUTHORIZATION
- **AUTH-01** 🔴✅ No operator auth — `/review.html` + `/api/verify`, `/api/queue`, `/api/case-status`, `/api/ingest-live` all public. Anyone can verify/dismiss/scrape. [A1,A2,A3]
- **AUTH-02** 🔴 RBAC: viewer / reviewer / verifier / admin, least-privilege. [A1,A2]
- **AUTH-03** 🔴 MFA for operators. [A1,A2]
- **AUTH-04** 🔴 Two-person approval for RED alerts. [A1,A2]
- **AUTH-05** 🟠 Operator identity recorded on every action; device/session audit. [A1,A2]
- **AUTH-06** 🔴 Put whole app behind staging access until safe. [A1,A2]

## B. ABUSE / INTEGRITY
- **ABU-01** 🔴✅ No rate limiting (30 reports/0.73s). Per-endpoint limits by IP/phone/device/area. [A1,A2,A3]
- **ABU-02** 🟠 Payload size caps as policy (60k "passes" today). [A2,A3]
- **ABU-03** 🟠 Duplicate / coordinated-spam detection. [A1,A2]
- **ABU-04** 🟠 Source/report **reputation scoring** (historically-accurate sources weighted). [A1,A2,A3,A4]
- **ABU-05** 🔴 Blast-radius limits: new/unknown reporter can't trigger high-impact. [A1]
- **ABU-06** 🟠 Moderation queue for community posts. [A1]
- **ABU-07** 🟠 Emergency **kill-switch / takedown** for a false alert. [A1,A2]
- **ABU-08** 🟠 Webhook signature verification (AT etc.); bot defense; queue backpressure. [A2]
- **ABU-09** 🔴✅ Arbitrary incident types accepted (`made_up_type` mapped) → controlled vocabulary; unknown → `other_needs_review`. [A2,A3]
- **ABU-10** 🔴✅ Sighting for nonexistent case accepted (id 999999) → validate case existence + sighting trust pipeline (OTP, evidence, dedup, anomaly, operator review before zone change). [A2]
- **ABU-11** 🔴 **Data poisoning / information warfare** (gangs flood, forces dismiss, political/rival manipulation) → coordinated-reporting anomaly detection + disinfo detection + cross-referencing. [A3-5.3]
- **ABU-12** 🟠 Red-team / ambush-scenario test suite. [A1]

## C. INCIDENT INTEGRITY (logic bugs)
- **INT-01** 🔴 **Decision-key collision** `type|location|state` → new incident inherits old verify/dismiss. → immutable `incident_uuid` + `event_version` + lineage; decisions attach to a version. [A2-D]
- **INT-02** 🟠✅ **Duplicate alerts** on repeat verify (51→54) → alert lifecycle DRAFT→PUBLISHED→UPDATED→CANCELLED→EXPIRED, immutable alert id, idempotency (CAP-compatible). [A2-H]
- **INT-03** 🟠 Alert **update / cancel / expire** logic + TTL. [A2,A3,A4]

## D. BEACON / BLUETOOTH SECURITY
- **BLE-01** 🔴 `/api/beacon-relay` accepts unauthenticated arbitrary lat/lng → re-anchors search (spoofable). [A2]
- **BLE-02** 🔴✅ `beacon_id` returned in public `/api/missing`. → never expose; rotating ephemeral IDs; signed relay envelope; replay + timestamp checks; device attestation; private server-side matching. [A2]

## E. XSS / OUTPUT / WEB SECURITY
- **XSS-01** 🔴 Stored XSS — `openCase()`/FindMe + incident render + RSS titles use `innerHTML` raw (only channel escapes). → escape ALL untrusted output / `textContent`. [A2,A3-4.3]
- **XSS-02** 🟠 Add **CSP** + standard security headers; CI XSS tests. [A2,A3]
- **XSS-03** 🟠 **No CORS headers** — breaks behind CDN/custom domain. [A3-4.6]

## F. PRIVACY / NDPA
- **PRIV-01** 🔴✅ Public `/api/missing` leaks name/age/exact place/vehicle/clothing/direction/beacon/coords/sightings → **3-scope split**: public flyer (redacted, fuzzy area) / family-case-team / restricted responder (exact coords/evidence). [A1,A2]
- **PRIV-02** 🔴 **Reporter threat model** — IP, cell tower, timing metadata. → metadata scrubbing at the load-balancer/network, timing randomization, optional Tor/VPN. [A3-5.1,A4-2.2]
- **PRIV-03** 🟠 **NDPA**: DPIA before launch; retention schedule + auto-expiry; **erasure endpoint**; data-subject rights (access/rectify/object/restrict/portability/erasure/no-automated-decision); DPA for third parties. [A1,A2,A3,A4]
- **PRIV-04** 🟠 **Chain of custody / evidentiary tracking** for verified incidents. [A3]
- **PRIV-05** 🟠 **Append-only** decisions table (currently upserts) + **tamper-evident audit** (hash chain, actor, reason, prev→new state, immutable export). [A2,A3-4.5,A4]
- **PRIV-06** 🟠 Localized trust communication so communities know it's civilian-run + anonymous. [A4]

## G. "FAKE DATA" / DEMO SAFETY
- **FAKE-01** 🔴✅ 100% synthetic data shown as real (seeded verified RED + Kankara case). → `DEMO_MODE` flag; **un-dismissible DEMO banner**; remove seed from `ensure_seed` for fresh deploy (empty map); document demo→live; separate demo tenant. [A1,A2,A3]
- **FAKE-02** 🔴 Relabel honestly: "verified"=demo · "SOS active"=no-delivery · "most likely zone"=preliminary · "route clear"=corridor scan · "proactive"=app-open · "Bluetooth relay"=backend · "anonymous"=needs abuse controls. [A1,A2]

## H. GEOCODING / GEOGRAPHY
- **GEO-01** 🔴✅ **Silent centroid fallback** (unknown place → 9.2,8.2) → return "location not verified" + manual pin + per-coordinate **confidence**. [A2,A3]
- **GEO-02** 🟠 Sole reliance on public Nominatim (≤1 req/s, weak rural data, town-centroid only). → controlled geodata service. [A2,A3,A4]
- **GEO-03** 🟠 48-town gazetteer → full **774 LGA + ~7,000 wards + settlements** (HDX/OCHA), aliases/local spellings, **road network**, schools/markets/motor-parks/checkpoints/religious centers, **offline gazetteer cache**, community-contributed locations. [A1,A2,A3,A4]

## I. DATA PIPELINE / INTELLIGENCE
- **DATA-01** 🔴 No real-time pipeline — RSS is **manual** (operator click), no cron/scheduler/worker. → scheduled scraping every 15–30 min. [A3]
- **DATA-02** 🟠 English-only RSS → **local-language sources** (Hausa/Yoruba/Igbo/Pidgin) + **social monitoring** (Twitter/X, Telegram, WhatsApp groups, Facebook, YouTube). [A1,A3]
- **DATA-03** 🟠 AI gated/unproven; sparse keywords (9 EN kidnap, 3–5 local). → working key (Groq free tier) + **rich multilingual NLP** w/ native speakers + bandit slang. [A1,A3,A4]
- **DATA-04** 🟡 `police_misconduct` in API types but **missing from keyword parser**. [A1-8]
- **DATA-05** 🟠 **False positives** (sports/politics/metaphor/old-news/syndication/rumor/satire/scam) → labeled test set with **negatives**. [A1,A2,A3]
- **DATA-06** 🟠 **Source independence** — same outlet/syndicated counted as independent corroboration → confidence inflated. Add media-ownership/wire-service dedup. [A3-4.7,A4]
- **DATA-07** 🟠 **Temporal decay** — all signals in 72h weighted equally; weight should decay with age. [A3-5.4]
- **DATA-08** 🟠 **Semantic duplicate detection** — 10 people, same event → 10 "sources" (only SHA-256 same-source dedup today). [A3-5.6]
- **DATA-09** 🟡 Satellite **SAR/VIIRS** anomaly detection (Sentinel-1/VIIRS). [A1,A3]
- **DATA-10** 🟠 **72-h risk forecast / predictive model** (historical, seasonal, market-days, day/time, clustering, bandit corridors). [A1,A3,A4]
- **DATA-11** 🟠 **Continuous AI training** — operator verify/dismiss → fine-tune prompts + rules (feedback loop). [A4]

## J. CODE-LEVEL / PERFORMANCE / PRODUCTION INFRA
- **PERF-01** 🟠 **Synchronous `recompute()` on every report** = full-table-scan + full re-cluster; times out under load. → incremental cluster update. [A3-4.1]
- **PERF-02** 🟠 **No pagination** (every endpoint returns full dataset; MB JSON; client DOM freeze on low-end phones). → limit/cursor. [A3-4.2]
- **PROD-01** 🟠 **Python stdlib `ThreadingHTTPServer`** in prod (no pooling/gzip/cache-headers/HTTPS/graceful-shutdown/metrics). → WSGI (Gunicorn/uvicorn). [A3-4.4]
- **PROD-02** 🟠 **All logging suppressed** (`log_message` no-op) → structured logging, request IDs, error aggregation. [A3-4.5]
- **PROD-03** 🟠 pgbouncer **connection pooling**; CDN static caching; **automated DB backups**; **monitoring** (Prometheus/Grafana); **CI/CD** w/ gate every commit. [A3]
- **PROD-04** 🟡 `pipeline.py` fails on clean checkout — add `os.makedirs(data)`. [A1,A3]
- **PROD-05** 🟡 Production stack target (Next.js/Vercel + Supabase/PostGIS). [A3]
- **PROD-06** 🟠 **Low-bandwidth 2G/3G** optimization (PWA + SMS). [A4]

## K. BROADCAST / "LAST MILE" (the system's reason to exist)
- **BC-01** 🔴 **No outbound broadcast.** SMS (AT not wired), USSD-out, WhatsApp Business API, push (OneSignal/Web Push), IVR/voice, community radio/town-crier. [A1,A2,A3,A4]
- **BC-02** 🔴 **Tiered + geofenced**: push RED to everyone within `TYPE_RADIUS` immediately; pull lower advisories. [A4]
- **BC-03** 🟠 Delivery **receipts**, retry, expiry; reach priority WhatsApp→SMS/USSD→push→radio. [A1,A2,A3,A4]
- **BC-04** 🟠 Proactive warnings only work **app-open** → server-side geofenced **push subscriptions** (consented), TTL, ack. [A2,A3]

## L. RESPONSE LOOP / SOS / RESPONDER (the missing half)
- **SOS-01** 🔴 SOS has **no durable event, no trusted-circle notify, no delivery confirm, no operator escalation, no 112 handoff**; shares only via Web Share/clipboard (manual). → full **SOS state machine**. [A1,A2,A3]
- **SOS-02** 🔴 **Silent / covert mode** — alarm-first is dangerous during active abduction; add silent + covert-phrase + dead-air triggers. [A2]
- **SOS-03** 🟠 **Trusted-circle onboarding**; travel **check-in timer** / "arrive safely". [A1,A2,A3]
- **RESP-01** 🔴 **Responder handoff**: verified responder directory (state/LGA), school/transport/hospital focal persons, police/NSCDC where appropriate; **acknowledgement** states (received/reviewing/responding/closed); **escalation timers**; after-action review. [A1,A2]
- **RESP-02** 🔴 **112 / ECC** integration — governed human handoff (not static "call 112"). [A1,A2]
- **RESP-03** 🟠 **Multi-Agency Anti-Kidnap Fusion Cell** — secure **read-only** API for `verified` incidents (intelligence to them; never a targeting tool). [A4]
- **RESP-04** 🟠 **Community early-action protocols** — what to DO on ORANGE/RED (early warning + early action). [A4]
- **RESP-05** 🟠 Incident-commander + **family-liaison** workspace. [A2]
- **RESP-06** 🔴 Preserve bright line: **no automatic armed dispatch.** [A1,A2,A4]

## M. FINDME / TRIANGULATION / WAKASAFE
- **FIND-01** 🟠 Triangulation is a **heuristic**, not rescue-grade → 3 layers (public radius / analyst probability surface / responder plan); relabel "preliminary search visualization". [A1,A2,A3]
- **FIND-02** 🟠 Search radius **50 km/h highway** assumption wrong for forest/terrain (5–15 km/h; 3–5× too large) → terrain-aware (forest/mountain/river/road/hideout). [A3-5.5]
- **FIND-03** 🟠 **USSD missing-person dead-ends** (doesn't create a case) → open real case + reference (DS-YYYY-NNNN) + callback enrichment. [A2]
- **WAKA-01** 🟠 WakaSafe is **straight-line radius**, not road routing (misses on-path danger between endpoints) → routing engine (OSRM/GraphHopper), segment risk, time-of-day, checkpoints/closures, alt routes; relabel "corridor scan". [A1,A2,A3-5.7]

## N. OFFLINE / RESILIENCE / NATIVE
- **OFF-01** 🟠 PWA **not offline** (sw.js kill-switch) → cache shell + **offline report queue** (QUEUED→SYNC_PENDING→RECEIVED); show delivered-vs-saved. [A1,A2,A3]
- **OFF-02** 🟠 **Native app** (React Native/Flutter): BLE scanner, background location, push, real-time **PTT**. [A1,A2,A3]
- **OFF-03** 🟠 BLE crowd-relay needs native scanner + privacy protocol/encrypted matching/replay-resistance/battery/abuse tests. [A2,A3]
- **OFF-04** 🟡 Store-and-forward for SMS/USSD (conceptual, no impl). [A3]

## O. LANGUAGE / ACCESSIBILITY
- **LANG-01** 🟠 UI **entirely English** → multi-language UI (Hausa/Yoruba/Igbo/Pidgin). [A1,A3]
- **LANG-02** 🟡 Voice in/out only `en-NG`; USSD + channels English-only. [A3]
- **LANG-03** 🟠 Rich local-language NLP (native-speaker training data + validation + bandit slang). [A1,A3,A4]

## P. METRICS / TRUST / OPERATING MODEL / DOMAIN
- **MET-01** 🟠 **Life-saving metrics**: signal→review, review→warn, warn→deliver, delivery rate, ack rate, SOS→operator-ack, SOS→handoff, false-positive rate, missed/false-negative rate, people-warned-before-route, credible-sightings, cases-resolved, harm-from-false/exposed-info, responder-ack SLA. **North Star:** verified emergencies with acknowledged human response within SLA. [A1,A2]
- **MET-02** 🟠 **False-positive tracking + community-flag feedback loop** + precision/recall over time. [A3-5.2,A4]
- **OPS-01** 🟠 **24/7 SHIELD situation room** (shifts/SLA/escalation/drills/backup). [A1,A2]
- **OPS-02** 🟠 **MOUs**: 112 ecosystem, SEMA, hospitals, transport unions, schools, traditional/religious, civil-society, telecom/messaging. [A1,A2]
- **OPS-03** 🟠 **Corruption-aware routing** (need-to-know coords, dual approval, actor audit, corruption-risk flags, protected reporter identity, alt escalation). [A1,A2]
- **OPS-04** 🟠 **Community sensitization / town halls / PILOT** one high-risk state (Kaduna/Zamfara) — **not nationwide**. [A1,A2,A4]
- **SCH-01** 🟠 **School early-warning module** (only 37% of schools in 10 states have EWS — UNICEF): panic/report path, threat checklist, parent broadcast, verified closure/reopening; map to Fed Min of Education **Minimum Standards for Safe Schools**. [A1]
- **SCH-02** 🟡 Reporting **sentinel network** (okada/transport/truckers/market leaders/farmers/traditional leaders/clergy/school admins/health workers/vetted volunteers) — observe + report safely, not vigilante. [A1]
- **GUID-01** 🟠 Replace hard-coded guidance ("travel by day/convoy") with **locally-approved, expert-reviewed** guidance; expand `TYPE_GUIDANCE`. [A1,A4]
- **ECON-01** 🟡 **Economic/incentive gap** — secure anonymous **bounty/tip-reward** (donor/NGO-funded). [A4]

---

## New test gates (`validate_security.py`) — must FAIL now, then driven GREEN
auth (unauth→401) · role (reviewer can't verify RED; 2 verifiers) · demo (prod can't boot synthetic-verified) · **PII** (public missing has no exact place/beacon/private sightings) · **XSS** (name/place/RSS/posts can't execute) · CORS · geocode (no silent centroid; offline pilot set) · false-positive (sports/politics/metaphor/old/rumor) · false-negative (HA/YO/IG/Pidgin detected or abstained) · source-independence (syndicated ≠ independent) · broadcast (alert reaches test phone + delivery recorded) · responder (verified → responder task + ack) · expiry (stale alerts downgrade/expire) · abuse (burst spam capped; oversized rejected) · audit (actor+ts+reason+prev/new+hash) · USSD-case-creation · offline-queue.

## Phased plan (merging A1's 7/30/90, A2's Phase 0–4, A3's 8 phases, A4's 4 phases)
- **Phase 0 — Stop the dangerous failure modes (before ANY real use):** AUTH-01/06, INT-01, INT-02, ABU-01/02/09/10, BLE-02, XSS-01/03, PRIV-01, FAKE-01/02, GEO-01, PROD-04. *(each lands with a failing→passing security-gate check)*
- **Phase 1 — Real-time data reality:** DATA-01/02/03/05/06/08, PERF-01/02, FAKE (real pipeline), continuous-classification.
- **Phase 2 — The response loop:** BC-01/02/03/04, SOS-01/02/03, RESP-01/02/06, INT-03, PRIV-05, MET-01.
- **Phase 3 — Field resilience + reach:** GEO-02/03, OFF-01/04, FIND-02/03, WAKA-01, LANG-01/03, PROD-01/02/03/06, PRIV-02/03.
- **Phase 4 — Trusted intelligence + integration:** ABU-04/11, DATA-07/09/10, RESP-03/04/05, MET-02, GUID-01, FIND-01.
- **Phase 5 — Operating model + pilot:** OPS-01..04, SCH-01/02, ECON-01, OFF-02/03 (native), DATA — predictive.

## Accountability — what I got wrong
1. **Feature-first, not trust-first** — wrong order for a safety tool (all 4 audits).
2. **My gate measured "doesn't crash," not "is it safe/private/real"** — so "56/56" was true-but-misleading.
3. **I synthesized when told to capture everything** — dropped the whole code-level/perf/prod layer + the English-only-UI gap + fusion-cell/economic items + the roadmaps. That is itself the "skip things" failure. This register now holds **every item**; only true duplicates are merged (cross-referenced in [brackets]).
4. Nothing is "launch-safe" — only **demo prototype** — until Phase 0 is green.
