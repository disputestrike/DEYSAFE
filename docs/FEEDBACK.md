# DeySafe — Audit Feedback Register (source of truth for fixes)

Two external audits (A = "Full System Audit"; B = "Comprehensive Audit / Gap Analysis").
Every finding is captured here — nothing skipped. Overlapping findings are merged and
cross-referenced (both sources noted). Each item: **severity**, **source(s)**, **verified?**
(did I reproduce it against the live code), **fix**, and **proof gate** it must pass.

## The root cause (both audits agree)
We built the **visible feature surface** before the **trust + response core**. *Visibility ≠ rescue.*
The missing half of the chain is: **warn → DELIVER → ACKNOWLEDGE → coordinate → escalate → close → learn**,
sitting on a foundation of **auth, privacy, abuse-control, and honest labeling** that does not yet exist.
And our QA gate measured **"doesn't crash on bad input,"** not **"is it safe / authorized / private / real"** —
so "56/56 green" gave false confidence while the safety-critical layer was wide open.

Legend: 🔴 release-blocking · 🟠 high · 🟡 medium · ✅ verified by my own repro · 📄 from audit text

---

## 1. SECURITY / TRUST — release-blocking
| ID | Problem | Sev | Src | Verified | Fix | Proof gate |
|---|---|---|---|---|---|---|
| S1 | **No auth/authz.** `/api/verify`, `/api/queue`, `/api/case-status`, `/api/ingest-live`, `/review.html` are PUBLIC. The "human gate" is fake. | 🔴 | A+B | ✅ 200 no-auth | Operator auth (login + token), RBAC (viewer/reviewer/verifier/admin), MFA, 2-person approval for RED, lock all operator routes + console | unauth → 401; reviewer can't verify RED |
| S2 | **Decision-key collision.** Decisions keyed by `type\|location_name\|state` → a NEW incident inherits a prior verify/dismiss. Unreviewed incident shows "verified". | 🔴 | B | ✅ code | Immutable `incident_uuid` + `event_version`; decisions attach to a specific incident version, never a type+city key | old decision never affects new incident |
| S3 | **Input not trusted.** Arbitrary incident type accepted (`made_up_type` mapped); sighting for nonexistent case accepted; case-status mutable by anyone. | 🔴 | A+B | ✅ | Controlled vocabulary (unknown → `other_needs_review`); validate case existence; authz on case mutations | bad type rejected/quarantined; fake case_id → 400 |
| S4 | **Beacon spoofing + exposure.** `/api/beacon-relay` accepts unauthenticated arbitrary lat/lng and re-anchors the search; `beacon_id` returned on public `/api/missing`. | 🔴 | A+B | ✅ (beacon_id public) | Signed/rotating ephemeral beacon IDs, replay+timestamp checks, server-side private matching, operator review before a relay moves the search zone; never expose beacon_id publicly | spoofed relay can't move zone; no beacon_id in public payload |
| S5 | **No abuse controls.** No rate-limit / dedup / size cap / OTP. 30 reports in 0.73s; a 60k payload counts as "pass". | 🔴 | A+B | 📄 | Per-endpoint rate limits (IP/phone/device/area), payload caps, duplicate suppression, risk-based OTP, blast-radius limits for new/unknown reporters, moderation queue, kill-switch | burst spam can't create public panic |
| S6 | **Stored XSS.** Missing-person + incident render paths use `innerHTML` with raw user/RSS values (only community channel escapes). | 🔴 | A+B | 📄 (need full sweep) | Escape ALL untrusted output (name/place/vehicle/clothing/description/RSS titles); prefer `textContent`; add CSP + security headers | XSS payload in name/place/RSS never executes |
| S7 | **Duplicate alerts / no lifecycle.** Repeat verify grows alert count (51→54). No idempotency/expiry/cancel. | 🟠 | B | ✅ | Alert lifecycle DRAFT→PUBLISHED→UPDATED→CANCELLED→EXPIRED + immutable alert id + idempotency (CAP-compatible concepts) | repeat verify → no new duplicate alert |

## 2. PRIVACY (NDPA / data minimization)
| ID | Problem | Sev | Src | Verified | Fix | Proof gate |
|---|---|---|---|---|---|---|
| P1 | **Missing-person PII public.** `/api/missing` returns name/age/exact place/vehicle/clothing/direction/beacon/coords/sightings to anyone. | 🔴 | A+B | ✅ | Split into 3 scopes: **public flyer** (redacted, fuzzy area, safe description, contact button) · **family/case-team** · **restricted responder** (exact coords/evidence). | public payload has no exact place/beacon/private sightings |
| P2 | **No DPIA / NDPA controls.** No retention schedule, erasure, data-subject rights. | 🟠 | A+B | 📄 | DPIA before launch; retention + erasure; subject-access; data-minimization by default. | DPIA doc exists; retention enforced |

## 3. RELIABILITY / "FAKE vs REAL"
| ID | Problem | Sev | Src | Verified | Fix | Proof gate |
|---|---|---|---|---|---|---|
| R1 | **Silent centroid fallback.** Unknown place → pinned to 9.2,8.2 instead of "location unverified". Sole reliance on public Nominatim (≤1 req/s, not production-grade). | 🔴 | A+B | ✅ | Never silently centroid: return **"location not verified"** + require manual pin; per-coord **confidence**; real gazetteer (state/LGA/ward/community/roads/landmarks) + offline fallback. | unknown place → unverified (NOT centroid); 100 pilot places resolve offline |
| R2 | **Synthetic verified alerts in "production".** Seed inserts a verified RED + sample case mixed with real data. | 🔴 | A+B | ✅ (seed) | Gate all synthetic data behind `DEMO_MODE`; label every synthetic item; **"DEMO DATA — DO NOT USE FOR REAL SAFETY DECISIONS"** banner; prod boot forbids synthetic verified alerts. | prod cannot boot with synthetic verified alerts |
| R3 | **Detection gaps / false positives.** `police_misconduct` missing from keyword parser; sports/politics/metaphor misread as incidents; syndicated news counted as independent corroboration; loose language detection. | 🟠 | A+B | 📄 | Labeled test set incl. **negatives** (football/politics/metaphor/old news/syndication/rumor/satire/scam); source-independence scoring; align keyword types with API types. | false-positive + false-negative gates pass |
| R4 | **`pipeline.py` fails on clean checkout** (no `os.makedirs(data)`). | 🟡 | A | 📄 | Add `os.makedirs` to pipeline. | clean checkout runs |

## 4. THE MISSING RESPONSE LOOP (the big one)
| ID | Problem | Sev | Src | Fix | Proof gate |
|---|---|---|---|---|---|
| L1 | **SOS doesn't deliver/escalate.** No durable SOS event, trusted-circle notify, delivery confirm, operator escalation, 112 handoff, or **silent** mode. | 🔴 | A+B | SOS state machine: TRIGGERED→LOCATION→CIRCLE_NOTIFIED→DELIVERED→OPERATOR_ACK→112_HANDOFF→COORDINATED→SAFE/ESCALATED/CLOSED; silent + audible modes; SMS/WhatsApp/push fallback | silent SOS reaches ≥2 channels + records delivery + operator ack |
| L2 | **No outbound broadcast.** No SMS/WhatsApp/push/IVR send, delivery receipts, retry, expiry. | 🔴 | A+B | Outbound channels (Africa's Talking SMS/USSD, push, WhatsApp), delivery receipts, retry, expiry | verified alert reaches test phones + records delivery |
| L3 | **Proactive warnings only work app-open.** | 🟠 | A+B | Server-side geofenced push subscriptions (consented), TTL, ack | warning arrives with app closed |
| L4 | **WakaSafe = straight-line scan**, not road routing. | 🟠 | A+B | Road-network routing + segment risk; until then **relabel "corridor scan"** | labeled honestly; (later) real road segments |
| L5 | **Triangulation = heuristic**, not rescue-grade. | 🟠 | A+B | 3 layers: public radius / analyst probability surface / responder plan; **relabel "preliminary search visualization"** | labeled; analyst surface gated to operators |
| L6 | **USSD missing-person dead-ends** (doesn't create a case). | 🟠 | B | USSD opens a real case + returns a reference number (DS-YYYY-NNNN) | USSD-only user can open + update a case |
| L7 | **No responder handoff.** No directory, acknowledgement, escalation timers, 112 integration. | 🔴 | A+B | Responder directory by state/LGA; ack states (received/reviewing/responding/closed); escalation timers; governed 112 handoff (no armed auto-dispatch) | verified incident creates a responder task requiring ack |
| L8 | **PWA not offline** (sw.js kill-switch). | 🟡 | A+B | Cache app shell; queue field reports (QUEUED→SYNC_PENDING→RECEIVED); show delivered-vs-saved | report queued offline → syncs later |
| L9 | **Audit not tamper-evident.** Rows only, no hash chain. | 🟠 | A+B | Hash-chained audit (actor, ts, reason, prev→new state); immutable export | audit entry has actor+reason+prev/new+hash |
| L10 | **No life-saving metrics.** | 🟠 | A+B | Track signal→review, review→warn, delivery rate, ack rate, false-pos/neg, SOS→ack, case closure | metrics dashboard renders real numbers |

## 5. HONEST LABELING (stop implying operational backing)
| ID | Relabel | Src |
|---|---|---|
| H1 | "verified" demo alerts → DEMO; "SOS active" → prototype (no delivery yet); "most likely zone" → preliminary search viz; "route clear" → corridor scan w/ uncertainty; "proactive alerts" → app-open only (until push); "Bluetooth relay" → backend prototype; "anonymous" → add abuse controls. Add global DEMO banner. | A+B |

## 6. OPERATING MODEL (not code, but required)
24/7 SHIELD situation room (shifts/SLA/drills) · MOUs with 112 ecosystem, SEMA, schools, transport unions, hospitals, community/religious leaders · corruption-aware compartmentalized routing · **pilot one corridor/state/school first — do NOT launch nationwide.**

## 7. NEW TEST GATES to add (`validate_security.py`)
auth gate (unauth→401) · role gate (reviewer can't verify RED; 2 verifiers) · demo gate (prod can't boot synthetic verified) · **PII gate** (public missing has no exact place/beacon/private sightings) · **XSS gate** (name/place/RSS/posts can't execute) · geocode gate (no silent centroid; pilot places resolve offline) · false-positive gate (sports/politics/metaphor/old/rumor → not incidents) · false-negative gate (HA/YO/IG/Pidgin detected or abstained) · broadcast gate (alert reaches test phone + delivery recorded) · responder gate (verified → responder task + ack) · expiry gate (stale alerts downgrade/expire) · abuse gate (burst spam can't panic) · audit gate (every high-impact action: actor+ts+reason+prev/new+hash).

---

## Phased plan (matches both audits)
- **Phase 0 — Stop the dangerous failure modes (before ANY demo):** S1 auth+lock console · S2 incident UUIDs/versioning · S3 controlled vocab + case validation · S4 hide beacon_id + gate relay · S5 rate limits + size caps · S6 escape all output + headers · S7 alert idempotency · P1 public/restricted missing split · R1 stop silent centroid (return "unverified") · R2 DEMO_MODE + banner · R4 pipeline makedirs. **Each lands with a failing→passing `validate_security.py` check.**
- **Phase 1 — Response loop:** L1 SOS state machine + silent mode · L2 outbound SMS/push + delivery · L7 responder handoff + ack · L3 push subscriptions · L9 tamper-evident audit · L4/L5 relabel.
- **Phase 2 — Field resilience:** L6 USSD case creation · L8 offline queue · R1 real gazetteer + offline · scheduled ingest · multilingual review.
- **Phase 3 — Trusted intelligence:** R3 reputation + syndication/dup detection + negative test set · analyst surfaces · forecasting (after real data).
- **Phase 4 — Pilot:** one corridor/state/school, 24/7 team, prove the loop before expansion.

## Accountability — what I got wrong
1. **Feature-first instead of trust-first.** For a kidnapping-safety tool that's the dangerous order. Both audits nailed it.
2. **My gate measured the wrong thing** — "returns 200 / doesn't crash," not "is authorized / private / real." So "56/56 PASS" was *true but misleading*. The new `validate_security.py` measures SAFE.
3. **I reported features as working/done** when the trust layer underneath made them not launch-safe. "Done" now means "does the exact thing, safely, proven" — and nothing here is "launch-safe," only **demo prototype**, until Phase 0 is green.
