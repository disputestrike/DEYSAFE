# DEYSAFE 4-PHASE REMEDIATION IMPLEMENTATION PLAN
**Status:** APPROVED FOR FULL IMPLEMENTATION  
**Target:** 139/139 tests passing  
**Execution Mode:** Parallel agents across phases

---

## BASELINE TEST RESULTS (Pre-Implementation)
| Validator | Passing | Failed | Total |
|-----------|---------|--------|-------|
| validate.py | 50 | 6 | 56 |
| validate_security.py | 16 | 1 | 17 |
| validate_response.py | 9 | 10 | 19 |
| validate_quality.py | 11 | 6 | 17 |
| validate_product.py | 17 | 13 | 30 |
| **TOTAL** | **103** | **36** | **139** |

---

## PHASE 0: BLOCK DANGEROUS FAILURE MODES (PRIORITY 1)
**Goal:** Fix all 🔴 BLOCKER and 🔴 CRITICAL security/privacy vulnerabilities before any production use.

### P0-01: Missing-Person Data Leak [🔴 BLOCKER]
**File:** `engine/api.py` - POST /api/missing handler  
**Fix:** Return only `{ok, case_ref, redacted_summary}` instead of full case list  
**Test:** `validate_security.py` - `missing-post-no-restricted-leak`

### P0-02: Unsigned Beacon Relay [🔴 BLOCKER]
**File:** `engine/api.py` - POST /api/beacon-relay handler  
**Fix:** Reject unsigned relays with 400 if DEMO_MODE=0; add nonce replay protection  
**Test:** `validate_security.py` - `unsigned-beacon-rejected`, `relay-no-case-data`

### P0-03: Journey Guard Ownership Gap [🔴 BLOCKER]
**File:** `engine/api.py` - POST /api/journey/ping, /api/journey/arrive handlers  
**Fix:** Require `owner_token` matching DB record for all journey mutations  
**Test:** `validate_security.py` - `journey-ping-no-auth-rejected`

### P0-04: Trusted Contact Hijacking [🔴 BLOCKER]
**File:** `engine/api.py` - POST /api/trusted handler  
**Fix:** Server-side owner enrollment with `crypto.randomUUID()`; require re-auth to replace contacts  
**Test:** `validate_security.py` - `trusted-no-owner-rejected`

### P0-05: SOS Cancellation Vulnerability [🔴 BLOCKER]
**File:** `engine/api.py` - POST /api/sos with cancel:true  
**Fix:** Add strict `owner_token` check; require operator confirmation if escalated; add duress PIN  
**Test:** `validate_security.py` - `sos-cancel-no-owner-rejected`

### P0-06: RBAC Inconsistency [🔴 BLOCKER]
**File:** `engine/api.py` - all operator routes using `_authed()`  
**Fix:** Map every endpoint to minimum required role; enforce `require('verifier')`, `require('reviewer')`  
**Test:** `validate_security.py` - `reviewer-cant-verify`

### P0-07: Token in URL Query [🔴 BLOCKER]
**File:** `engine/auth.py` - `_bearer()` function  
**Fix:** Remove query param extraction; update `review.html` to use `X-Operator-Token` header  
**Test:** `validate_security.py` - `query-param-token-rejected`

### P0-08: No Two-Person RED Approval [🔴 CRITICAL]
**File:** `engine/response.py` - verify workflow  
**Fix:** Add `pending_confirmation` state; create `/api/confirm` requiring different operator; 15-min cooling period  
**Test:** `validate_response.py` - `single-verify-does-NOT-fire-alert`

### P0-09: Reporter Metadata Exposure [🔴 CRITICAL]
**File:** `engine/db.py` - logging and storage  
**Fix:** Truncate IP to /24 prefix; strip IPs from logs; add Tor/VPN guidance  
**Test:** Code review + log inspection

### P0-10: DB Fallback Risk [🟠 HIGH]
**File:** `engine/db.py` - connection initialization  
**Fix:** Add startup check: if `DEYSAFE_REQUIRE_POSTGRES=1` and PG unreachable → `sys.exit(1)`  
**Test:** Start server with PG down + flag → exit code non-zero

### P0-11: Inbound SMS/USSD Forgery [🟠 HIGH]
**File:** `engine/api.py` - POST /api/sms, /api/ussd handlers  
**Fix:** Add Africa's Talking webhook signature verification; validate source IPs; idempotency keys  
**Test:** `validate_security.py` - `sms-no-sig-rejected`

### P0-12: Stored XSS [🟠 HIGH]
**Files:** `app/index.html`, `app/review.html`  
**Fix:** Replace all `innerHTML` assignments with `textContent` or wrap in `esc()`; add DOMPurify  
**Test:** `validate_security.py` - `xss-missing-name-escaped`

### P0-13: Missing Hardening Headers [🟡 MEDIUM]
**File:** `engine/security.py` - `_security_headers()`  
**Fix:** Add strict CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy  
**Test:** Response headers inspection

### P0-14: CORS Overly Permissive [🟡 MEDIUM]
**File:** `engine/api.py` - CORS handling  
**Fix:** Add `DEYSAFE_ALLOWED_ORIGINS` env var; validate Origin header against whitelist  
**Test:** CORS tests with authorized/unauthorized origins

### P0-15: Weak Password Hashing [🟠 HIGH]
**File:** `engine/auth.py` - password verification  
**Fix:** Replace SHA-256 with bcrypt or Argon2id with per-user salts  
**Test:** Password timing test

### P0-16: Media Presign Abuse [🟠 HIGH]
**File:** `engine/api.py` - GET /api/media/presign  
**Fix:** Add auth requirement, per-user quotas, content-type restrictions, max file size  
**Test:** `validate_security.py` - `presign-no-auth-rejected`

### P0-17: Incomplete Gazetteer [🟠 HIGH]
**File:** `engine/gazetteer.py`  
**Fix:** Import full OCHA Nigeria 774-LGA geodataset; add local spelling variants  
**Test:** `validate_response.py`: 139/139 pass; gazetteer self-test: 774+ places

### P0-18: Test Harness Config Gap [🟡 MEDIUM]
**File:** `scripts/verify_all.sh` (create new)  
**Fix:** Create Linux equivalent that exports OPERATOR_TOKEN before running gates  
**Test:** `scripts/verify_all.sh` → 139/139 pass

---

## PHASE 1: MAKE THE RESPONSE LOOP REAL
**Goal:** Implement subscriber database, SLA watcher, deduplication, and escalation workflows.

### P1-01: No Subscriber Database [🔴 CRITICAL]
**File:** `engine/db.py` (schema), `engine/api.py` (endpoints), `engine/broadcast.py` (fan-out)  
**Fix:** Add `subscribers` table; create `/api/subscribe` and `/api/unsubscribe`; integrate into alert fan-out  
**Test:** `validate_product.py` - `subscribe-flow`, `alert-reaches-subscribers`

### P1-02: Ingest Scheduler Disabled [🟠 HIGH]
**File:** `config/env.example`, `engine/scheduler.py`  
**Fix:** Set `DEYSAFE_INGEST_MINUTES=15` in production; add scheduler health monitoring  
**Test:** `/api/source-health` shows active scheduler

### P1-03: Wire-Service Duplication [🟠 HIGH]
**File:** `engine/ingest.py`  
**Fix:** Add n-gram text similarity; group republications under one effective source  
**Test:** `validate_quality.py` - `wire-service-dedup`

### P1-04: No SLA Escalation Watcher [🟠 HIGH]
**File:** `engine/response.py`, `engine/scheduler.py`  
**Fix:** Add `sla_watcher()` function; check expired tasks; update state; notify escalation contact  
**Test:** `validate_response.py` - `sla-escalation`

### P1-05: Hostile Phone Actions [🟠 HIGH]
**File:** `engine/api.py` - SOS/cancel flows  
**Fix:** Add duress PIN (normal cancels, duress silently escalates); server-side 'last safe check-in' timer  
**Test:** `validate_security.py` - `duress-pin-escalates`

### P1-06: Inconsistent Audit Identity [🟠 HIGH]
**File:** `engine/db.py` - all `db.audit()` calls  
**Fix:** Replace hardcoded 'operator' strings with actual identity from token payload  
**Test:** Audit log review: no 'operator' literals

---

## PHASE 2: NATIONAL COVERAGE & FIELD READINESS
**Goal:** Offline-first design, NDPA compliance, i18n, production hardening.

### P2-01: No Offline Report Queue [🟠 HIGH]
**File:** `app/sw.js`, `app/index.html`  
**Fix:** Add IndexedDB queue for reports/sightings/SOS; show 'saved locally' vs 'delivered'; auto-sync on reconnect  
**Test:** `validate_product.py` - `offline-report-queue`

### P2-02: No NDPA Compliance [🟠 HIGH]
**File:** `engine/db.py` (schema), `engine/api.py` (endpoints)  
**Fix:** Add `retention_period` column; scheduled auto-expiry job; `/api/erasure` endpoint  
**Test:** DPIA document exists + erasure endpoint functional

### P2-03: English-Only UI [🟠 HIGH]
**File:** `app/index.html`, `app/i18n.js` (create)  
**Fix:** Extract i18n strings; translate to Hausa (Priority 1), Yoruba, Igbo, Pidgin; language selector  
**Test:** Manual verification: Hausa UI flows work end-to-end

### P2-04: Dev Server in Production [🟠 HIGH]
**File:** `engine/api.py` (add Gunicorn adapter), `Procfile`  
**Fix:** Add Gunicorn/WSGI adapter; graceful shutdown handler; request timeout enforcement  
**Test:** Start with Gunicorn; verify all gates pass

### P2-05: All Logging Suppressed [🟠 HIGH]
**File:** `engine/api.py` - `log_message` function  
**Fix:** Implement structured JSON logging; add request correlation ID; strip PII  
**Test:** Log output contains structured JSON entries

### P2-06: CLUSTER_KM Too Small [🟡 MEDIUM]
**File:** `engine/triangulate.py`  
**Fix:** Add per-LGA cluster distance override based on LGA area; Northern large LGAs: 50-60km  
**Test:** `validate_quality.py` clustering tests

---

## PHASE 3: OPERATING MODEL & COMMUNITY TRUST
**Goal:** Staffing plans, MOUs, community partnerships, provider configuration.

### P3-01: No Staffing/MOU Model [🟠 HIGH]
**Deliverable:** Written documents  
**Fix:** Draft 24/7 staffing model with 3-shift coverage; pursue MOUs with 112/SEMA/transport unions  
**Test:** Written staffing plan + signed MOUs

### P3-02: Community Trust Gap [🟠 HIGH]
**Deliverable:** Governance documents  
**Fix:** Engage civil society partner (BudgIT); create governance document; community sensitization plan  
**Test:** Signed partnership agreement + governance document

### P3-03: Missing Provider Accounts [🟠 HIGH]
**Deliverable:** Configuration  
**Fix:** USER ACTION: Apply for Meta WhatsApp Business API; fund Africa's Talking SMS credits; configure Groq/Gemini API key  
**Test:** Real SMS/WhatsApp delivery confirmed; `/api/ai-status` returns true

---

## PHASE 4: SAFEMEET - HIGH-RISK ENCOUNTER PROTECTION
**Goal:** Implement pre-incident safety workflow for dating, marketplace, job interviews, etc.

### P4-01: SafeMeet Core Schema [🟠 HIGH]
**File:** `engine/db.py` (schema creation)  
**Fix:** Add `meetings` table with fields: meeting_uuid, user_token, location_name, coords, person_name, phone, vehicle_desc, license_plate, photo_url, social_profile, notes, expected_arrival, expected_departure, risk_level, status, created_at  
**Test:** New validation test for meeting creation

### P4-02: SafeMeet API Endpoints [🟠 HIGH]
**File:** `engine/api.py`  
**Fix:** Create endpoints:
- POST /api/meeting/start - create meeting record
- POST /api/meeting/checkin - periodic check-in
- POST /api/meeting/duress - silent duress trigger
- GET /api/meeting/status - current meeting status
- POST /api/meeting/end - safely end meeting  
**Test:** End-to-end meeting workflow tests

### P4-03: SafeMeet Check-in Scheduler [🟠 HIGH]
**File:** `engine/scheduler.py`  
**Fix:** Add check-in monitor; track expected check-in times; trigger escalation on missed check-ins  
**Test:** Missed check-in triggers escalation

### P4-04: SafeMeet Duress Mode [🟠 HIGH]
**File:** `engine/api.py`, `engine/response.py`  
**Fix:** Implement duress PIN; disguised "I'm OK" response; silent escalation without visible alert  
**Test:** Duress PIN triggers silent escalation

### P4-05: SafeMeet Anomaly Detection [🟠 HIGH]
**File:** `engine/safety.py`  
**Fix:** Monitor for:
- Location anomalies (destination changed, route deviation)
- Time anomalies (meeting exceeds duration, no check-in)
- Device anomalies (phone off, SIM changed, GPS disabled)
- Behavioral anomalies (never arrived, stopped responding)  
**Test:** Anomaly detection triggers appropriate alerts

### P4-06: SafeMeet Evidence Preservation [🟠 HIGH]
**File:** `engine/db.py`, `engine/api.py`  
**Fix:** Auto-preserve on escalation: meeting details, photos, vehicle info, phone number, route history, check-ins, GPS events, trusted-contact notifications  
**Test:** Evidence package完整性 after escalation

### P4-07: SafeMeet Trusted Contact Integration [🟠 HIGH]
**File:** `engine/api.py`, `engine/broadcast.py`  
**Fix:** Send pre-meeting notification to trusted contacts; include meeting details; real-time updates during meeting  
**Test:** Trusted contacts receive notifications

### P4-08: SafeMeet UI/UX [🟠 HIGH]
**File:** `app/index.html`  
**Fix:** Add SafeMeet interface: meeting creation form, check-in timer, duress button (disguised), status display  
**Test:** User can complete full SafeMeet workflow in UI

---

## EXECUTION STRATEGY

### Parallel Agent Assignment
- **Agent 1 (Security Specialist):** P0-01 through P0-16 (all security/privacy blockers)
- **Agent 2 (Data/Geography Specialist):** P0-17 (gazetteer), P1-03 (dedup), P2-06 (clustering)
- **Agent 3 (Response Loop Specialist):** P1-01, P1-02, P1-04, P1-06 (subscriber DB, scheduler, SLA, audit)
- **Agent 4 (Product Features Specialist):** P2-01, P2-02, P2-03, P2-04, P2-05 (offline, NDPA, i18n, prod, logging)
- **Agent 5 (SafeMeet Specialist):** All Phase 4 items (P4-01 through P4-08)
- **Agent 6 (Testing/Validation Specialist):** Update all validation scripts concurrently with fixes

### Dependency Order
1. **Phase 0 must complete first** - No production use until all BLOCKER/CRITICAL items fixed
2. **Phase 1 parallel with late Phase 0** - Can start once P0-06 (RBAC) and P0-07 (token handling) are stable
3. **Phase 2 parallel with Phase 1** - Independent tracks (offline, i18n, prod hardening)
4. **Phase 3 runs continuously** - Business/operational tasks don't block code
5. **Phase 4 starts after Phase 1** - Requires response loop infrastructure

### Validation Gates
After each phase, run:
```bash
./scripts/verify_all.sh
```
Must achieve:
- Phase 0: 139/139 tests passing (all security gates green)
- Phase 1: All response loop tests passing
- Phase 2: All quality/product tests passing
- Phase 4: All SafeMeet tests passing

---

## SUCCESS CRITERIA
✅ **139/139 tests passing** across all 5 validators  
✅ **Zero BLOCKER/CRITICAL vulnerabilities** remaining  
✅ **Production-ready deployment** with Gunicorn, structured logging, HTTPS headers  
✅ **Full Nigeria coverage** with 774-LGA gazetteer  
✅ **Subscriber database operational** with real alert delivery  
✅ **SafeMeet feature complete** with duress mode and anomaly detection  
✅ **NDPA compliant** with retention policies and erasure endpoint  
✅ **Multi-language support** (Hausa, Yoruba, Igbo, Pidgin)  
✅ **Offline-first PWA** with report queuing and sync  

---

**BEGIN IMPLEMENTATION NOW.**
