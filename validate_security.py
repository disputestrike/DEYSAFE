"""DeySafe / SHIELD — Pre-release SECURITY gate (Phase 0).

Companion to validate.py. Where validate.py proves "it doesn't crash", THIS gate
proves "it is safe / private / real". Every check below ENCODES the required
Phase-0 end state from docs/FEEDBACK.md, so they are EXPECTED TO FAIL against the
current (insecure) build and are driven GREEN as each fix lands.

    python validate_security.py [base_url]      # default http://localhost:4500

Same engineering loop as the base gate: MONITOR (run) -> CORRECT (fix the fails)
-> MEASURE (pass rate) -> ADJUST. Standard library only. Prints [PASS]/[FAIL] per
check and a RESULT summary; exits 1 if any check fails.

Sections:
  A) AUTH      operator-only endpoints reject anonymous callers (AUTH-01/06)
  B) DEMO+VOCAB demo flag is observable; controlled vocabulary (FAKE-01, ABU-09)
  C) CASE      sightings for nonexistent cases are rejected (ABU-10)
  D) PII       public flyer is redacted — no beacon/exact place/PII (PRIV-01, BLE-02)
  E) GEO       unknown place is flagged unverified, never silent centroid (GEO-01)
  F) IDEMPOT   re-verifying the same incident does not duplicate alerts (INT-02)
  G) XSS       stored <script> in user input is escaped/stripped on output (XSS-01)
  H) ABUSE     burst spam from one caller gets rate-limited (ABU-01)

NOTE ON FAIL-OPEN AUTH: the locked endpoints fail OPEN when OPERATOR_TOKEN is unset
(so validate.py stays 56/56). This gate therefore sets a token to PROVE the lock
works. If the server was booted withOUT OPERATOR_TOKEN, the AUTH checks document
the gap (they will FAIL) rather than giving a false green — run the server with
OPERATOR_TOKEN set to drive section A green.
"""
import sys
import json
import time
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4500"
P = [0]
F = [0]
FAILS = []

# Sensitive keys that must NEVER appear in the PUBLIC missing-person flyer (PRIV-01/BLE-02).
PII_KEYS = ["beacon_id", "exact_place", "vehicle", "clothing", "direction", "last_seen"]
XSS_PAYLOAD = "<script>alert(1)</script>"


def call(method, path, body=None, headers=None, timeout=25):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                j = json.loads(raw)
            except Exception:
                j = None
            return r.status, (j or {}), raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            j = json.loads(raw)
        except Exception:
            j = None
        return e.code, (j or {}), raw
    except Exception as e:
        return 0, {}, repr(e)


def html(path, headers=None, timeout=15):
    try:
        req = urllib.request.Request(BASE + path, headers=(headers or {}))
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, repr(e)


def check(name, cond, detail=""):
    if cond:
        P[0] += 1
        print("[PASS] " + name)
    else:
        F[0] += 1
        FAILS.append(name + ((" -> " + str(detail)) if detail else ""))
        print("[FAIL] " + name + ((" -> " + str(detail)) if detail else ""))


def _missing_public():
    """Fetch the PUBLIC (no-auth) missing list; return the list of case dicts."""
    s, j, _ = call("GET", "/api/missing")
    return s, (j.get("missing") if isinstance(j.get("missing"), list) else [])


print("=== DeySafe / SHIELD pre-release SECURITY gate (Phase 0) ===")
print("target: " + BASE)
print("(checks encode the required end state; they FAIL on the current build by design)")

# ---------------------------------------------------------------------------
print("\n-- A. AUTH: operator endpoints must reject anonymous callers (AUTH-01/06) --")
# These choke points publish/scrape alerts and resolve cases. Without a token they
# must return 401/403 (NOT 200). Fail-open posture means: run the server with
# OPERATOR_TOKEN set for these to pass; unset => documented gap (fails here).
s, j, _ = call("GET", "/api/queue")
check("GET /api/queue without token -> 401/403 (operator-only review queue)", s in (401, 403), "got " + str(s))

s, j, _ = call("POST", "/api/verify",
               {"type": "kidnapping", "location_name": "Shiroro", "state": "Niger", "decision": "verified"})
check("POST /api/verify without token -> 401/403 (the human publish gate)", s in (401, 403), "got " + str(s))

s, j, _ = call("POST", "/api/ingest-live", {}, timeout=90)
check("POST /api/ingest-live without token -> 401/403 (operator RSS pull)", s in (401, 403), "got " + str(s))

s, j, _ = call("POST", "/api/case-status", {"case_id": 1, "status": "located"})
check("POST /api/case-status without token -> 401/403 (operator resolves cases)", s in (401, 403), "got " + str(s))

s, h = html("/review.html")
# AUTH-06: the console PAGE serves (it holds no data — only the shell + sign-in form),
# but it must PRESENT a login gate, and the operator DATA endpoints above must be 401
# without a token. Gating the page itself was a UX bug (login form unreachable), so we
# assert the page serves a sign-in gate instead — data protection is covered by the
# operator-endpoint 401 checks (queue/verify/case-status/ingest-live) above.
check("GET /review.html serves the SHIELD console with a sign-in gate (data is API-gated; AUTH-06)",
      s == 200 and ('id="login"' in h or "operator sign-in" in h.lower()), "got " + str(s))

# ---------------------------------------------------------------------------
print("\n-- B. NO DEMO + CONTROLLED VOCAB: instance runs live data only; types are constrained (FAKE-01, ABU-09) --")
# The app has no demo mode. Health must honestly report that it serves no synthetic
# data, so monitoring can prove a deploy is live (never fake data presented as real).
s, j, _ = call("GET", "/api/health")
check("GET /api/health honestly reports NO synthetic data (FAKE-01, go-live)", s == 200 and j.get("synthetic_data") is False, "keys=" + str(sorted(j.keys())))

# An arbitrary made-up incident type must NOT survive as that literal type. It must
# be rejected (400) or coerced to a controlled-vocab bucket (other_needs_review).
ALLOWED_TYPES = {"kidnapping", "banditry_attack", "missing_person", "armed_robbery", "police_misconduct", "other_needs_review"}
s, j, raw = call("POST", "/api/report", {"type": "made_up_type", "place": "Kano", "description": "vocab gate probe"})
leaked_type = "made_up_type" in (raw or "")
rejected = s == 400
coerced = s == 200 and not leaked_type
check("POST /api/report type='made_up_type' rejected or coerced (NOT stored as made_up_type) (ABU-09)",
      rejected or coerced, "status=" + str(s) + " leaked_literal_type=" + str(leaked_type))

# ---------------------------------------------------------------------------
print("\n-- C. CASE VALIDATION: sighting for a nonexistent case is refused (ABU-10) --")
# A sighting bound to a case that does not exist must not be accepted, or it can
# re-anchor a phantom search zone. Want 400/404, not ok:true.
s, j, _ = call("POST", "/api/sighting", {"case_id": 999999, "place": "Jibia", "hours_ago": 0.5, "note": "ghost case"})
check("POST /api/sighting case_id=999999 -> 400/404 and not ok (ABU-10)",
      s in (400, 404) and not j.get("ok"), "status=" + str(s) + " ok=" + str(j.get("ok")))

# ---------------------------------------------------------------------------
print("\n-- D. PII: public missing flyer must be a REDACTED flyer (PRIV-01, BLE-02) --")
# Brief #6: the app no longer ships any sample data, so seed our OWN case WITH sensitive
# fields. The PUBLIC flyer must then strip them — that redaction is exactly what we assert
# below. (Previously this rode on the demo [SAMPLE] case, which is gone.)
call("POST", "/api/missing", {"name": "Priv Probe", "place": "Kankara",
     "exact_place": "Government Science School, Kankara", "vehicle": "White Hilux, no plate",
     "clothing": "Blue school uniform", "direction": "North toward Jibia",
     "beacon_id": "PRIV-PROBE-BEACON", "hours_ago": 2, "count": 1, "lat": 11.52, "lng": 7.61})
s, cases = _missing_public()
if s != 200:
    check("GET /api/missing (public) reachable", False, "status=" + str(s))
elif not cases:
    # No cases at all -> nothing to leak; record as pass so an empty prod DB is green.
    check("GET /api/missing (public) carries no PII keys (empty set)", True, "no cases")
else:
    present = sorted({k for k in PII_KEYS for m in cases if k in m})
    check("GET /api/missing (public) omits beacon_id/exact_place/vehicle/clothing/direction/last_seen (PRIV-01/BLE-02)",
          not present, "leaked keys: " + str(present))
    # raw per-sighting lat/lng must not ride along in the public flyer either
    raw_sighting_coords = any(
        isinstance(m.get("sightings"), list) and any(("lat" in sg or "lng" in sg) for sg in m["sightings"])
        for m in cases)
    check("GET /api/missing (public) sightings carry no raw lat/lng (PRIV-01)",
          not raw_sighting_coords, "raw coords in sightings=" + str(raw_sighting_coords))

# ---------------------------------------------------------------------------
print("\n-- E. GEOCODE: unknown place is flagged unverified, never silent centroid (GEO-01) --")
# Posting a nonsense place must NOT silently drop a pin on the Nigeria centroid
# (~9.2, 8.2). The response must signal the location is unverified / needs a pin.
s, j, raw = call("POST", "/api/report",
                 {"type": "kidnapping", "place": "Zzxqwville Nowhereplace", "description": "geo gate probe"})
risk = j.get("risk") or {}
incs = risk.get("incidents") or []


def _is_centroid(la, lo):
    try:
        return abs(float(la) - 9.2) < 0.05 and abs(float(lo) - 8.2) < 0.05
    except Exception:
        return False


centroid_pin = any(_is_centroid(i.get("lat"), i.get("lng")) for i in incs) or _is_centroid(risk.get("lat"), risk.get("lng"))
low = (raw or "").lower()
unverified_signal = (
    j.get("location_unverified") is True
    or risk.get("location_unverified") is True
    or str(j.get("coords_confidence") or risk.get("coords_confidence") or "").lower() in ("unverified", "none", "low")
    or "unverified" in low or "not verified" in low or "needs_pin" in low or "manual pin" in low
)
check("POST /api/report unknown place -> location flagged unverified (GEO-01)",
      unverified_signal, "no unverified signal in response")
check("POST /api/report unknown place -> NOT silently pinned to centroid 9.2,8.2 (GEO-01)",
      not centroid_pin, "centroid pin present")

# ---------------------------------------------------------------------------
print("\n-- F. IDEMPOTENCY: re-verifying the same incident does not duplicate the alert (INT-02) --")
# Authed where required; on the locked build this needs the operator token. We send
# the token if the server expects it; if it's fail-open, the bare calls still work.
AUTH_HDR = {"X-Operator-Token": "secgate-test-token"}


def _alert_count():
    s, j, _ = call("GET", "/api/alerts")
    return len(j.get("alerts", [])) if s == 200 else None


# Seed a fresh corroborating report so an incident exists to verify, then verify it
# twice and assert the alert count does not climb on the second identical verify.
call("POST", "/api/report",
     {"type": "banditry_attack", "place": "Gusau", "description": "idempotency probe corroboration"}, headers=AUTH_HDR)
ver_body = {"type": "banditry_attack", "location_name": "Gusau", "state": "Zamfara", "decision": "verified"}
call("POST", "/api/verify", ver_body, headers=AUTH_HDR)  # first verify (may create an alert)
n1 = _alert_count()
call("POST", "/api/verify", ver_body, headers=AUTH_HDR)  # identical second verify
n2 = _alert_count()
check("second identical /api/verify does NOT increase alert count (INT-02 idempotency)",
      n1 is not None and n2 is not None and n2 <= n1, str(n1) + " -> " + str(n2))

# ---------------------------------------------------------------------------
print("\n-- G. XSS: stored <script> in user input is neutralised on output (XSS-01) --")
# Both consoles must escape untrusted output. Static guard: the served HTML must
# carry an escape helper / not be a raw innerHTML sink.
for page in ("/index.html", "/review.html"):
    s, h = html(page, headers=AUTH_HDR)
    has_escape = ("function esc" in h) or ("textContent" in h) or ("escapeHtml" in h)
    check("served " + page + " ships an output-escape helper (XSS-01)", s == 200 and has_escape,
          "status=" + str(s) + " escape_helper=" + str(has_escape))

# Dynamic round-trip: file a missing-person whose NAME contains a <script>, then read
# the PUBLIC flyer back and assert the name is not returned as a live, unescaped tag.
call("POST", "/api/missing",
     {"name": "XSSProbe " + XSS_PAYLOAD, "place": "Lokoja", "hours_ago": 1, "count": 1}, headers=AUTH_HDR)
s, cases = _missing_public()
hit = next((m for m in cases if "XSSProbe" in (m.get("name") or "")), None)
if hit is None:
    check("missing-person name with <script> is stored escaped/stripped on read (XSS-01)", False, "probe case not found")
else:
    nm = hit.get("name") or ""
    neutralised = "<script>" not in nm  # escaped (&lt;script&gt;) or stripped entirely
    check("missing-person name with <script> returned escaped/stripped (XSS-01)", neutralised, "name=" + repr(nm[:60]))

# ---------------------------------------------------------------------------
print("\n-- H. ABUSE: burst spam from one caller is rate-limited (ABU-01) --")
# Fire 25 rapid identical reports from the same caller; at least one must be throttled
# (HTTP 429). On the current build NONE are throttled -> this fails by design.
codes = []
for n in range(25):
    s, _, _ = call("POST", "/api/report",
                   {"type": "armed_robbery", "place": "Kano", "description": "burst spam probe " + str(n)},
                   timeout=15)
    codes.append(s)
throttled = sum(1 for c in codes if c == 429)
check("25 rapid POST /api/report from one caller -> some 429 (ABU-01 rate limit)",
      throttled > 0, "throttled=" + str(throttled) + "/25 codes=" + str(sorted(set(codes))))

# ---------------------------------------------------------------------------
print("\n=== SECURITY RESULT: %d passed, %d failed ===" % (P[0], F[0]))
for x in FAILS:
    print("  FAIL: " + x)
sys.exit(1 if F[0] else 0)
