"""DeySafe / SHIELD — Pre-release QUALITY gate (Phase 2-4).

Fourth gate in the family. The others prove escalating properties of the build:

    validate.py            "it doesn't crash"                 (56 checks)
    validate_security.py   "it is safe / private / real"      (Phase 0)
    validate_response.py   "the response loop exists"         (Phase 1)
    validate_quality.py    "it is correct, lean, and field-ready"  (Phase 2-4)  <- THIS

This gate proves the Phase 2-4 *intelligence + resilience* layer is actually wired
into the API, not just sitting in importable engine modules. It checks the six
items the SCOUT change-map flagged as built-but-unwired (engine/gazetteer.py,
engine/routing.py, engine/metrics.py) or data-only (config/keywords.json
negative_terms / police_misconduct):

  PERF-02  GET /api/incidents?limit=2 returns <=2 incidents AND a total/paging
           field (pagination — every list endpoint must stop dumping the full
           dataset onto low-end phones).
  MET-01   GET /api/metrics (operator token) returns a real life-saving-metrics
           OBJECT (the North-Star funnel), not the SPA shell.
  DATA-05  a report whose text is an obvious sports/football sentence does NOT
           create a map incident (negative-term false-positive suppression).
  DATA-04  a police-misconduct sentence is DETECTABLE as police_misconduct
           (the type exists in the API but was missing from the keyword parser).
  GEO-03   GET /api/gazetteer?q=<a real LGA NOT in the 48-town seed> resolves
           OFFLINE with a confidence (the 774-LGA offline gazetteer layer).
  WAKA-01  GET /api/route?from=Abuja&to=Kaduna returns PER-SEGMENT corridor risk
           (road-aware corridor scan, not a two-endpoint straight line).

    python validate_quality.py [base_url]       # default http://localhost:4500

Run the server the same way as the other gates (operator token so the metrics
view is reachable; DEMO_MODE so there is data to page):

    # bash
    DEMO_MODE=true OPERATOR_TOKEN=secgate-test-token DEYSAFE_BROADCAST_SIM=1 \
        python engine/api.py
    # PowerShell
    $env:DEMO_MODE='true'; $env:OPERATOR_TOKEN='secgate-test-token'; \
        $env:DEYSAFE_BROADCAST_SIM='1'; python engine/api.py

Then:  python validate_quality.py

Same engineering loop as the other gates: MONITOR (run) -> CORRECT (fix the
fails) -> MEASURE (pass rate) -> ADJUST. Standard library only. Prints
[PASS]/[FAIL] per check and a RESULT line; exits 1 if any check fails.

Like validate_security.py / validate_response.py, EVERY check encodes the
required Phase 2-4 end state, so the checks are EXPECTED TO FAIL against the
current (pre-wiring) build and are driven GREEN as each fix lands.

IMPORTANT — unknown GET paths fall through to the SPA static handler, which
serves app/index.html with HTTP 200 (not 404). So a missing JSON route looks
like "200 + an HTML page", NOT "404". Every check below therefore asserts on the
parsed JSON SHAPE (a route is "wired" only when it returns the expected JSON
object), never on the status code alone — otherwise an unwired route would score
a false green off the 200 the SPA fallback returns.

Auth contract (preserved): GET /api/metrics is OPERATOR-class (fail-closed) and
receives the token; the field/read paths (incidents / gazetteer / route / report
/ classify) are public and are called anonymously.
"""
import sys
import os
import json
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4500"
# Operator token for the fail-closed operator endpoints (the server is launched
# with the same OPERATOR_TOKEN). Public/field endpoints get NO token on purpose.
OPTOKEN = os.environ.get("OPERATOR_TOKEN", "")

# Operator-class path prefixes that should receive the token. Everything else is
# the public/field surface and is called anonymously.
OP_PATHS = ("/api/metrics",)

P = [0]
F = [0]
FAILS = []


def _auth_for(path, want_token):
    h = {"Content-Type": "application/json"}
    base = path.split("?")[0]
    is_op = any(base.startswith(p) for p in OP_PATHS)
    if want_token is None:
        want_token = is_op
    if want_token and OPTOKEN:
        h["Authorization"] = "Bearer " + OPTOKEN
        h["X-Operator-Token"] = OPTOKEN
    return h


def call(method, path, body=None, want_token=None, timeout=25):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers=_auth_for(path, want_token))
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


def check(name, cond, detail=""):
    if cond:
        P[0] += 1
        print("[PASS] " + name)
    else:
        F[0] += 1
        FAILS.append(name + ((" -> " + str(detail)) if detail else ""))
        print("[FAIL] " + name + ((" -> " + str(detail)) if detail else ""))


def _get(obj, *keys, default=None):
    """First present, non-None value among keys in a dict (tolerant of naming)."""
    if not isinstance(obj, dict):
        return default
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return default


def _is_json_obj(raw):
    """True only if the body parsed as a JSON object — proves a real JSON route
    answered, not the SPA index.html the static fallback serves on a 200."""
    return isinstance(raw, dict)


def _num(x):
    try:
        return float(x)
    except Exception:
        return None


print("=== DeySafe / SHIELD pre-release QUALITY gate (Phase 2-4) ===")
print("target: " + BASE)
print("(checks encode the required Phase 2-4 end state; they FAIL on the pre-wiring build by design)")
if not OPTOKEN:
    print("note: OPERATOR_TOKEN is empty — the /api/metrics check will document the gap "
          "(run the server with OPERATOR_TOKEN set to drive it green).")

# ---------------------------------------------------------------------------
# A. PERF-02 — pagination (GET /api/incidents?limit=2 -> <=2 + a paging/total field)
# ---------------------------------------------------------------------------
print("\n-- A. PERF-02: list endpoints paginate (limit honoured + a total/paging field) --")
# Seed a handful of incidents so there is genuinely more than 2 to page, making the
# limit meaningful (each distinct place becomes its own incident).
for i, place in enumerate(("Kaduna", "Kano", "Gusau", "Katsina", "Sokoto")):
    call("POST", "/api/report",
         {"type": "banditry_attack", "place": place,
          "description": "quality-gate pagination seed %d" % i}, want_token=False)

s, j, raw = call("GET", "/api/incidents?limit=2", want_token=False)
incs = j.get("incidents") if isinstance(j.get("incidents"), list) else None
n = len(incs) if isinstance(incs, list) else None
# A total/paging field must accompany the page so a client knows there is more.
PAGE_KEYS = ("total", "count", "total_count", "next_cursor", "cursor",
             "next_offset", "offset", "has_more", "page", "limit", "remaining")
paging_field = next((k for k in PAGE_KEYS if k in j), None) if isinstance(j, dict) else None
check("GET /api/incidents?limit=2 returns a JSON incidents list (PERF-02)",
      s == 200 and isinstance(incs, list), "status=%s type=%s" % (s, type(incs).__name__))
check("GET /api/incidents?limit=2 honours the limit (returns <=2) (PERF-02)",
      isinstance(n, int) and n <= 2, "returned %s incidents" % n)
check("GET /api/incidents?limit=2 carries a total/paging field (client knows there is more) (PERF-02)",
      bool(paging_field), "paging field present=%s keys=%s" % (bool(paging_field), sorted(j.keys()) if isinstance(j, dict) else None))

# ---------------------------------------------------------------------------
# B. MET-01 — life-saving metrics object (operator-gated GET /api/metrics)
# ---------------------------------------------------------------------------
print("\n-- B. MET-01: GET /api/metrics (operator) returns the life-saving-metrics object (North-Star funnel) --")
ms, mj, mraw = call("GET", "/api/metrics", want_token=True)
# A real metrics route returns a JSON OBJECT (the SPA fallback returns HTML on 200,
# which json.loads cannot parse -> mj stays {} and _is_json_obj(mraw) is False).
is_obj = _is_json_obj(mj) and mraw.lstrip().startswith("{")
# The object must look like the funnel metrics.compute() produces, not just any JSON.
metric_keys = ("north_star", "false_positive_rate", "responder_ack_rate",
               "signal_to_review_min", "review_to_alert_min", "deliveries",
               "sos_open", "cases_resolved", "alerts_active")
present = [k for k in metric_keys if (isinstance(mj, dict) and k in mj)] if is_obj else []
# Accept either a top-level metrics dict or a {"metrics": {...}} envelope.
inner = mj.get("metrics") if (isinstance(mj, dict) and isinstance(mj.get("metrics"), dict)) else None
if inner is not None:
    present = sorted(set(present) | {k for k in metric_keys if k in inner})
    north = _get(inner, "north_star") or _get(mj, "north_star")
else:
    north = _get(mj, "north_star")
check("GET /api/metrics (token) returns a JSON object, not the SPA shell (MET-01)",
      ms == 200 and is_obj, "status=%s json_object=%s head=%r" % (ms, is_obj, (mraw or "")[:40]))
check("GET /api/metrics exposes life-saving funnel metrics (>=3 known metric keys) (MET-01)",
      len(present) >= 3, "metric keys present=%s" % present)
check("GET /api/metrics carries a North-Star block (verified emergencies w/ acknowledged response) (MET-01)",
      isinstance(north, dict) and any(k in north for k in
                                      ("verified_emergencies", "within_sla_rate", "acknowledged_responses", "ack_sla_min")),
      "north_star=%s" % (json.dumps(north)[:120] if north is not None else None))

# ---------------------------------------------------------------------------
# C. DATA-05 — false-positive suppression (a sports sentence makes NO incident)
# ---------------------------------------------------------------------------
print("\n-- C. DATA-05: an obvious sports sentence does NOT create a map incident (negative-term suppression) --")
# The text below carries an incident KEYWORD used as sports metaphor ("launched an
# attack") PLUS a real gazetteer location ("Kano"), so today's parser detects a
# banditry_attack and the report becomes a map incident — a textbook false positive.
# Once config/keywords.json `negative_terms` is wired into geoparse, the dominant
# sports negatives (super eagles / league / match / scored) must make it ABSTAIN.
SPORTS = ("Super Eagles launched an attack in the second half of the league match "
          "in Kano, and the forward nearly scored before the keeper saved it")
s, j, raw = call("POST", "/api/report",
                 {"type": "", "place": "Kano", "description": SPORTS}, want_token=False)
risk = j.get("risk") or {}
sports_incident_count = risk.get("count")
# Pass when the sports report does NOT register as a danger incident at that point
# (count == 0). A non-empty count means the false positive still slips through.
check("POST /api/report with a sports sentence does NOT create a map incident (DATA-05)",
      s == 200 and (sports_incident_count == 0 or sports_incident_count is None),
      "incident_count_at_point=%s" % sports_incident_count)

# ---------------------------------------------------------------------------
# D. DATA-04 — police-misconduct is detectable as police_misconduct
# ---------------------------------------------------------------------------
print("\n-- D. DATA-04: a police-misconduct sentence is detectable as police_misconduct (keyword parser) --")
# police_misconduct is a valid API type but was missing from the keyword parser.
# /api/classify always returns the rule-based detection, so we can read the parser's
# verdict directly without needing an LLM key.
POLICE = ("Police officers extorted money and harassed drivers at an illegal "
          "checkpoint in Kaduna, demanding a bribe before letting them pass")
s, j, raw = call("POST", "/api/classify", {"text": POLICE}, want_token=False)
rb = j.get("rule_based") or {}
detected = (_str := str(_get(rb, "incident_type") or _get(j, "incident_type") or "")).lower()
# Also accept the result surfacing via a structured /api/report path as a fallback.
if detected != "police_misconduct":
    s2, j2, _ = call("POST", "/api/report",
                     {"type": "", "place": "Kaduna", "description": POLICE}, want_token=False)
    r2 = (j2.get("risk") or {}).get("incidents") or []
    if any((i.get("type") == "police_misconduct") for i in r2):
        detected = "police_misconduct"
check("a police-misconduct sentence is detected as type 'police_misconduct' (DATA-04)",
      detected == "police_misconduct", "detected_type=%r" % detected)

# ---------------------------------------------------------------------------
# E. GEO-03 — offline gazetteer resolves a real LGA NOT in the 48-town seed
# ---------------------------------------------------------------------------
print("\n-- E. GEO-03: an LGA outside the 48-town seed resolves OFFLINE with a confidence (774-LGA gazetteer) --")
# 'Giwa' is a real Kaduna LGA in the kidnapping belt and is NOT one of the 48 seed
# towns in config/locations.json, so resolving it proves the larger offline
# gazetteer layer (engine/gazetteer.py) is wired — not the seed table or a network
# OSM call. GEO-01 still applies: the result must carry a confidence grade.
LGA = "Giwa"
gs, gj, graw = call("GET", "/api/gazetteer?q=" + LGA, want_token=False)
g_obj = _is_json_obj(gj) and graw.lstrip().startswith("{")
# Tolerate either {result:{...}} or a flat object.
node = gj.get("result") if (isinstance(gj, dict) and isinstance(gj.get("result"), dict)) else gj
lat = _num(_get(node, "lat", "latitude")) if isinstance(node, dict) else None
lng = _num(_get(node, "lng", "lon", "longitude")) if isinstance(node, dict) else None
conf = _get(node, "confidence", "coords_confidence", "score") if isinstance(node, dict) else None
ok_flag = (_get(gj, "ok") is not False)  # absent or True is fine; explicit False is a miss
# Coordinates must be inside Nigeria's bounding box and NOT the silent centroid (9.2,8.2).
in_ng = (lat is not None and lng is not None and 4.0 < lat < 14.0 and 2.5 < lng < 15.0)
not_centroid = not (lat is not None and lng is not None and abs(lat - 9.2) < 0.05 and abs(lng - 8.2) < 0.05)
check("GET /api/gazetteer?q=Giwa returns a JSON object, not the SPA shell (GEO-03)",
      gs == 200 and g_obj, "status=%s json_object=%s head=%r" % (gs, g_obj, (graw or "")[:40]))
check("GET /api/gazetteer resolves a non-seed LGA to real Nigeria coords offline (GEO-03)",
      ok_flag and in_ng and not_centroid, "lat=%s lng=%s in_ng=%s not_centroid=%s" % (lat, lng, in_ng, not_centroid))
check("GET /api/gazetteer result carries a confidence grade (GEO-01 honoured) (GEO-03)",
      conf not in (None, ""), "confidence=%r" % conf)

# ---------------------------------------------------------------------------
# F. WAKA-01 — road-aware corridor scan returns per-segment risk
# ---------------------------------------------------------------------------
print("\n-- F. WAKA-01: GET /api/route?from=Abuja&to=Kaduna returns PER-SEGMENT corridor risk (not 2-endpoint) --")
# A real corridor scan densifies the route into ordered segments and scores each,
# so it catches danger BETWEEN the endpoints (the straight-line two-endpoint scan
# misses it). It must also stay honestly labelled a corridor approximation, never
# implying true road routing.
rs, rj, rraw = call("GET", "/api/route?from=Abuja&to=Kaduna", want_token=False)
r_obj = _is_json_obj(rj) and rraw.lstrip().startswith("{")
segs = None
if isinstance(rj, dict):
    for key in ("segments", "segment_risk", "legs"):
        if isinstance(rj.get(key), list):
            segs = rj[key]
            break
    if segs is None and isinstance(rj.get("route"), dict) and isinstance(rj["route"].get("segments"), list):
        segs = rj["route"]["segments"]
seg_ok = isinstance(segs, list) and len(segs) >= 2
# Each segment must carry its own risk reading (a level or a numeric score).
per_seg_risk = seg_ok and all(
    isinstance(sg, dict) and (_get(sg, "level", "risk", "status") is not None or _num(_get(sg, "score")) is not None)
    for sg in segs)
# The payload must stay honest that this is a corridor approximation, not road routing.
blob = json.dumps(rj).lower() if isinstance(rj, dict) else ""
honest_label = ("corridor" in blob) or ("approximation" in blob) or ("not road" in blob)
check("GET /api/route returns a JSON object, not the SPA shell (WAKA-01)",
      rs == 200 and r_obj, "status=%s json_object=%s head=%r" % (rs, r_obj, (rraw or "")[:40]))
check("GET /api/route?from=Abuja&to=Kaduna densifies into >=2 ordered segments (WAKA-01)",
      seg_ok, "segment_count=%s" % (len(segs) if isinstance(segs, list) else segs))
check("GET /api/route reports per-segment risk (level/score on every segment) (WAKA-01)",
      per_seg_risk, "per_segment_risk=%s" % per_seg_risk)
check("GET /api/route labels itself a corridor approximation, not road routing (WAKA-01 honesty)",
      honest_label, "honest_label=%s" % honest_label)

# ---------------------------------------------------------------------------
print("\n=== QUALITY RESULT: %d passed, %d failed ===" % (P[0], F[0]))
for x in FAILS:
    print("  FAIL: " + x)
print("RESULT quality %d/%d passed (%d failed)" % (P[0], P[0] + F[0], F[0]))
sys.exit(1 if F[0] else 0)
