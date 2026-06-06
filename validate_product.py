"""DeySafe / SHIELD product-priority gate.

Proves the new product layer is wired, gated, and redacted:
  - Phone Safety Readiness
  - Journey Guard
  - SHIELD case workspace
  - restricted evidence / GeoTrace
  - Safety Points / Sentinel Network
  - Guardian Mesh / tracker registry
  - ops agreements / drills

Run with a server started using OPERATOR_TOKEN and DEMO_MODE, or via:
  powershell -ExecutionPolicy Bypass -File scripts/verify_all.ps1
"""
import os
import sys
import json
import urllib.request
import urllib.error


BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4500"
OPTOKEN = os.environ.get("OPERATOR_TOKEN", "")

OP_PATHS = (
    "/api/journeys", "/api/cases", "/api/shield", "/api/case", "/api/evidence",
    "/api/geotrace", "/api/sentinels", "/api/mesh", "/api/trackers",
    "/api/ops-agreements", "/api/ops-drills", "/api/ops-readiness",
    "/api/safety-points",
)

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
                j = {}
            return r.status, j, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            j = json.loads(raw)
        except Exception:
            j = {}
        return e.code, j, raw
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


def has_any(d, keys):
    return any(k in d for k in keys)


print("=== DeySafe / SHIELD product-priority gate ===")
print("target: " + BASE)
if not OPTOKEN:
    print("note: OPERATOR_TOKEN is empty; operator-gated checks will show the gap.")


# A. Phone Safety Readiness
owner = "prod-gate-owner"
s, j, raw = call("POST", "/api/readiness", {
    "owner_token": owner,
    "platform": "gate",
    "findmy_enabled": True,
    "trusted_contacts": 2,
    "silent_sos": True,
    "sms_fallback": True,
    "offline_pack": True,
}, want_token=False)
ready = j.get("readiness") or {}
check("POST /api/readiness returns a scored checklist",
      s == 200 and j.get("ok") is True and ready.get("readiness_score", 0) >= 70,
      "status=%s score=%s" % (s, ready.get("readiness_score")))
s2, j2, _ = call("GET", "/api/readiness?owner_token=" + owner, want_token=False)
check("GET /api/readiness is owner-token scoped and returns saved score",
      s2 == 200 and (j2.get("readiness") or {}).get("readiness_score") == ready.get("readiness_score"),
      "status=%s" % s2)


# B. Journey Guard
s, j, raw = call("POST", "/api/journey/start", {
    "owner_token": owner,
    "from": "Abuja",
    "to": "Kaduna",
    "share_consent": False,
}, want_token=False)
journey = j.get("journey") or {}
jid = journey.get("journey_uuid") or journey.get("id")
check("POST /api/journey/start creates a redacted Journey Guard session",
      s == 200 and j.get("ok") is True and jid and journey.get("coords_redacted") is True,
      "status=%s journey=%s raw=%s" % (s, jid, raw[:160]))
s, j, raw = call("POST", "/api/journey/ping", {
    "journey_uuid": jid,
    "event_type": "checkin",
    "lat": 9.11111,
    "lng": 7.22222,
    "share_consent": False,
}, want_token=False)
check("POST /api/journey/ping works without exact GPS consent",
      s == 200 and j.get("ok") is True and (j.get("journey") or {}).get("coords_redacted") is True,
      "status=%s raw=%s" % (s, raw[:160]))
s, j, raw = call("GET", "/api/journey?id=" + str(jid), want_token=False)
pub_j = j.get("journey") or {}
check("GET /api/journey public projection omits raw GPS fields",
      s == 200 and not has_any(pub_j, ("lat", "lng", "last_lat", "last_lng", "owner_token")),
      "keys=%s" % sorted(pub_j.keys()))
s, j, _ = call("GET", "/api/journeys", want_token=False)
check("GET /api/journeys is operator gated",
      s == 401, "status=%s" % s)
s, j, _ = call("GET", "/api/journeys", want_token=True)
check("GET /api/journeys with token returns operator list",
      s == 200 and isinstance(j.get("journeys"), list), "status=%s" % s)


# C. SHIELD cases
s, j, raw = call("POST", "/api/cases", {
    "case_type": "journey",
    "subject_ref": jid,
    "summary": "product gate guarded journey",
    "family_liaison": "Amina",
    "incident_commander": "Bello",
    "requires_second_approval": True,
}, want_token=True)
case = j.get("case") or {}
cid = case.get("case_uuid")
check("POST /api/cases creates a SHIELD case with liaison/commander fields",
      s == 200 and cid and case.get("family_liaison") == "Amina" and case.get("incident_commander") == "Bello",
      "status=%s case=%s" % (s, cid))
s, j, _ = call("POST", "/api/case-update", {
    "case_uuid": cid,
    "body": "family liaison notified; no public exact-location release",
}, want_token=True)
check("POST /api/case-update appends case timeline updates",
      s == 200 and isinstance(j.get("updates"), list) and len(j.get("updates")) >= 1,
      "status=%s" % s)


# D. Restricted evidence / GeoTrace
s, j, raw = call("POST", "/api/evidence", {
    "case_uuid": cid,
    "evidence_type": "video",
    "title": "checkpoint clip",
    "source_label": "restricted analyst",
    "lat": 9.10101,
    "lng": 7.20202,
    "notes": "exact location and raw notes must stay restricted",
    "public_summary": "Restricted video reviewed by analyst.",
}, want_token=True)
ev = j.get("evidence") or {}
eid = ev.get("evidence_uuid")
check("POST /api/evidence stores custody hash and restricted evidence",
      s == 200 and eid and ev.get("custody_hash") and ev.get("lat") is not None,
      "status=%s evidence=%s" % (s, eid))
s, j, _ = call("GET", "/api/evidence-public?id=" + str(eid), want_token=False)
pub = j.get("evidence") or {}
check("GET /api/evidence-public redacts exact coords/source/custody/notes",
      s == 200 and pub.get("restricted") is True and not has_any(pub, ("lat", "lng", "custody_hash", "notes", "source_label")),
      "keys=%s" % sorted(pub.keys()))
s, j, raw = call("POST", "/api/geotrace", {
    "case_uuid": cid,
    "evidence_uuid": eid,
    "confidence": "medium",
    "method": "video_landmark_review",
    "area_label": "Kaduna-Abuja corridor",
    "lat": 9.1,
    "lng": 7.2,
    "radius_km": 12,
    "notes": "probability zone only",
}, want_token=True)
check("POST /api/geotrace labels analysis as restricted aid, not exact locator",
      s == 200 and j.get("ok") is True and "not an exact locator" in (j.get("note") or ""),
      "status=%s note=%s" % (s, j.get("note")))


# E. Safety Points / Sentinel
s, j, _ = call("POST", "/api/safety-points", {
    "name": "Unvetted Gate Point",
    "state": "Kaduna",
    "lat": 10.1,
    "lng": 7.4,
    "vetted": False,
}, want_token=True)
unvetted = (j.get("point") or {}).get("point_uuid")
s, j, _ = call("GET", "/api/safety-points", want_token=False)
public_points = j.get("points") or []
check("GET /api/safety-points hides unvetted points",
      s == 200 and all(p.get("point_uuid") != unvetted for p in public_points),
      "status=%s" % s)
s, j, _ = call("POST", "/api/safety-points", {
    "name": "Vetted Clinic Safe Point",
    "point_type": "clinic",
    "state": "Kaduna",
    "lat": 10.2,
    "lng": 7.5,
    "vetted": True,
}, want_token=True)
vetted = (j.get("point") or {}).get("point_uuid")
s, j, _ = call("GET", "/api/safety-points", want_token=False)
check("GET /api/safety-points exposes only vetted active public points",
      s == 200 and any(p.get("point_uuid") == vetted and p.get("vetted") is True for p in (j.get("points") or [])),
      "status=%s" % s)
s, j, _ = call("POST", "/api/sentinels", {
    "name": "Verified Observer",
    "org": "pilot partner",
    "trust_level": "verified",
    "state": "Kaduna",
}, want_token=True)
check("POST /api/sentinels records an opt-in sentinel roster item",
      s == 200 and (j.get("sentinel") or {}).get("trust_level") == "verified",
      "status=%s" % s)


# F. Mesh / trackers / ops weak spots
s, j, _ = call("POST", "/api/mesh/devices", {
    "owner_token": owner,
    "device_label": "family relay phone",
    "consent_scope": "trusted_circle",
    "rotating_id": "rot-abc",
}, want_token=True)
check("POST /api/mesh/devices records consent-scoped mesh device",
      s == 200 and (j.get("device") or {}).get("consent_scope") == "trusted_circle",
      "status=%s" % s)
s, j, _ = call("POST", "/api/trackers", {
    "owner_ref": cid,
    "label": "DeySafe Tag prototype",
    "tracker_type": "tag",
    "stable_id": "serial-123",
    "rotating_id": "rotating-123",
    "consent_status": "active",
}, want_token=True)
tracker = j.get("tracker") or {}
projection = j.get("public_projection") or {}
check("POST /api/trackers hashes stable IDs and public projection omits hash",
      s == 200 and len(tracker.get("stable_id_hash") or "") == 64 and "stable_id_hash" not in projection,
      "status=%s" % s)
s, j, _ = call("POST", "/api/ops-agreements", {
    "partner_name": "Pilot Response Partner",
    "partner_type": "clinic",
    "scope": "family liaison and safe handoff",
    "status": "active",
}, want_token=True)
check("POST /api/ops-agreements records escalation partner coverage",
      s == 200 and (j.get("agreement") or {}).get("partner_name") == "Pilot Response Partner",
      "status=%s" % s)
s, j, _ = call("POST", "/api/ops-drills", {
    "drill_type": "tabletop",
    "participants": "operator, liaison, responder",
    "outcome": "handoff path tested",
    "gaps": "live channel proof still pending",
}, want_token=True)
check("POST /api/ops-drills records drill and remaining gaps",
      s == 200 and (j.get("drill") or {}).get("gaps"),
      "status=%s" % s)
s, j, _ = call("GET", "/api/ops-readiness", want_token=True)
ops = j.get("ops_readiness") or {}
check("GET /api/ops-readiness summarizes weak operational gaps",
      s == 200 and ops.get("sentinels", 0) >= 1 and ops.get("safety_points", 0) >= 2
      and ops.get("agreements", 0) >= 1 and ops.get("drills", 0) >= 1,
      "status=%s ops=%s" % (s, ops))


print("\nRESULT: %d passed, %d failed" % (P[0], F[0]))
if FAILS:
    print("FAILURES:")
    for f in FAILS:
        print(" - " + f)
    sys.exit(1)
sys.exit(0)
