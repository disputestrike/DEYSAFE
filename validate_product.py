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
import time
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


# Launch UX / PWA / WakaSafe regression gates
s, j, raw = call("GET", "/api/places", want_token=False)
check("GET /api/places is broad autocomplete, not a hardcoded travel boundary",
      s == 200 and j.get("open_search") is True and int(j.get("count") or 0) >= 100
      and len(j.get("places") or []) >= 100,
      "status=%s count=%s source=%s" % (s, j.get("count"), j.get("source")))
s, j, raw = call("GET", "/api/route?from=Abuja&to=Kaduna", want_token=False)
check("GET /api/route exposes auto-renderable road/fallback route metadata",
      s == 200 and j.get("ok") is True and j.get("route_mode") in ("road", "corridor")
      and isinstance(j.get("waypoints"), list) and len(j.get("waypoints") or []) >= 2
      and "road_routing" in j and j.get("from_place") and j.get("to_place"),
      "status=%s mode=%s waypoints=%s raw=%s" % (s, j.get("route_mode"), len(j.get("waypoints") or []), raw[:160]))
app_path = os.path.join(os.path.dirname(__file__), "app", "index.html")
sw_path = os.path.join(os.path.dirname(__file__), "app", "sw.js")
manifest_path = os.path.join(os.path.dirname(__file__), "app", "manifest.json")
gitignore_path = os.path.join(os.path.dirname(__file__), ".gitignore")
env_example_path = os.path.join(os.path.dirname(__file__), ".env.example")
try:
    app_html = open(app_path, encoding="utf-8").read()
    sw_js = open(sw_path, encoding="utf-8").read()
    manifest_json = open(manifest_path, encoding="utf-8").read()
    gitignore_txt = open(gitignore_path, encoding="utf-8").read()
    env_example = open(env_example_path, encoding="utf-8").read()
except Exception:
    app_html = ""
    sw_js = ""
    manifest_json = ""
    gitignore_txt = ""
    env_example = ""
check("PWA install path is wired in the browser app",
      "beforeinstallprompt" in app_html and "installApp" in app_html
      and "serviceWorker.register('/sw.js')" in app_html,
      "install/register markers missing")
check("Service worker caches the shell while keeping live API calls network-first",
      "SHELL_CACHE" in sw_js and "startsWith('/api/')" in sw_js and "caches.open" in sw_js,
      "service worker markers missing")
check("WakaSafe auto-renders route on map and no longer asks to view route",
      "Road route rendered automatically" in app_html and "View route on map" not in app_html
      and "go('home')" in app_html,
      "auto-route markers missing")
check("WakaSafe starts Journey Guard automatically instead of exposing manual trip buttons",
      "Start WakaSafe" in app_html and "startJourneyAutoWatch" in app_html
      and "Start guard" not in app_html and "Check in</button>" not in app_html
      and "Mark arrived" not in app_html,
      "manual guard controls still visible")
check("Privacy decoy lock is available for coercion-safe SOS concealment",
      'id="decoy"' in app_html and "panicLock" in app_html and "Privacy lock" in app_html
      and "Trip Notes" in app_html,
      "decoy lock markers missing")
check("Report screen exposes camera/video evidence capture metadata",
      'id="rMedia"' in app_html and "capture=\"environment\"" in app_html
      and "mediaMetaFromInput" in app_html,
      "media capture markers missing")
check("Home screen exposes AI evidence review for image/video triage",
      'id="aiMedia"' in app_html and "AI evidence review" in app_html
      and "analyzeEvidence" in app_html and "/api/media/analyze" in app_html,
      "AI evidence review markers missing")
check("Cloudflare R2 browser evidence upload path is wired",
      "/api/media/presign" in app_html and "uploadEvidenceIfAny" in app_html
      and "CLOUDFLARE_R2_BUCKET" in env_example,
      "R2 upload markers/env docs missing")
check("DeySafe PWA branding assets are wired into manifest, shell cache, and header",
      "deysafe-icon-192.png" in app_html and "deysafe-icon-192.png" in manifest_json
      and "deysafe-icon-512.png" in manifest_json and "deysafe-favicon.png" in sw_js,
      "branding assets missing")
check("Repository hygiene ignores runtime artifacts without Markdown fences",
      "```" not in gitignore_txt and ".env" in gitignore_txt and "__pycache__/" in gitignore_txt
      and ".verify-logs/" in gitignore_txt and "!.env.example" in gitignore_txt,
      "gitignore hygiene markers missing")
check("Readiness moved into settings instead of cluttering WakaSafe",
      'id="v-settings"' in app_html and "Phone Safety Readiness" in app_html
      and "settingsBtn" in app_html,
      "settings/readiness markers missing")
time.sleep(1.0)  # Wait for rate limit reset
s, j, raw = call("POST", "/api/report", {
    "type": "armed_robbery",
    "place": "Kaduna",
    "description": "robbery report with camera evidence metadata",
    "media": {"name": "clip.mp4", "type": "video/mp4", "size": 12345,
              "hash": "a" * 64},
}, want_token=False)
check("POST /api/report preserves camera/video evidence fingerprint metadata",
      s == 200 and j.get("ok") is True and (j.get("evidence_meta") or {}).get("hash") == "a" * 64,
      "status=%s evidence=%s raw=%s" % (s, j.get("evidence_meta"), raw[:160]))
s, j, raw = call("POST", "/api/media/presign", {
    "name": "clip.mp4",
    "type": "video/mp4",
    "size": 1000,
}, want_token=False)
check("POST /api/media/presign exposes key-gated Cloudflare R2 upload contract",
      s == 200 and j.get("ok") is True and j.get("provider") == "cloudflare_r2"
      and "configured" in j,
      "status=%s raw=%s" % (s, raw[:200]))
s, j, raw = call("POST", "/api/media/analyze", {
    "media": {"name": "checkpoint.jpg", "type": "image/jpeg", "size": 2048,
              "hash": "b" * 64},
    "context": "Police checkpoint near Ikeja bridge, blue Hilux and badge visible",
}, want_token=False)
check("POST /api/media/analyze gives honest evidence AI triage without faking vision",
      s == 200 and j.get("ok") is True and j.get("provider") == "deysafe_media_triage"
      and j.get("vision_ready") is False and (j.get("analysis") or {}).get("next_step")
      and (j.get("analysis") or {}).get("suggested_report") is not None,
      "status=%s raw=%s" % (s, raw[:240]))


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
    "owner_token": owner,
}, want_token=True)
check("POST /api/journey/ping requires owner_token for security (P0-03)",
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


# C. SafeMeet
check("SafeMeet frontend uses real API and foreground auto-watch",
      'id="v-meet"' in app_html and "/api/safemeet/start" in app_html
      and "startMeetWatch" in app_html and "/api/safemeet/end" in app_html,
      "SafeMeet UI/API markers missing")
s, j, raw = call("POST", "/api/safemeet/start", {
    "owner_token": owner,
    "meeting_type": "transaction",
    "meeting_place": "Kaduna",
    "meeting_address": "Central market gate",
    "meeting_lat": 10.5105,
    "meeting_lng": 7.4165,
    "expected_arrival": "12:30",
}, want_token=False)
meet = j.get("session") or {}
sid = j.get("session_uuid") or meet.get("session_uuid")
check("POST /api/safemeet/start creates a stored risk-scored meeting session",
      s == 200 and j.get("ok") is True and sid and meet.get("owner_token") is None
      and meet.get("risk_level") in ("low", "medium", "high", "critical"),
      "status=%s sid=%s raw=%s" % (s, sid, raw[:180]))
s, j, raw = call("POST", "/api/safemeet/checkin", {
    "owner_token": owner,
    "session_uuid": sid,
    "status": "arrived",
    "lat": 10.5107,
    "lng": 7.4168,
    "accuracy": 20,
}, want_token=False)
check("POST /api/safemeet/checkin records arrival and returns anomaly assessment",
      s == 200 and j.get("ok") is True and j.get("session_status") in ("in_progress", "scheduled")
      and isinstance(j.get("anomalies"), dict),
      "status=%s raw=%s" % (s, raw[:180]))
s, j, raw = call("GET", "/api/safemeet/list?owner_token=" + owner, want_token=False)
check("GET /api/safemeet/list is owner-scoped and redacted",
      s == 200 and any((m.get("session_uuid") == sid and "owner_token" not in m)
                       for m in (j.get("sessions") or [])),
      "status=%s raw=%s" % (s, raw[:180]))
s, j, raw = call("POST", "/api/safemeet/end", {
    "owner_token": owner,
    "session_uuid": sid,
}, want_token=False)
check("POST /api/safemeet/end completes the meeting on the server",
      s == 200 and j.get("ok") is True and (j.get("session") or {}).get("state") == "completed",
      "status=%s raw=%s" % (s, raw[:180]))


# D. SHIELD cases
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
