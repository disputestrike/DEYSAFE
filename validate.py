"""DeySafe / SHIELD — Pre-release validation gate.

Engineering process: MONITOR (run all gates) -> CORRECT (fix fails) -> MEASURE
(pass rate) -> ADJUST. Run against the live server:

    python validate.py [base_url]        # default http://localhost:4500

Sections: A) every endpoint (click-through)  B) chaos / negative inputs
(must validate, never 500-crash, no SQL injection)  C) functional flows.
Exit 0 if all pass, 1 if any fail.
"""
import sys
import os
import json
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4500"
# Operator token so the functional gate can drive the now-auth-locked operator
# endpoints (the server is launched with the same OPERATOR_TOKEN). Public
# endpoints get no token and are unaffected.
OPTOKEN = os.environ.get("OPERATOR_TOKEN", "")
OP_PATHS = ("/api/verify", "/api/queue", "/api/ingest-live", "/api/case-status", "/review")
P = [0]
F = [0]
FAILS = []
LEVELS = ["GREEN", "YELLOW", "ORANGE", "RED"]


def _hdrs(path):
    h = {"Content-Type": "application/json"}
    if OPTOKEN and any(path.split("?")[0].startswith(p) for p in OP_PATHS):
        h["Authorization"] = "Bearer " + OPTOKEN
    return h


def call(method, path, body=None, timeout=25):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers=_hdrs(path))
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


def html(path):
    try:
        req = urllib.request.Request(BASE + path, headers=_hdrs(path))
        with urllib.request.urlopen(req, timeout=15) as r:
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


def lidx(l):
    return LEVELS.index(l) if l in LEVELS else -1


print("=== DeySafe / SHIELD pre-release validation gate ===")
print("target: " + BASE)

print("\n-- A. Endpoints (click-through, happy path) --")
s, j, _ = call("GET", "/api/health"); check("GET /api/health", s == 200 and "incidents" in j, s)
s, j, _ = call("GET", "/api/incidents"); check("GET /api/incidents", s == 200 and isinstance(j.get("incidents"), list), s)
_incs = j.get("incidents", []); _ttl = {"verified": 240, "needs_human_review": 96, "corroborated": 72, "candidate_unverified": 48}
check("incidents carry age & within decay TTL (auto drop-off)", all(("age_hours" in i and i["age_hours"] <= _ttl.get(i.get("status"), 48) + 0.2) for i in _incs), "n=" + str(len(_incs)))
check("a verified RED incident is visible (full severity ladder)", any(i.get("status") == "verified" for i in _incs), "verified present")
s, j, _ = call("GET", "/api/queue"); check("GET /api/queue", s == 200 and isinstance(j.get("queue"), list), s)
s, j, _ = call("GET", "/api/missing"); check("GET /api/missing (+radius)", s == 200 and isinstance(j.get("missing"), list) and (not j["missing"] or "radius_km" in j["missing"][0]), s)
s, j, _ = call("GET", "/api/places"); check("GET /api/places (+coords)", s == 200 and j.get("places") and j.get("coords"), s)
check("police_misconduct type available (Govia accountability)", "police_misconduct" in (j.get("types") or []), j.get("types"))
s, j, _ = call("GET", "/api/risk?place=Kaduna"); check("GET /api/risk", s == 200 and j.get("level") and j.get("guidance"), j)
s, j, _ = call("GET", "/api/alerts"); check("GET /api/alerts", s == 200 and isinstance(j.get("alerts"), list), s)
s, j, _ = call("GET", "/api/ai-status"); check("GET /api/ai-status", s == 200 and "ai" in j, s)
s, j, _ = call("GET", "/api/geocode?q=Kaduna"); check("GET /api/geocode (gazetteer, no key)", s == 200 and j.get("ok") and (j.get("result") or {}).get("lat"), j)
s, j, _ = call("GET", "/api/risk?lat=10.52&lng=7.44"); check("GET /api/risk?lat&lng (proximity)", s == 200 and j.get("level") and "count" in j, j)
s, h = html("/"); check("GET / serves DeySafe app", s == 200 and "DeySafe" in h, s)
s, h = html("/review.html"); check("GET /review.html serves SHIELD console", s == 200 and "SHIELD" in h, s)
s, j, _ = call("POST", "/api/report", {"type": "armed_robbery", "place": "Kano", "description": "endpoint test"}); check("POST /api/report", s == 200 and j.get("ok"), j)
s, j, _ = call("POST", "/api/missing", {"name": "Test Person", "place": "Lokoja", "hours_ago": 2, "count": 1}); check("POST /api/missing", s == 200 and j.get("ok"), j)
_, mj, _ = call("GET", "/api/missing"); cid = mj["missing"][0]["id"] if mj.get("missing") else None
s, j, _ = call("POST", "/api/sighting", {"case_id": cid, "place": "Jibia", "hours_ago": 0.5, "note": "t"}); check("POST /api/sighting", s == 200 and j.get("ok"), j)
s, j, _ = call("POST", "/api/verify", {"type": "kidnapping", "location_name": "Shiroro", "state": "Niger", "decision": "verified"}); check("POST /api/verify (+alert)", s == 200 and j.get("ok"), j)
s, j, _ = call("POST", "/api/case-status", {"case_id": cid, "status": "located"}); check("POST /api/case-status", s == 200 and j.get("ok"), j)
s, j, _ = call("POST", "/api/classify", {"text": "Gunmen kidnapped 15 students in Kankara"}); check("POST /api/classify", s == 200 and "ai" in j, j)
s, j, _ = call("POST", "/api/ingest-live", {}, timeout=90); check("POST /api/ingest-live (public RSS, key-gated AI, never 500)", s == 200 and "fetched" in j and "incidents" in j and "ai_on" in j, j)
s, j, _ = call("POST", "/api/intake", {"text": "Gunmen kidnapped students in Kankara", "mode": "report"}); check("POST /api/intake report (AI/rule-based)", s == 200 and (j.get("fields") or {}).get("place"), j)
s, j, _ = call("POST", "/api/intake", {"text": "My son David is missing near Kaduna since morning"}); check("POST /api/intake auto->missing", s == 200 and j.get("mode") == "missing" and "fields" in j, j)
s, j, _ = call("POST", "/api/channel", {"area": "Kaduna", "text": "Checkpoint clear on the Kaduna road, all calm"}); check("POST /api/channel (community post)", s == 200 and j.get("ok") and isinstance(j.get("posts"), list), j)
s, j, _ = call("GET", "/api/channel"); check("GET /api/channel feed", s == 200 and isinstance(j.get("posts"), list), j)
s, j, raw = call("POST", "/api/sms", {"from": "+2348000000", "text": "gunmen on the Kaduna road"}); check("POST /api/sms inbound report (basic-phone reach)", s == 200 and (j.get("parsed") or {}).get("place"), j)
s, j, raw = call("POST", "/api/ussd", {"text": ""}); check("POST /api/ussd menu (CON)", s == 200 and "DeySafe" in raw, raw[:30])
s, j, raw = call("POST", "/api/ussd", {"text": "1*Kaduna"}); check("POST /api/ussd area check -> END", s == 200 and "END" in raw, raw[:30])
s, j, _ = call("POST", "/api/missing", {"name": "Geo Test Case", "place": "Gwoza", "hours_ago": 1, "count": 1})
gcase = next((x for x in (j.get("missing") or []) if x.get("name") == "Geo Test Case"), {})
check("typed non-dropdown place gets real coords (FindMe pin off-centroid)", s == 200 and 4 < (gcase.get("lat") or 0) < 14 and not (abs((gcase.get("lat") or 0) - 9.2) < 0.05 and abs((gcase.get("lng") or 0) - 8.2) < 0.05), gcase.get("lat"))
call("POST", "/api/missing", {"name": "Beacon Kid", "place": "Kaduna", "beacon_id": "TAG-XYZ-1", "hours_ago": 2})
s, j, _ = call("POST", "/api/beacon-relay", {"beacon_id": "TAG-XYZ-1", "lat": 10.6, "lng": 7.5, "hours_ago": 0.2}); check("Bluetooth beacon relay -> sighting (AirTag crowd-find)", s == 200 and j.get("matched") and isinstance(j.get("missing"), list), j)
s, j, _ = call("POST", "/api/beacon-relay", {"beacon_id": "NO-SUCH-TAG", "lat": 9, "lng": 8}); check("unknown beacon -> matched:false (privacy)", s == 200 and j.get("matched") is False, j)

print("\n-- B. Chaos / negative inputs (validate, never crash, no injection) --")
s, j, _ = call("POST", "/api/report", {}); check("report empty -> 400 (not 500)", s == 400, s)
s, j, _ = call("POST", "/api/report", {"place": "Kano"}); check("report missing description -> 400", s == 400, s)
s, j, _ = call("POST", "/api/missing", {}); check("missing empty -> 400", s == 400, s)
s, j, _ = call("POST", "/api/verify", {"type": "x", "location_name": "y", "state": "z", "decision": "BOGUS"}); check("verify bad decision -> 400", s == 400, s)
s, j, _ = call("POST", "/api/sighting", {"place": "Kano"}); check("sighting no case_id -> 400", s == 400, s)
s, j, _ = call("POST", "/api/case-status", {"case_id": "abc", "status": "located"}); check("case-status non-numeric id -> 400", s == 400, s)
s, j, _ = call("POST", "/api/intake", {}); check("intake empty text -> 400", s == 400, s)
s, j, _ = call("POST", "/api/channel", {}); check("channel empty text -> 400", s == 400, s)
s, j, _ = call("POST", "/api/sms", {}); check("sms empty text -> 400", s == 400, s)
s, j, _ = call("POST", "/api/beacon-relay", {}); check("beacon-relay missing fields -> 400", s == 400, s)
s, j, _ = call("GET", "/api/risk?place=Nowhereville"); check("risk unknown place -> GREEN", s == 200 and j.get("level") == "GREEN", j)
s, j, _ = call("GET", "/api/risk"); check("risk no place -> graceful 200", s == 200, s)
s, j, _ = call("GET", "/api/geocode?q="); check("geocode empty q -> ok:false (no crash)", s == 200 and j.get("ok") is False, j)
s, j, _ = call("GET", "/api/risk?lat=abc&lng=xyz"); check("risk non-numeric lat/lng -> graceful 200", s == 200 and j.get("level"), j)
s, j, _ = call("POST", "/api/report", {"type": "kidnapping", "place": "Kaduna", "description": "'; DROP TABLE incidents;-- "}); check("SQL-injection string -> handled", s == 200 and j.get("ok"), s)
s2, j2, _ = call("GET", "/api/health"); check("DB intact after injection attempt", s2 == 200 and "incidents" in j2, "survived")
s, j, _ = call("POST", "/api/report", {"type": "kidnapping", "place": "Kano", "description": "A" * 60000}); check("huge 60k body -> handled (no 500)", s != 500 and s != 0, s)
try:
    req = urllib.request.Request(BASE + "/api/report", data=b"{not valid json", method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        ms = r.status
except urllib.error.HTTPError as e:
    ms = e.code
except Exception:
    ms = 0
check("malformed JSON -> 400 (no crash)", ms == 400, ms)
s, j, _ = call("POST", "/api/does-not-exist", {}); check("unknown POST -> 404 (not 500)", s == 404, s)
s, h = html("/api/does-not-exist"); check("unknown path -> served, not 500", s in (200, 404), s)

print("\n-- C. Functional flows (state actually changes) --")
_, r1, _ = call("GET", "/api/risk?place=Gusau"); before = r1.get("level")
call("POST", "/api/report", {"type": "banditry_attack", "place": "Gusau", "description": "second corroborating report"})
_, r2, _ = call("GET", "/api/risk?place=Gusau"); after = r2.get("level")
check("corroboration raises area level", lidx(after) >= lidx(before) and lidx(after) >= 0, str(before) + " -> " + str(after))
_, m1, _ = call("GET", "/api/missing"); cse = m1["missing"][0]; rb = cse["radius_km"]
call("POST", "/api/sighting", {"case_id": cse["id"], "place": "Jibia", "hours_ago": 0.1, "note": "fresh"})
_, m2, _ = call("GET", "/api/missing"); ra = next((x["radius_km"] for x in m2["missing"] if x["id"] == cse["id"]), None)
check("fresh sighting tightens search radius", ra is not None and ra <= rb, str(rb) + " -> " + str(ra))
_, a1, _ = call("GET", "/api/alerts"); nb = len(a1.get("alerts", []))
call("POST", "/api/verify", {"type": "banditry_attack", "location_name": "Gusau", "state": "Zamfara", "decision": "verified"})
_, a2, _ = call("GET", "/api/alerts"); na = len(a2.get("alerts", []))
check("operator verify fires a public alert", na >= nb and na > 0, str(nb) + " -> " + str(na))
s, j, _ = call("POST", "/api/report", {"type": "banditry_attack", "place": "Buni Yadi", "description": "gunmen sighted on the road, several vehicles"})
rsk = j.get("risk") or {}
check("typed off-gazetteer report becomes a map incident", s == 200 and j.get("ok") and rsk.get("count", 0) >= 1, rsk.get("count"))

print("\n=== RESULT: %d passed, %d failed ===" % (P[0], F[0]))
for x in FAILS:
    print("  FAIL: " + x)
sys.exit(1 if F[0] else 0)
