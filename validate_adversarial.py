"""Adversarial / denial-condition gate (the 'prove the attacker is BLOCKED' suite).

Unlike the happy-path validators, every check here asserts that a HOSTILE request is
REJECTED: missing credential, wrong credential, raw-id-as-authority, unsigned relay,
under-privileged role, anonymous destructive action, forged webhook, PII leak. This is
the test regime a serious safety org runs before launch.

Run against a server started with the adversarial profile (see scripts/run_adversarial):
  DEYSAFE_OPERATORS=viewer1:viewer:<h>,admin1:admin:<h>
  DEYSAFE_WEBHOOK_SECRET=hooksecret   DEYSAFE_BEACON_SECRET=beaconsecret
  OPERATOR_TOKEN=''                    DEMO_MODE=true
"""
import json
import sys
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4500"
P = [0]
F = [0]
FAILS = []


def chk(name, cond, detail=""):
    (P if cond else F)[0] += 1
    print(("  [PASS] " if cond else "  [FAIL] ") + name + ("" if cond else "  <%s>" % detail))
    if not cond:
        FAILS.append(name)


def call(method, path, body=None, token=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"_err": repr(e)}


def login(user, pw):
    _, r = call("POST", "/api/login", {"username": user, "password": pw})
    return r.get("token")


print("=== ADVERSARIAL / DENIAL-CONDITION GATE ===")

# ---------------------------------------------------------------- RED-03 journey
s, j = call("POST", "/api/journey/start",
            {"owner_token": "OWNER-AAA", "from": "Kaduna", "to": "Abuja", "mode": "road"})
jid = j.get("journey_uuid") or (j.get("journey") or {}).get("journey_uuid") or j.get("id")
if jid:
    s1, _ = call("POST", "/api/journey/ping", {"journey_uuid": jid, "event_type": "duress"})
    chk("journey/ping with NO owner_token is rejected (not 200)", s1 != 200, s1)
    s2, _ = call("POST", "/api/journey/ping", {"journey_uuid": jid, "owner_token": "WRONG", "event_type": "duress"})
    chk("journey/ping with WRONG owner_token is rejected", s2 != 200, s2)
    s3, _ = call("POST", "/api/journey/arrive", {"journey_uuid": jid})
    chk("journey/arrive with NO owner_token is rejected", s3 != 200, s3)
    s4, j4 = call("POST", "/api/journey/ping", {"journey_uuid": jid, "owner_token": "OWNER-AAA", "event_type": "checkin"})
    chk("journey/ping with CORRECT owner_token is accepted", s4 == 200, (s4, j4))
else:
    chk("journey/start created a session to attack", False, j)

# ---------------------------------------------------------------- RED-05 SOS
s, so = call("POST", "/api/sos", {"owner_token": "SOS-OWNER-1", "mode": "silent", "message": "help",
                                  "lat": 10.5, "lng": 7.4})
ref = so.get("ref") or so.get("handoff_ref") or so.get("sos_uuid") or so.get("id")
if ref:
    s1, r1 = call("POST", "/api/sos", {"sos_uuid": so.get("sos_uuid") or ref, "ref": ref, "cancel": True})
    closed = (str((r1 or {}).get("state") or (r1 or {}).get("status") or "")).upper() == "CLOSED"
    chk("SOS cancel with NO owner cannot hard-CLOSE the event", not (s1 == 200 and closed), (s1, r1))
else:
    chk("SOS created to attack", False, so)

# ---------------------------------------------------------------- RED-01 missing leak
s, m = call("POST", "/api/missing", {"name": "Test", "place": "Kankara", "exact_place": "Secret School 12",
                                     "vehicle": "Black Hilux XYZ", "direction": "north forest",
                                     "beacon_id": "SECRET-BEACON", "description": "victim"})
blob = json.dumps(m).lower()
leaked = any(w in blob for w in ("secret school", "black hilux", "secret-beacon", "north forest")) or isinstance(m.get("missing"), list)
chk("public /api/missing POST returns ONLY a receipt (no restricted leak)", (s == 200 and m.get("case_ref") and not leaked), (s, list(m.keys())))

# ---------------------------------------------------------------- RED-02 beacon
s, b = call("POST", "/api/beacon-relay", {"beacon_id": "SECRET-BEACON", "lat": 1.0, "lng": 1.0})
chk("unsigned beacon-relay rejected when a beacon secret is set", s != 200, s)
chk("beacon-relay reply carries no missing-person PII", "secret school" not in json.dumps(b).lower(), b)

# ---------------------------------------------------------------- RED-06/07 operator auth + role
s, _ = call("POST", "/api/verify", {"type": "banditry_attack", "location_name": "Gusau", "state": "Zamfara", "decision": "verified"})
chk("/api/verify with NO operator token is rejected (401)", s == 401, s)
s, _ = call("POST", "/api/verify", {"type": "banditry_attack", "location_name": "Gusau", "state": "Zamfara", "decision": "verified"},
            headers={"Authorization": "Bearer not-a-real-token"})
chk("/api/verify with a BOGUS token is rejected", s in (401, 403), s)
tv = login("viewer1", "viewerpw")
if tv:
    s, _ = call("POST", "/api/verify", {"type": "banditry_attack", "location_name": "Gusau", "state": "Zamfara", "decision": "verified"}, token=tv)
    chk("/api/verify by a 'viewer' role is rejected (403 RBAC)", s == 403, s)
sgq, _ = call("GET", "/api/sos-queue?token=not-a-real-token")
chk("operator route does NOT accept ?token= query credential", sgq == 401, sgq)

# ---------------------------------------------------------------- erasure (mine)
s, _ = call("POST", "/api/erasure", {"address": "+2348011112222", "confirm": "ERASE"})
chk("anonymous /api/erasure is rejected (401)", s == 401, s)

# ---------------------------------------------------------------- RED-09 webhook
s, _ = call("POST", "/api/sms", {"from": "+234800", "text": "gunmen near Kano"})
chk("inbound /api/sms with NO webhook secret is rejected (401)", s == 401, s)

print("\n=== ADVERSARIAL RESULT: %d passed, %d failed ===" % (P[0], F[0]))
for x in FAILS:
    print("  FAIL: " + x)
sys.exit(1 if F[0] else 0)
