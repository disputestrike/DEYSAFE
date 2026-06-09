"""DeySafe hostile-device personal beta gate.

Run with a server started in demo/OTP echo mode:

    python validate_personal_beta.py [base_url]

This gate proves the phone-facing beta is not just UI:
  - account/OTP session exists
  - guardian PII is not stored/rendered in the browser bundle
  - Safety Vault is server-side and redacted
  - Journey/SOS ownership checks fail closed
  - Safety PIN and Duress PIN drive distinct SOS states
  - Web Push registration/test/confirm contracts exist
  - MySafe and SafeMeet AI intake are wired
"""
import json
import os
import sys
import urllib.error
import urllib.request


BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4500"
ROOT = os.path.dirname(os.path.abspath(__file__))
OPTOKEN = os.environ.get("OPERATOR_TOKEN", "")

P = [0]
F = [0]
FAILS = []


def call(method, path, body=None, token="", operator=False, timeout=25, extra_headers=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if operator and OPTOKEN:
        headers["Authorization"] = "Bearer " + OPTOKEN
        headers["X-Operator-Token"] = OPTOKEN
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw), raw
            except Exception:
                return r.status, {}, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw), raw
        except Exception:
            return e.code, {}, raw
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


def app_text(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


print("=== DeySafe hostile-device personal beta gate ===")
print("target: " + BASE)

app_html = app_text(os.path.join("app", "index.html"))
sw_js = app_text(os.path.join("app", "sw.js"))
api_py = app_text(os.path.join("engine", "api.py"))
identity_py = app_text(os.path.join("engine", "identity.py"))
db_py = app_text(os.path.join("engine", "db.py"))

check("browser bundle does not store guardian PII in ds_trusted localStorage",
      "ds_trusted" not in app_html and "tcAddress" not in app_html and "contacts:tcLoad" not in app_html)
check("Profile exposes phone session, Safety PINs, Safety Vault, push, and MySafe",
      all(x in app_html for x in (
          "/api/signup/start", "/api/profile/pins", "/api/vault/guardians",
          "/api/push/config", "/api/mysafe/places", "Emergency contacts")))
check("Browser session uses HttpOnly cookie path instead of persistent localStorage bearer",
      "Set-Cookie" in api_py and "ds_session" in api_py and "localStorage.setItem('ds_session'" not in app_html
      and "localStorage.removeItem('ds_session')" in app_html,
      "session cookie/localStorage markers missing")
check("Safety Vault stores guardian addresses as encrypted ciphertext",
      "address_ciphertext" in identity_py and "encrypt_secret" in identity_py
      and "guardian_address" in identity_py and "address_ciphertext" in db_py,
      "guardian ciphertext markers missing")
check("SafeMeet is voice-first and AI-filled",
      "meetNL" in app_html and "fillSafeMeetAI" in app_html and "mode:'meet'" in app_html)
check("service worker can display push notifications",
      "self.addEventListener('push'" in sw_js and "showNotification" in sw_js and "notificationclick" in sw_js)

s, j, _ = call("GET", "/api/me")
check("GET /api/me without session is rejected", s == 401, "status=%s" % s)

phone = "+2348000001234"
s, j, raw = call("POST", "/api/signup/start", {"phone": phone, "device_id": "gate-device"})
otp = j.get("dev_otp")
check("POST /api/signup/start returns demo OTP in validation mode",
      s == 200 and j.get("ok") is True and otp and j.get("otp_ref"), "status=%s raw=%s" % (s, raw[:160]))

s, j, raw = call("POST", "/api/signup/verify", {
    "otp_ref": j.get("otp_ref"),
    "code": otp,
    "first_name": "Gate",
    "language": "en",
    "device_id": "gate-device",
})
token = j.get("session_token") or ""
check("POST /api/signup/verify creates a session token",
      s == 200 and j.get("ok") is True and token.startswith("dsu."), "status=%s raw=%s" % (s, raw[:160]))

s, j, _ = call("GET", "/api/me", token=token)
policy = (j.get("user") or {}).get("guardian_policy_id")
check("GET /api/me with session returns redacted user and policy",
      s == 200 and j.get("ok") is True and policy and "phone" in (j.get("user") or {}), "status=%s" % s)

s, j, _ = call("GET", "/api/me", extra_headers={"Cookie": "ds_session=" + token})
check("GET /api/me accepts HttpOnly cookie session without bearer token",
      s == 200 and j.get("ok") is True and (j.get("user") or {}).get("guardian_policy_id") == policy,
      "status=%s" % s)

s, j, _ = call("POST", "/api/profile/pins", {
    "app_pin": "1111",
    "safety_pin": "2468",
    "duress_pin": "8642",
}, token=token)
check("POST /api/profile/pins stores distinct Safety and Duress PINs",
      s == 200 and j.get("ok") is True and (j.get("pins") or {}).get("duress") is True,
      "status=%s raw=%s" % (s, j))

s, j, _ = call("GET", "/api/vault/guardians")
check("GET /api/vault/guardians without session is rejected", s == 401, "status=%s" % s)

s, j, raw = call("POST", "/api/vault/guardians", {
    "name": "Amina",
    "channel": "sms",
    "address": "+2348000000001",
}, token=token)
g1 = j.get("guardian") or {}
g1_code = j.get("dev_verification_code") or ""
check("first guardian can be added after phone verification",
      s == 200 and j.get("ok") is True and g1.get("address_redacted") and g1_code,
      "status=%s raw=%s" % (s, raw[:160]))

s, j, _ = call("POST", "/api/vault/guardians/verify", {
    "guardian_uuid": g1.get("guardian_uuid"),
    "code": g1_code,
}, token=token)
check("guardian verification confirms Safety Vault contact",
      s == 200 and j.get("ok") is True and (j.get("guardian") or {}).get("verified") is True,
      "status=%s raw=%s" % (s, j))

s, j, _ = call("POST", "/api/vault/guardians", {
    "name": "Bello",
    "channel": "sms",
    "address": "+2348000000002",
    "safety_pin": "0000",
}, token=token)
check("second guardian requires correct Safety PIN step-up", s == 403, "status=%s" % s)

s, j, _ = call("POST", "/api/vault/guardians", {
    "name": "Bello",
    "channel": "sms",
    "address": "+2348000000002",
    "safety_pin": "2468",
}, token=token)
check("second guardian succeeds with correct Safety PIN", s == 200 and j.get("ok") is True, "status=%s" % s)

s, j, raw = call("GET", "/api/vault/guardians", token=token)
guardians = j.get("guardians") or []
check("Safety Vault list is redacted and server-side",
      s == 200 and len(guardians) >= 2 and all("address" not in g and "address_redacted" in g for g in guardians),
      "status=%s raw=%s" % (s, raw[:200]))

s, j, _ = call("POST", "/api/readiness", {
    "platform": "gate",
    "findmy_enabled": True,
    "silent_sos": True,
    "sms_fallback": True,
    "offline_pack": True,
}, token=token)
ready = j.get("readiness") or {}
check("readiness uses server guardian count for verified users",
      s == 200 and ready.get("trusted_contacts", 0) >= 2, "status=%s readiness=%s" % (s, ready))

s, j, raw = call("POST", "/api/journey/start", {
    "from": "Abuja",
    "to": "Kaduna",
    "share_consent": False,
}, token=token)
journey = j.get("journey") or {}
jid = journey.get("journey_uuid")
check("Journey Guard starts under verified user ownership",
      s == 200 and j.get("ok") is True and jid, "status=%s raw=%s" % (s, raw[:160]))

s, j, _ = call("POST", "/api/journey/ping", {
    "journey_uuid": jid,
    "owner_token": "stolen-phone",
    "event_type": "arrived",
})
check("wrong owner cannot ping someone else's Journey Guard",
      s == 403 and j.get("ok") is False, "status=%s" % s)

s, j, _ = call("POST", "/api/journey/ping", {
    "journey_uuid": jid,
    "event_type": "auto_checkin",
    "share_consent": False,
}, token=token)
check("session owner can ping Journey Guard",
      s == 200 and j.get("ok") is True, "status=%s" % s)

s, j, _ = call("POST", "/api/sos", {
    "mode": "silent",
    "message": "gate SOS",
    "notify": True,
    "guardian_policy_id": policy,
    "client_id": "gate-sos-1",
}, token=token)
sos_id = j.get("sos_uuid")
check("SOS create uses server Vault policy and returns durable ref",
      s == 200 and j.get("ok") is True and sos_id and j.get("ref"), "status=%s" % s)

s, j, _ = call("POST", "/api/sos", {"sos_uuid": sos_id, "cancel": True}, token=token)
check("SOS closure without PIN is rejected", s == 403, "status=%s" % s)

s, j, _ = call("POST", "/api/sos", {"sos_uuid": sos_id, "cancel": True, "pin": "2468"}, token=token)
check("Safety PIN requests verified SOS closure, not direct close",
      s == 200 and j.get("state") == "CLOSE_REQUESTED", "status=%s state=%s" % (s, j.get("state")))

s, j, _ = call("POST", "/api/sos", {
    "mode": "silent",
    "message": "gate duress SOS",
    "notify": True,
    "guardian_policy_id": policy,
    "client_id": "gate-sos-2",
}, token=token)
sos_duress = j.get("sos_uuid")
s, j, _ = call("POST", "/api/sos", {"sos_uuid": sos_duress, "cancel": True, "pin": "8642"}, token=token)
check("Duress PIN shows local closure while escalation remains marked",
      s == 200 and j.get("duress") is True and j.get("state") == "DURESS_CONFIRMED",
      "status=%s state=%s duress=%s" % (s, j.get("state"), j.get("duress")))

s, j, _ = call("POST", "/api/push/register", {
    "subscription": {"endpoint": "local-permission://gate-device", "keys": {"p256dh": "local", "auth": "local"}},
    "device_id": "gate-device",
}, token=token)
sub_id = j.get("subscription_id")
check("Web Push registration contract stores a subscription", s == 200 and sub_id, "status=%s" % s)

s, j, _ = call("POST", "/api/push/test", {"subscription_id": sub_id}, token=token)
check("Web Push test contract requires visible receipt confirmation",
      s == 200 and j.get("ok") is True and "confirm" in (j.get("note") or "").lower(), "status=%s" % s)

s, j, _ = call("POST", "/api/push/confirm", {"subscription_id": sub_id}, token=token)
check("Web Push receipt confirmation is recorded", s == 200 and j.get("confirmed") is True, "status=%s" % s)

s, j, _ = call("POST", "/api/mysafe/places", {"alias": "Home", "place": "Abuja"}, token=token)
check("MySafe place saves through verified session", s == 200 and j.get("ok") is True, "status=%s" % s)

s, j, _ = call("POST", "/api/mysafe/routes", {
    "origin_alias": "Home",
    "destination_alias": "Work",
    "days": "weekdays",
    "departure_window": "07:00-08:00",
}, token=token)
check("MySafe recurring route saves through verified session", s == 200 and j.get("ok") is True, "status=%s" % s)

s, j, _ = call("POST", "/api/intake", {"mode": "meet", "text": "I am meeting a seller at Computer Village by 4pm"}, token=token)
fields = j.get("fields") or {}
check("AI intake supports SafeMeet mode", s == 200 and j.get("mode") == "meet" and fields.get("meeting_type"),
      "status=%s fields=%s" % (s, fields))

s, j, _ = call("POST", "/api/missing", {
    "name": "Receipt Test",
    "place": "Kaduna",
    "hours_ago": 1,
    "count": 1,
})
check("POST /api/missing returns receipt only, not restricted missing list",
      s == 200 and j.get("ok") is True and "missing" not in j, "status=%s keys=%s" % (s, sorted(j.keys())))

s, j, _ = call("POST", "/api/safety-tick", {}, operator=True)
check("operator safety tick endpoint runs server-side stale timers",
      s == 200 and j.get("ok") is True and "journeys_checked" in j, "status=%s raw=%s" % (s, j))

print("\nRESULT: %d passed, %d failed" % (P[0], F[0]))
if FAILS:
    print("FAILURES:")
    for f in FAILS:
        print(" - " + f)
    sys.exit(1)
sys.exit(0)
