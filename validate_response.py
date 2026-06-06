"""DeySafe / SHIELD — Pre-release RESPONSE-LOOP gate (Phase 1).

Third gate in the family. Where validate.py proves "it doesn't crash" and
validate_security.py proves "it is safe / private / real", THIS gate proves the
RESPONSE LOOP exists: an SOS becomes a durable event, a human verify actually
reaches people (broadcast + delivery receipts) and creates a responder task with
human acknowledgement, alerts have a real lifecycle (cancel / TTL-expiry), and a
USSD missing-person report opens a real case with a reference number.

    python validate_response.py [base_url]      # default http://localhost:4500

Run the server in SIM broadcast mode so sends are testable WITHOUT real accounts:

    # bash
    DEMO_MODE=true OPERATOR_TOKEN=secgate-test-token DEYSAFE_BROADCAST_SIM=1 \
        python engine/api.py
    # PowerShell
    $env:DEMO_MODE='true'; $env:OPERATOR_TOKEN='secgate-test-token'; \
        $env:DEYSAFE_BROADCAST_SIM='1'; python engine/api.py

Then:  python validate_response.py

Same engineering loop as the other gates: MONITOR (run) -> CORRECT (fix the
fails) -> MEASURE (pass rate) -> ADJUST. Standard library only. Prints
[PASS]/[FAIL] per check and a RESULT summary; exits 1 if any check fails.

Like validate_security.py, every check ENCODES the required Phase-1 end state, so
the checks are EXPECTED TO FAIL against the current (pre-response-loop) build and
are driven GREEN as each fix lands.

Auth contract (must be preserved by the implementation):
  * FIELD endpoints stay public + rate-limited:  /api/sos, /api/ussd, GET /api/missing.
  * OPERATOR endpoints are fail-closed:  /api/verify, /api/responder/ack,
    /api/alert/cancel, and the operator visibility views (deliveries / responder
    tasks / sos queue) require a valid operator token.
This gate sends OPERATOR_TOKEN (env) ONLY on the operator-class paths, proving the
field paths work anonymously and the operator paths are actually gated.
"""
import sys
import os
import json
import time
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4500"
# Operator token for the fail-closed operator endpoints (the server is launched
# with the same OPERATOR_TOKEN). Field endpoints get NO token on purpose.
OPTOKEN = os.environ.get("OPERATOR_TOKEN", "")

# Operator-class path prefixes that should receive the token. Everything else
# (the FIELD surface) is called anonymously so we also prove it stays public.
OP_PATHS = (
    "/api/verify",
    "/api/responder",        # /api/responder/ack, /api/responder-tasks, /api/responders
    "/api/alert",            # /api/alert/cancel, /api/alert-cancel, /api/alert/update
    "/api/deliveries",
    "/api/sos-queue",
    "/api/sos-status",
)

P = [0]
F = [0]
FAILS = []


def _auth_for(path, want_token):
    """Return auth headers for a path. `want_token` lets a caller force token-on
    (operator probe) or token-off (the anonymous 401 probe) regardless of path."""
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


def _now_iso_past(seconds):
    import datetime
    return (datetime.datetime.now() - datetime.timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _str(x):
    return ("" if x is None else str(x)).strip()


print("=== DeySafe / SHIELD pre-release RESPONSE-LOOP gate (Phase 1) ===")
print("target: " + BASE)
print("(checks encode the required Phase-1 end state; they FAIL on the pre-response-loop build by design)")
if not OPTOKEN:
    print("note: OPERATOR_TOKEN is empty — operator-gated checks will document the gap (run the server with OPERATOR_TOKEN set).")

# ---------------------------------------------------------------------------
# A. SOS — durable event + state machine (SOS-01/02)
# ---------------------------------------------------------------------------
print("\n-- A. SOS: silent SOS creates a DURABLE event (TRIGGERED) that transitions + is readable (SOS-01/02) --")
# A1: a silent SOS (covert mode — no alarm) must create a durable, server-side
# event with its own id and an initial state of TRIGGERED. Field endpoint: public.
s, j, raw = call("POST", "/api/sos", {"kind": "silent", "lat": 10.52, "lng": 7.44,
                                      "message": "response-gate silent SOS"}, want_token=False)
sos_id = _get(j, "id", "sos_id", "sos_uuid", "uuid")
sos_state = _str(_get(j, "state", "status"))
check("POST /api/sos {kind:'silent'} -> ok + durable id (SOS-01)",
      s == 200 and bool(j.get("ok", True)) and bool(sos_id), "status=%s id=%s" % (s, sos_id))
check("POST /api/sos {kind:'silent'} -> initial state TRIGGERED (SOS-02 silent/covert)",
      sos_state.upper() == "TRIGGERED", "state=%r" % sos_state)

# A2: the event must be durably READABLE back (operator SOS queue or a GET by id),
# reflecting the same id + a non-empty state.
def _sos_lookup(target_id):
    """Find the SOS event by id across the likely read surfaces. Returns its dict or None."""
    if not target_id:
        return None
    tid = _str(target_id)
    # Try a direct GET first, then an operator queue/list view.
    for path in ("/api/sos?id=" + tid, "/api/sos/" + tid):
        st, jj, _ = call("GET", path, want_token=False)
        if st == 200 and isinstance(jj, dict):
            if any(_str(_get(jj, "id", "sos_id", "sos_uuid", "uuid")) == tid for _ in [0]):
                return jj
            for key in ("sos", "event"):
                node = jj.get(key)
                if isinstance(node, dict) and _str(_get(node, "id", "sos_id", "sos_uuid", "uuid")) == tid:
                    return node
    for path in ("/api/sos-queue", "/api/sos"):
        st, jj, _ = call("GET", path, want_token=True)
        if st == 200 and isinstance(jj, dict):
            for key in ("events", "sos", "queue", "items"):
                arr = jj.get(key)
                if isinstance(arr, list):
                    hit = next((e for e in arr if isinstance(e, dict)
                                and _str(_get(e, "id", "sos_id", "sos_uuid", "uuid")) == tid), None)
                    if hit:
                        return hit
    return None


found = _sos_lookup(sos_id)
check("SOS event is durably readable back (GET reflects the created event) (SOS-01)",
      found is not None, "id=%s not found on any SOS read surface" % sos_id)

# A3: an SOS UPDATE must TRANSITION the event to a new state (e.g. NOTIFYING /
# ACKED / ESCALATED / RESOLVED). We post an update and assert the readable state
# changed away from TRIGGERED. The update surface may be the same field endpoint
# (with the id) or an operator status endpoint — we try both.
def _sos_update(target_id):
    tid = _str(target_id)
    attempts = [
        ("POST", "/api/sos", {"id": tid, "kind": "silent", "status": "RESOLVED"}, False),
        ("POST", "/api/sos", {"sos_id": tid, "state": "RESOLVED"}, False),
        ("POST", "/api/sos-status", {"id": tid, "status": "ACKED"}, True),
        ("POST", "/api/sos-status", {"sos_id": tid, "state": "ACKED"}, True),
    ]
    last = None
    for method, path, payload, tok in attempts:
        st, jj, _ = call(method, path, payload, want_token=tok)
        last = (st, jj)
        if st == 200 and (jj.get("ok", True) is not False):
            return st, jj
    return last if last else (0, {})

if sos_id:
    us, uj = _sos_update(sos_id)
    after = _sos_lookup(sos_id)
    new_state = _str(_get(uj, "state", "status")) or _str(_get(after, "state", "status"))
    transitioned = bool(new_state) and new_state.upper() != "TRIGGERED"
    check("POST /api/sos update TRANSITIONS the event to a new state (SOS-01 state machine)",
          us == 200 and transitioned, "update_status=%s new_state=%r" % (us, new_state))
else:
    check("POST /api/sos update TRANSITIONS the event to a new state (SOS-01 state machine)",
          False, "no SOS id from create step")

# ---------------------------------------------------------------------------
# B. BROADCAST — verify fans out, delivery receipts recorded (BC-01/02/03)
# ---------------------------------------------------------------------------
print("\n-- B. BROADCAST: an operator RED verify records >=1 delivery; operator deliveries view shows it (BC-01/03) --")
# Seed a corroborating report so a real incident exists to verify, then verify it.
# In SIM mode (DEYSAFE_BROADCAST_SIM=1) the fan-out records 'sim_delivered' receipts
# WITHOUT real accounts — never a fabricated real send.
def _deliveries():
    """Operator deliveries view -> list of receipt dicts (tolerant of shape)."""
    st, jj, _ = call("GET", "/api/deliveries", want_token=True)
    if st != 200 or not isinstance(jj, dict):
        return st, None
    for key in ("deliveries", "receipts", "items", "log"):
        if isinstance(jj.get(key), list):
            return st, jj[key]
    return st, []

# Unauth deliveries view must be operator-gated (fail-closed) like /api/queue.
us, _, _ = call("GET", "/api/deliveries", want_token=False)
check("GET /api/deliveries without token -> 401/403 (operator-only receipts view)",
      us in (401, 403), "got " + str(us))

ds, before = _deliveries()
n_before = len(before) if isinstance(before, list) else None
call("POST", "/api/report",
     {"type": "kidnapping", "place": "Birnin Gwari", "description": "broadcast-gate corroboration A"})
call("POST", "/api/report",
     {"type": "kidnapping", "place": "Birnin Gwari", "description": "broadcast-gate corroboration B"})
vs, vj, _ = call("POST", "/api/verify",
                 {"type": "kidnapping", "location_name": "Birnin Gwari", "state": "Kaduna",
                  "decision": "verified"})
check("operator verify (RED kidnapping) succeeds for broadcast (auth + publish gate)",
      vs == 200 and vj.get("ok"), "status=%s ok=%s" % (vs, vj.get("ok")))

ds2, after = _deliveries()
n_after = len(after) if isinstance(after, list) else None
check("GET /api/deliveries reachable with token (operator deliveries view) (BC-03)",
      ds2 == 200 and isinstance(after, list), "status=%s type=%s" % (ds2, type(after).__name__))
# At least one delivery receipt exists for the just-fired alert (SIM mode counts).
grew = (n_before is not None and n_after is not None and n_after > n_before)
any_delivery = isinstance(after, list) and len(after) >= 1
check("operator RED verify records >=1 delivery receipt (BC-01/03; SIM mode counts)",
      grew or any_delivery, "before=%s after=%s" % (n_before, n_after))
# The receipt must be honest about SIM vs real (never fake a real send).
if isinstance(after, list) and after:
    rec = after[-1]
    st_val = _str(_get(rec, "status", "state")).lower()
    sim_flag = bool(_get(rec, "sim", default=False)) or "sim" in st_val or st_val == "sim_delivered"
    check("delivery receipt is explicitly SIM-flagged, not a faked real send (account-gated send rule)",
          sim_flag, "receipt=%s" % json.dumps(rec)[:160])
else:
    check("delivery receipt is explicitly SIM-flagged, not a faked real send (account-gated send rule)",
          False, "no receipts to inspect")

# ---------------------------------------------------------------------------
# C. RESPONDER — verify creates a task (received); ack moves it to responding (RESP-01/06)
# ---------------------------------------------------------------------------
print("\n-- C. RESPONDER: verify creates a responder_task (received); ack -> responding; unauth ack -> 401 (RESP-01/06) --")
def _responder_tasks():
    for path in ("/api/responder-tasks", "/api/responder/tasks", "/api/responder_tasks"):
        st, jj, _ = call("GET", path, want_token=True)
        if st == 200 and isinstance(jj, dict):
            for key in ("tasks", "responder_tasks", "items"):
                if isinstance(jj.get(key), list):
                    return st, jj[key]
    return st, None

# Unauth responder-tasks view must be operator-gated.
rs, _, _ = call("GET", "/api/responder-tasks", want_token=False)
check("GET /api/responder-tasks without token -> 401/403 (operator-only)",
      rs in (401, 403), "got " + str(rs))

# Fire a fresh verified incident dedicated to the responder check.
call("POST", "/api/report",
     {"type": "banditry_attack", "place": "Maru", "description": "responder-gate corroboration A"})
call("POST", "/api/report",
     {"type": "banditry_attack", "place": "Maru", "description": "responder-gate corroboration B"})
call("POST", "/api/verify",
     {"type": "banditry_attack", "location_name": "Maru", "state": "Zamfara", "decision": "verified"})

ts, tasks = _responder_tasks()
check("operator verify creates a responder_task (RESP-01 handoff)",
      ts == 200 and isinstance(tasks, list) and len(tasks) >= 1,
      "status=%s tasks=%s" % (ts, (len(tasks) if isinstance(tasks, list) else tasks)))

# The freshest task should be in the initial human-ack state 'received'
# (RESP-06: human ack states only — never auto-dispatch).
task = None
if isinstance(tasks, list) and tasks:
    task = tasks[0]
    received_ok = any(_str(_get(t, "status", "state")).lower() == "received" for t in tasks)
    check("a new responder_task is in state 'received' (RESP-06 human ack, no auto-dispatch)",
          received_ok, "states=%s" % [(_get(t, "status", "state")) for t in tasks[:5]])
else:
    check("a new responder_task is in state 'received' (RESP-06 human ack, no auto-dispatch)",
          False, "no tasks returned")

# Pick a task id in 'received' to ack.
def _task_id(t):
    return _get(t, "id", "task_id", "task_uuid", "uuid")

ack_target = None
if isinstance(tasks, list):
    ack_target = next((t for t in tasks if _str(_get(t, "status", "state")).lower() == "received"), None) \
        or (tasks[0] if tasks else None)
tid = _task_id(ack_target) if ack_target else None

# Unauthenticated ack MUST be rejected (401/403) — fail-closed operator action.
ua_status = None
if tid is not None:
    for path in ("/api/responder/ack", "/api/responder-ack"):
        st, _, _ = call("POST", path, {"id": tid, "task_id": tid, "status": "responding"},
                        want_token=False)
        ua_status = st
        if st in (401, 403):
            break
check("POST /api/responder/ack WITHOUT token -> 401/403 (operator-only ack)",
      ua_status in (401, 403), "got %s (task_id=%s)" % (ua_status, tid))

# Authenticated ack moves the task to 'responding'.
def _ack(target_id):
    last = None
    for path in ("/api/responder/ack", "/api/responder-ack"):
        st, jj, _ = call("POST", path,
                         {"id": target_id, "task_id": target_id, "status": "responding",
                          "state": "responding", "ack": True}, want_token=True)
        last = (st, jj)
        if st == 200 and (jj.get("ok", True) is not False):
            return st, jj
    return last if last else (0, {})

if tid is not None:
    aks, akj = _ack(tid)
    _, tasks2 = _responder_tasks()
    moved = False
    if isinstance(tasks2, list):
        t2 = next((t for t in tasks2 if _str(_task_id(t)) == _str(tid)), None)
        moved = bool(t2) and _str(_get(t2, "status", "state")).lower() == "responding"
    # Fall back to the ack response body if the list view doesn't echo the row.
    if not moved:
        moved = _str(_get(akj, "status", "state")).lower() == "responding"
    check("POST /api/responder/ack (token) moves the task to 'responding' (RESP-01 ack lifecycle)",
          aks == 200 and moved, "ack_status=%s now=%r" %
          (aks, _str(_get(akj, "status", "state"))))
else:
    check("POST /api/responder/ack (token) moves the task to 'responding' (RESP-01 ack lifecycle)",
          False, "no responder task id to ack")

# ---------------------------------------------------------------------------
# D. ALERT LIFECYCLE — operator cancel + TTL expiry (INT-03)
# ---------------------------------------------------------------------------
print("\n-- D. ALERT LIFECYCLE: operator cancel deactivates an alert; a past-TTL alert is not active (INT-03) --")
def _active_alerts():
    st, jj, _ = call("GET", "/api/alerts")
    return st, (jj.get("alerts") if isinstance(jj.get("alerts"), list) else None)

# Ensure there is an active alert to cancel: verify a dedicated incident.
call("POST", "/api/report",
     {"type": "armed_robbery", "place": "Funtua", "description": "alert-lifecycle corroboration A"})
call("POST", "/api/report",
     {"type": "armed_robbery", "place": "Funtua", "description": "alert-lifecycle corroboration B"})
call("POST", "/api/verify",
     {"type": "armed_robbery", "location_name": "Funtua", "state": "Katsina", "decision": "verified"})

las, alerts = _active_alerts()
# Identify the Funtua alert (immutable key/title) so we can cancel exactly it.
def _alert_key(a):
    return _get(a, "incident_key", "alert_uuid", "key", "id")

target_alert = None
if isinstance(alerts, list):
    target_alert = next((a for a in alerts if "funtua" in (_str(a.get("title")).lower())), None)
akey = _alert_key(target_alert) if target_alert else None

# Unauthenticated cancel must be rejected (operator-only kill-switch; ABU-07).
uc_status = None
if akey is not None:
    for path in ("/api/alert/cancel", "/api/alert-cancel"):
        st, _, _ = call("POST", path,
                        {"incident_key": akey, "alert_uuid": akey, "key": akey,
                         "reason": "gate unauth probe"}, want_token=False)
        uc_status = st
        if st in (401, 403):
            break
    check("POST /api/alert/cancel WITHOUT token -> 401/403 (operator kill-switch; ABU-07)",
          uc_status in (401, 403), "got %s" % uc_status)
else:
    check("POST /api/alert/cancel WITHOUT token -> 401/403 (operator kill-switch; ABU-07)",
          False, "no active alert found to target (verify did not fire one?)")

# Authenticated cancel -> the alert stops being active.
if akey is not None:
    def _cancel(k):
        last = None
        for path in ("/api/alert/cancel", "/api/alert-cancel"):
            st, jj, _ = call("POST", path,
                             {"incident_key": k, "alert_uuid": k, "key": k,
                              "reason": "false alarm — response gate"}, want_token=True)
            last = (st, jj)
            if st == 200 and (jj.get("ok", True) is not False):
                return st, jj
        return last if last else (0, {})

    cs, cj = _cancel(akey)
    _, alerts_after = _active_alerts()
    still_active = False
    if isinstance(alerts_after, list):
        still_active = any(_str(_alert_key(a)) == _str(akey) for a in alerts_after) or \
            any("funtua" in _str(a.get("title")).lower() for a in alerts_after)
    check("POST /api/alert/cancel (token) -> alert stops being active (INT-03 cancel + kill-switch)",
          cs == 200 and not still_active, "cancel_status=%s still_active=%s" % (cs, still_active))
else:
    check("POST /api/alert/cancel (token) -> alert stops being active (INT-03 cancel + kill-switch)",
          False, "no active alert key to cancel")

# TTL: the active-alerts list must not contain any alert whose expiry is in the
# past (read-time expiry, mirroring the incident decay model). Requires an
# expires_at-style field on alerts; absence of the field == not implemented yet.
import datetime
las2, alerts_now = _active_alerts()
def _expired(a):
    exp = _get(a, "expires_at", "expire_at", "ttl_at", "expiry")
    if not exp:
        return None  # no TTL field -> can't prove expiry handling
    try:
        return datetime.datetime.fromisoformat(_str(exp)) < datetime.datetime.now()
    except Exception:
        return None

if isinstance(alerts_now, list):
    flags = [_expired(a) for a in alerts_now]
    has_ttl_field = any(f is not None for f in flags)
    none_expired_active = not any(f is True for f in flags)
    check("active alerts carry a TTL/expires_at and none past-TTL are still active (INT-03 expiry)",
          has_ttl_field and none_expired_active,
          "ttl_field=%s past_ttl_active=%s" % (has_ttl_field, any(f is True for f in flags)))
else:
    check("active alerts carry a TTL/expires_at and none past-TTL are still active (INT-03 expiry)",
          False, "GET /api/alerts did not return a list (status=%s)" % las2)

# ---------------------------------------------------------------------------
# E. USSD — missing-person path creates a real case + reference number (FIND-03)
# ---------------------------------------------------------------------------
print("\n-- E. USSD: the missing-person path (text '3*Kaduna') opens a real case + reference (FIND-03) --")
def _missing_count():
    st, jj, _ = call("GET", "/api/missing", want_token=False)
    # Use pagination envelope 'total' field, not just first page length
    if isinstance(jj, dict) and "total" in jj:
        return st, jj["total"]
    arr = jj.get("missing") if isinstance(jj.get("missing"), list) else None
    return st, (len(arr) if isinstance(arr, list) else None)

ms0, m_before = _missing_count()
us, _, uraw = call("POST", "/api/ussd", {"text": "3*Kaduna", "sessionId": "respgate-1",
                                         "phoneNumber": "+2348000111"}, want_token=False)
ms1, m_after = _missing_count()

# The USSD response should END the session AND surface a case reference number.
import re
ended = us == 200 and "END" in (uraw or "")
# Reference format DS-YYYY-NNNN (per FEEDBACK FIND-03), but accept any DS-style ref.
ref_match = re.search(r"DS[-\s]?\d{4}[-\s]?\d{2,}", uraw or "", re.IGNORECASE) or \
    re.search(r"\b(?:case|ref(?:erence)?|no)\b[^\n]{0,12}\d{3,}", uraw or "", re.IGNORECASE)
check("POST /api/ussd '3*Kaduna' -> END with a case reference number (FIND-03)",
      ended and bool(ref_match), "raw=%r" % ((uraw or "")[:80]))
check("USSD missing-person path CREATES a case (GET /api/missing count increased) (FIND-03)",
      m_before is not None and m_after is not None and m_after > m_before,
      "missing %s -> %s" % (m_before, m_after))

# ---------------------------------------------------------------------------
print("\n=== RESPONSE RESULT: %d passed, %d failed ===" % (P[0], F[0]))
for x in FAILS:
    print("  FAIL: " + x)
print("RESULT response_loop %d/%d passed (%d failed)" % (P[0], P[0] + F[0], F[0]))
sys.exit(1 if F[0] else 0)
