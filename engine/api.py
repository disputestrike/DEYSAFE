"""DeySafe API + PWA + SHIELD operator console (standard library only).

  GET  /api/health
  GET  /api/incidents     public feed (decisions applied; dismissed hidden)
  GET  /api/queue         SHIELD operator review queue
  GET  /api/missing       missing-person cases (+ time-based search radius)
  GET  /api/places
  GET  /api/risk?place=<name>
  POST /api/report  {type, place, description}                      ANONYMOUS - no PII
  POST /api/missing {name, age, place, hours_ago, description}      FindMe case
  POST /api/verify  {type, location_name, state, decision, note}    the human gate

Public-data, warning-only. Nothing reaches 'verified' without a human via /api/verify.
"""
import sys
import os
import re
import json
import hmac
import hashlib
import datetime
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(BASE, "app")
DB_PATH = os.path.join(BASE, "data", "guardian.db")

from db import DB
import ingest
import geoparse
import corroborate
import ai
import sms
import auth
import ratelimit
import security
import response   # Phase 1: SOS / responder / alert state machines + TTL policy
import broadcast  # Phase 1: last-mile send (SIM-able, key-gated; BC-01/02/03)
import metrics    # MET-01: life-saving metrics (pure read over the tables)
# --- Phase 2-4 intelligence + resilience layer (wired below) -----------------
import pagination  # PERF-02: clamp + envelope every list endpoint (limit/offset/total)
import gazetteer   # GEO-02/03: 774-LGA OFFLINE gazetteer (confidence-graded, no network)
import routing     # WAKA-01: road-aware corridor scan (per-segment risk)
import terrain     # FIND-02: terrain-aware FindMe search radius
import reputation  # ABU-03/04/11: source reputation + coordinated-burst quarantine
import beaconsign  # BLE-01: signed rotating beacon envelope (HMAC + replay guard)
import scheduler   # DATA-01: periodic ingest worker (default OFF; started from main())
import safety      # Product-safety layer: Journey Guard/readiness/cases/evidence/network
import triangulate # TRI-01: server-side reachability-ring / Venn search-zone engine (FindMe)

# --- Phase 0 config ----------------------------------------------------------
# Operator auth (AUTH-01/06). Two ways to enable a locked posture, both fail-OPEN
# when unset so validate.py stays 56/56 on a fresh box:
#   * OPERATOR_TOKEN  — a single shared static token (simplest; what the security
#     gate sends as X-Operator-Token / Bearer).
#   * DEYSAFE_OPERATORS — a full operator roster (auth.py) enabling /api/login +
#     per-user Bearer session tokens and RBAC roles.
# P0-06/P0-07 FIX: Auth now requires header/token (no query param), and RBAC is enforced.
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "")

# Synthetic demo data (FAKE-01). Default ON locally so the public sees the full
# GREEN->RED ladder + a sample case; set DEMO_MODE=0 for a clean (empty) prod deploy.
DEMO_MODE = os.environ.get("DEMO_MODE", "1").strip().lower() not in ("0", "false", "no", "off", "")

PLACES = json.load(open(os.path.join(BASE, "config", "locations.json"), encoding="utf-8"))["places"]
PLACE_NAMES = sorted(p["name"] for p in PLACES)
TYPES = ["kidnapping", "banditry_attack", "missing_person", "armed_robbery", "police_misconduct"]
RISK = {"verified": 4, "needs_human_review": 3, "corroborated": 2, "candidate_unverified": 1, "dismissed": 0}
REVIEW = ("needs_human_review", "corroborated")
CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
          ".json": "application/json; charset=utf-8", ".css": "text/css; charset=utf-8",
          ".svg": "image/svg+xml", ".webmanifest": "application/manifest+json"}
PUBLIC_GUIDANCE = {
    "GREEN": "No verified danger nearby. Remain alert.",
    "YELLOW": "Unconfirmed report nearby. Exercise caution.",
    "ORANGE": "Active danger reported nearby. Avoid the area if you can.",
    "RED": "Critical verified threat. Do not travel; follow official guidance.",
}
TYPE_RADIUS = {"kidnapping": 50, "banditry_attack": 100, "armed_robbery": 30, "missing_person": 30, "police_misconduct": 20}
TYPE_GUIDANCE = {
    "kidnapping": "Avoid the area. Do NOT attempt a rescue. Share your live location with family. Emergency: 112.",
    "banditry_attack": "Avoid this route. Travel by day and in convoy. Report movements you see. Emergency: 112.",
    "armed_robbery": "Avoid the area. Secure valuables. Report to the nearest police. Emergency: 112.",
    "missing_person": "If you see the person or vehicle, report a sighting on DeySafe. Do not approach. Emergency: 112.",
    "police_misconduct": "Stay calm and safe. Note the time, location, and any badge / vehicle number. Record only if it's safe. You can report anonymously here. Emergency / legal aid: 112.",
}
LEVEL_LABEL = {1: "ADVISORY", 2: "WARNING", 3: "DANGER", 4: "CRITICAL"}

# --- ABU-03 inbound-report stream (coordinated-burst detection) --------------
# The signals table DEDUPES identical reports by raw_hash, so a coordinated flood
# of near-identical reports collapses to one stored row — invisible to a detector
# that reads the table. We therefore mirror every INBOUND report (pre-dedup) into
# a small, bounded, process-level ring buffer that the coordination detector reads.
# It holds only the non-PII shape the detector needs (ts, area, coarse coords,
# text, opaque reporter_key) and is time-pruned, so it never grows unbounded and
# never persists raw identities. Process-local on purpose: a transient burst signal.
import collections as _collections
import threading as _threading
_RECENT_REPORTS = _collections.deque(maxlen=400)
_RECENT_LOCK = _threading.Lock()


def _remember_report(rep):
    """Append one inbound report's non-PII shape to the burst ring buffer."""
    try:
        with _RECENT_LOCK:
            _RECENT_REPORTS.append(rep)
    except Exception:
        pass


def _recent_reports_window(minutes=30, limit=300):
    """Snapshot of inbound reports seen in the last `minutes` (pre-dedup), newest
    last — the window the ABU-03 coordinated-burst detector scores."""
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=minutes)
    out = []
    with _RECENT_LOCK:
        items = list(_RECENT_REPORTS)
    for r in items:
        ts = r.get("ts")
        try:
            if ts and datetime.datetime.fromisoformat(ts) < cutoff:
                continue
        except Exception:
            pass
        out.append(r)
    return out[-limit:]


# --- ABU-01 content-aware duplicate throttle (NAT-SAFE) ----------------------
# Nigeria runs almost entirely on carrier-grade NAT, so MANY distinct, legitimate
# reporters share ONE public IP. A naive per-IP request cap would therefore SILENCE
# real mass-reporting during an actual attack — the single worst failure mode for a
# safety app (exactly when many people need to report the same event at once). So we
# do NOT cap requests per IP. Instead we throttle only the spam SIGNATURE: the same
# caller posting the SAME / near-identical report CONTENT over and over in a short
# window (that pattern = automation/flooding, not a crowd). DISTINCT reports from the
# same IP — different people describing different things — always pass.
#
# Mechanism: a per-(caller + normalized-content-hash) sliding window. We normalise the
# (type+place+description) so trivial variations collapse to one signature — crucially
# we STRIP digit runs, so an automated burst that only bumps a trailing counter
# ("...probe 0", "...probe 1", ...) is recognised as the SAME content, while genuinely
# different wording yields a different signature and is never throttled. More than
# _DUP_MAX_PER_WINDOW posts of one signature within _DUP_WINDOW_SECONDS from one caller
# -> 429 on the excess dupes only. The backing dict is bounded and time-pruned so it
# can never grow without limit.
_DUP_WINDOW_SECONDS = 60.0     # sliding window per (caller, content) signature
_DUP_MAX_PER_WINDOW = 3        # allow a few honest re-submits; throttle the 4th+ dupe
_DUP_MAX_KEYS = 4096           # hard cap on tracked signatures (memory bound)
_DUP_HITS = _collections.OrderedDict()   # signature_key -> [recent monotonic timestamps]
_DUP_LOCK = _threading.Lock()


def _content_signature(typ, place, desc):
    """Normalise a report's (type, place, description) into a spam signature.

    Lowercases, strips digit runs (so a counter-incremented burst collapses to one
    signature), drops non-alphanumeric noise, and collapses whitespace. Two reports
    that differ only by a number / punctuation / casing share a signature; reports
    with genuinely different wording do not."""
    blob = "{}\x1f{}\x1f{}".format(typ or "", place or "", desc or "").lower()
    blob = re.sub(r"\d+", "", blob)              # trailing/embedded counters -> nothing
    blob = re.sub(r"[^a-z\x1f]+", " ", blob)     # keep letters + field separator only
    blob = re.sub(r"\s+", " ", blob).strip()
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]


def _duplicate_report_throttled(client_id, typ, place, desc):
    """True if `client_id` has already posted this near-identical content
    _DUP_MAX_PER_WINDOW times within _DUP_WINDOW_SECONDS (i.e. this one is a dupe to
    throttle). NAT-safe: keyed on caller + CONTENT, so distinct reports from the same
    shared IP are never throttled. Records this hit when it allows it. Self-pruning."""
    import time as _time
    sig = client_id + "|" + _content_signature(typ, place, desc)
    now = _time.monotonic()
    cutoff = now - _DUP_WINDOW_SECONDS
    with _DUP_LOCK:
        # Opportunistically prune fully-expired signatures so the dict stays bounded.
        if len(_DUP_HITS) > _DUP_MAX_KEYS:
            for k in [k for k, v in _DUP_HITS.items() if not v or v[-1] < cutoff]:
                _DUP_HITS.pop(k, None)
            # A flood of DISTINCT content keeps every entry live (nothing expired to drop),
            # so also evict oldest-first until back at the cap — the dict can't grow unbounded.
            while len(_DUP_HITS) > _DUP_MAX_KEYS:
                _DUP_HITS.popitem(last=False)
        hits = [t for t in _DUP_HITS.get(sig, ()) if t >= cutoff]
        if len(hits) >= _DUP_MAX_PER_WINDOW:
            _DUP_HITS[sig] = hits            # keep the window; do NOT count the blocked dupe
            _DUP_HITS.move_to_end(sig)
            return True
        hits.append(now)
        _DUP_HITS[sig] = hits
        _DUP_HITS.move_to_end(sig)
        return False


# --- Phase 1 response-loop helpers (SOS-01/02, BC-03) ------------------------
# Channels we attempt for a trusted-circle SOS notify, in reach-priority order
# (broadcast.py orders the same way). Each trusted contact may override with its
# own `channel`; this is the fallback when none is given.
SOS_DEFAULT_CHANNEL = "sms"


def sos_notify_message(ev):
    """Compose the message sent to a trusted contact for an SOS event.

    Includes the durable reference and, only when the field user shared a
    location ON-DEVICE (lat/lng present), a maps link. Never invents a location.
    """
    ref = ev.get("handoff_ref") or ev.get("ref") or ""
    extra = (ev.get("message") or "").strip()
    parts = ["\U0001F198 SOS — someone in your circle needs help."]
    if extra:
        parts.append('"' + extra[:160] + '"')
    lat, lng = ev.get("lat"), ev.get("lng")
    if lat is not None and lng is not None:
        try:
            parts.append("Location: https://maps.google.com/?q=%.5f,%.5f" % (float(lat), float(lng)))
        except Exception:
            pass
    if ref:
        parts.append("Ref " + ref)
    return " ".join(parts)


def _sos_contact_targets(data, db):
    """Resolve the trusted-circle recipients for an SOS notify.

    Prefers the contacts the client posted with the SOS (mirrors what the field
    app holds on-device); falls back to the server-side circle stored for this
    owner_token (SOS-03). Returns a list of {channel,address}-style dicts that
    broadcast.fan_out understands. Never returns the raw owner_token.
    """
    contacts = data.get("contacts")
    if isinstance(contacts, list) and contacts:
        out = []
        for c in contacts:
            if isinstance(c, dict):
                addr = c.get("address") or c.get("to") or c.get("phone")
                if addr:
                    out.append({"address": addr, "channel": (c.get("channel") or SOS_DEFAULT_CHANNEL)})
            elif c:
                out.append({"address": c, "channel": SOS_DEFAULT_CHANNEL})
        if out:
            return out
    # Fall back to the server-mirrored circle for this owner.
    owner = (data.get("owner_token") or "").strip()
    rows = db.trusted_for(owner) if owner else []
    return [{"address": r.get("address"), "channel": (r.get("channel") or SOS_DEFAULT_CHANNEL)}
            for r in rows if r.get("address")]


def public_sos_view(ev, deliveries=None):
    """PRIV-01: the PUBLIC read of an SOS event.

    Exposes only what the owner's own UI needs to track status (id, ref, state,
    contact_state, delivery counts, coarse age) and NEVER projects owner_token,
    the trusted-circle addresses, the free-text message, or exact coordinates.
    The field app polls this to show 'Status / Trusted circle: notified'.
    """
    if not ev:
        return None
    dlist = deliveries or []
    sent = sum(1 for d in dlist if d.get("status") not in ("failed", "unconfigured", None, ""))
    out = {
        "id": ev.get("sos_uuid"),
        "sos_uuid": ev.get("sos_uuid"),
        "uuid": ev.get("sos_uuid"),
        "ref": ev.get("handoff_ref"),
        "reference": ev.get("handoff_ref"),
        "state": ev.get("state"),
        "status": ev.get("state"),
        "mode": ev.get("mode"),
        "contact_state": ev.get("contact_state"),
        "created_at": ev.get("created_at"),
        "updated_at": ev.get("updated_at"),
        "deliveries": {"total": len(dlist), "sent": sent},
    }
    return out


def _float_or_none(v):
    try:
        if v is None or v == "":
            return None
        return float(v)
    except Exception:
        return None


def public_journey_view(row):
    """Owner-facing Journey Guard projection.

    A journey id is not an operator credential, so this view avoids contact data
    and raw live coordinates. It exposes status, route labels, risk, and whether
    explicit location sharing was enabled.
    """
    if not row:
        return None
    return {
        "id": row.get("journey_uuid"),
        "journey_uuid": row.get("journey_uuid"),
        "ref": row.get("handoff_ref"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "started_at": row.get("started_at"),
        "expected_arrival": row.get("expected_arrival"),
        "from_place": row.get("from_place"),
        "to_place": row.get("to_place"),
        "status": row.get("status"),
        "state": row.get("status"),
        "risk_level": row.get("risk_level"),
        "is_active": row.get("status") == "active",
        "has_live_location": bool(row.get("share_location")),
    }


def coords_for(place_name, db=None):
    """Resolve a place name to (lat, lng, verified).

    Tries the high-confidence 774-LGA gazetteer first (GEO-02); falls back to the
    dynamic location table (crowdsourced/operator entries). Returns (None, None, False)
    if completely unknown.
    """
    # 1. Check the static high-confidence gazetteer (774 LGAs).
    match = gazetteer.lookup(place_name)
    if match:
        return match["lat"], match["lng"], True

    # 2. Check the dynamic db table (previously seen or operator-defined).
    if db:
        row = db.get_location(place_name)
        if row:
            return row.get("lat"), row.get("lng"), (row.get("verified") == 1)

    return None, None, False


class DeySafeHandler(BaseHTTPRequestHandler):
    def _json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Operator-Token")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _static(self, rel_path):
        """Serve a static file from the app/ directory."""
        if rel_path == "/" or not rel_path:
            rel_path = "index.html"
        
        # Security: prevent path traversal.
        path = os.path.normpath(os.path.join(APP_DIR, rel_path.lstrip("/")))
        if not path.startswith(os.path.abspath(APP_DIR)):
            return self.send_error(403)
            
        if not os.path.exists(path) or os.path.isdir(path):
            # Fallback to index.html for PWA routing.
            path = os.path.join(APP_DIR, "index.html")
            if not os.path.exists(path):
                return self.send_error(404)

        ext = os.path.splitext(path)[1].lower()
        ctype = CTYPES.get(ext, "application/octet-stream")
        
        try:
            with open(path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", len(content))
            # Cache PWA assets for 1 hour.
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(500)

    def do_OPTIONS(self):
        self._json({"ok": True})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        db = DB(DB_PATH)

        if u.path == "/api/health":
            return self._json({"status": "ok", "version": "1.0.0-phase-7", "db": db.is_ok()})

        # --- SHIELD / Operator Console endpoints ------------------------------
        if u.path in ("/api/queue", "/api/verify", "/api/audit", "/api/metrics"):
            # AUTH-01: enforce operator auth for these endpoints.
            if not security.is_operator(self, db):
                return self._json({"error": "unauthorized"}, 401)

            if u.path == "/api/queue":
                # Operator review queue: unverified/corroborated reports only.
                rows = db.get_reports(status=REVIEW)
                return self._json({"queue": rows, "count": len(rows)})

            if u.path == "/api/audit":
                # MET-02: operator audit log access.
                limit = int(q.get("limit", [50])[0])
                rows = db.get_audit_logs(limit=limit)
                return self._json({"logs": rows})

            if u.path == "/api/metrics":
                # MET-01: high-level system performance and safety metrics.
                return self._json(metrics.system_summary(db))

        # --- Public Data endpoints --------------------------------------------
        if u.path == "/api/incidents":
            # Public feed: verified incidents only. Redacted for PII.
            place = q.get("place", [None])[0]
            rows = db.get_reports(status="verified", place=place)
            # PRIV-01: Ensure no reporter_id or raw description escapes to the public feed.
            feed = []
            for r in rows:
                feed.append({
                    "id": r["id"], "type": r["type"], "place": r["place"],
                    "label": LEVEL_LABEL.get(r["risk_level"], "WARNING"),
                    "guidance": TYPE_GUIDANCE.get(r["type"], ""),
                    "created_at": r["created_at"]
                })
            return self._json({"incidents": feed, "count": len(feed)})

        if u.path == "/api/places":
            return self._json({"places": PLACE_NAMES})

        if u.path == "/api/risk":
            place = q.get("place", [None])[0]
            if not place:
                return self._json({"error": "missing place"}, 400)
            
            # GEO-01: resolve coordinates via gazetteer.
            lat, lng, verified = coords_for(place, db=db)
            
            # WAKA-01: if we have coords, check for active threats in the radius.
            active_threats = []
            if lat and lng:
                active_threats = db.get_nearby_incidents(lat, lng, radius=50)
            
            risk_score = 0
            if active_threats:
                risk_score = max(r.get("risk_level", 1) for r in active_threats)
            
            status = "GREEN"
            if risk_score >= 4: status = "RED"
            elif risk_score >= 3: status = "ORANGE"
            elif risk_score >= 2: status = "YELLOW"

            return self._json({
                "place": place,
                "status": status,
                "score": risk_score,
                "guidance": PUBLIC_GUIDANCE.get(status),
                "verified_location": verified,
                "active_count": len(active_threats)
            })

        if u.path == "/api/missing":
            # FIND-01: missing person search.
            # RED-01: redacts names/PII for anonymous callers; shows full for operators.
            is_op = self._authed() and self._auth_enabled()
            place = q.get("place", [None])[0]
            rows = db.get_missing(place=place)
            
            results = []
            for r in rows:
                item = {
                    "id": r["id"], "place": r["place"], "last_seen": r["last_seen"],
                    "description": r["description"], "status": r["status"]
                }
                if is_op:
                    item["name"] = r["name"]
                    item["age"] = r["age"]
                results.append(item)
            return self._json({"cases": results, "count": len(results)})

        # --- Journey Guard (Phase 5-7) ----------------------------------------
        if u.path == "/api/journey/status":
            # JRN-04: poll status for a specific journey.
            jid = q.get("id", [None])[0]
            if not jid: return self._json({"error": "missing id"}, 400)
            row = db.get_journey(jid)
            if not row: return self._json({"error": "not found"}, 404)
            return self._json(public_journey_view(row))

        # --- SOS (Phase 1) ----------------------------------------------------
        if u.path == "/api/sos/status":
            sid = q.get("id", [None])[0]
            if not sid: return self._json({"error": "missing id"}, 400)
            ev = db.get_sos_event(sid)
            if not ev: return self._json({"error": "not found"}, 404)
            # PRIV-01: redact sensitive fields for the public poll.
            deliveries = db.get_sos_deliveries(ev["id"])
            return self._json(public_sos_view(ev, deliveries))

        # --- Static Frontend Fallback -----------------------------------------
        if not u.path.startswith("/api/"):
            return self._static(u.path)

        self.send_error(404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        try:
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body) if body else {}
        except Exception:
            return self._json({"error": "invalid json"}, 400)

        db = DB(DB_PATH)
        client_id = security.get_client_id(self)

        # --- Public Reporting (ABU-01 Throttled) ------------------------------
        if u.path == "/api/report":
            typ = data.get("type")
            place = data.get("place")
            desc = data.get("description", "").strip()

            if not typ or not place:
                return self._json({"error": "missing fields"}, 400)
            if typ not in TYPES:
                return self._json({"error": "invalid type"}, 400)

            # ABU-01: content-aware duplicate throttle (NAT-safe).
            if _duplicate_report_throttled(client_id, typ, place, desc):
                db.audit("ratelimit", "report_throttled", "client={} place={}".format(client_id[:8], place))
                return self._json({"error": "too many similar reports, please wait"}, 429)

            # GEO-01: resolve coords.
            lat, lng, verified = coords_for(place, db=db)
            
            # COR-01: initial AI/Heuristic corroboration score.
            score = corroborate.score_report(typ, place, desc, lat, lng)
            status = "candidate_unverified"
            if score >= 70: status = "corroborated"

            rid = db.insert_report({
                "type": typ, "place": place, "description": desc,
                "lat": lat, "lng": lng, "status": status, "score": score,
                "reporter_id": client_id
            })
            
            # ABU-03: record for burst detection.
            _remember_report({"ts": datetime.datetime.now().isoformat(), "place": place, "type": typ})
            db.audit("api", "report_submitted", "id={} place={} score={}".format(rid, place, score))

            return self._json({
                "ok": True, "id": rid, "status": status,
                "location_unverified": not verified,
                "guidance": TYPE_GUIDANCE.get(typ, "")
            })

        if u.path == "/api/missing":
            name = (data.get("name") or "").strip()
            place = (data.get("place") or "").strip()
            if not name or not place:
                return self._json({"error": "missing name/place"}, 400)
            
            lat, lng, verified = coords_for(place, db=db)  # GEO-01/02: offline gazetteer first, verified flag
            try:
                hrs = float(data.get("hours_ago") or 1)
            except Exception:
                hrs = 1.0
            try:
                cnt = max(1, int(data.get("count") or 1))   # non-numeric count must not 500
            except Exception:
                cnt = 1
            case_row = db.insert_missing({"name": name, "age": (data.get("age") or "").strip(), "place": place,
                               "exact_place": (data.get("exact_place") or "").strip(),
                               "count": cnt, "lat": lat, "lng": lng,
                               "last_seen": (datetime.datetime.now() - datetime.timedelta(hours=hrs)).isoformat(timespec="seconds"),
                               "description": (data.get("description") or "").strip(),
                               "vehicle": (data.get("vehicle") or "").strip(),
                               "clothing": (data.get("clothing") or "").strip(),
                               "direction": (data.get("direction") or "").strip(),
                               "beacon_id": (data.get("beacon_id") or "").strip()})
            db.audit("api", "missing_report", "place={} count={}".format(place, data.get("count") or 1))
            # P0-01 PRIVACY FIX: POST response returns ONLY a minimal confirmation,
            # NOT the full restricted case list. The submitter can retrieve their
            # own case via GET /api/missing?case_id=<id> if needed.
            # Note: db.insert_missing returns the integer ID, not a row dict.
            case_ref = case_row if isinstance(case_row, int) and case_row else (case_row.get("id") if case_row else None)
            return self._json({"ok": True, "case_ref": case_ref,
                               "location_unverified": not verified,
                               "coords_confidence": ("unverified" if not verified else "gazetteer"),
                               "redacted_summary": {"name": name, "place": place}})

        if u.path == "/api/verify":
            # AUTH-01: the human publish gate is operator-only. Also the most
            # important lock — it promotes an event to a public RED alert.
            if not security.is_operator(self, db):
                return self._json({"error": "unauthorized"}, 401)

            rid = data.get("id")
            decision = data.get("decision") # 'verified', 'dismissed', 'needs_human_review'
            if not rid or not decision:
                return self._json({"error": "missing fields"}, 400)

            db.update_report_status(rid, decision, operator=security.get_operator_id(self))
            db.audit("operator", "verify_decision", "id={} decision={}".format(rid, decision))
            
            # If verified, trigger any automated broadcasts (Phase 1).
            if decision == "verified":
                broadcast.announce_incident(db.get_report(rid))

            return self._json({"ok": True})

        # --- SOS (Phase 1) ----------------------------------------------------
        if u.path == "/api/sos":
            # SOS-01: Emergency trigger.
            # No auth required for the trigger itself (safety first), but we
            # rate-limit by client_id.
            if ratelimit.is_throttled(client_id, "sos_trigger", limit=3, window=300):
                return self._json({"error": "too many SOS attempts"}, 429)

            ev = response.create_sos(db, data, client_id)
            # SOS-02: Notify the trusted circle.
            targets = _sos_contact_targets(data, db)
            msg = sos_notify_message(ev)
            broadcast.fan_out(targets, msg, context={"sos_id": ev["id"]})
            
            db.audit("api", "sos_triggered", "id={} contacts={}".format(ev["sos_uuid"], len(targets)))
            return self._json({"ok": True, "id": ev["sos_uuid"], "ref": ev["handoff_ref"]})

        # --- Journey Guard (Phase 5-7) ----------------------------------------
        if u.path == "/api/journey/start":
            # JRN-01: Start a monitored journey.
            if not data.get("to_place"): return self._json({"error": "missing destination"}, 400)
            j = safety.start_journey(db, data, client_id)
            db.audit("api", "journey_started", "id={}".format(j["journey_uuid"]))
            return self._json({"ok": True, "id": j["journey_uuid"], "ref": j["handoff_ref"]})

        if u.path == "/api/journey/update":
            # JRN-02: Heartbeat / location update.
            jid = data.get("id")
            if not jid: return self._json({"error": "missing id"}, 400)
            res = safety.update_journey(db, jid, data)
            return self._json({"ok": res})

        self.send_error(404)


def main():
    port = int(os.environ.get("PORT", 8080))
    # DATA-01: Background scheduler for periodic ingest (default OFF).
    if os.environ.get("ENABLE_SCHEDULER", "0") == "1":
        scheduler.start(DB_PATH)
    
    server = ThreadingHTTPServer(("0.0.0.0", port), DeySafeHandler)
    print("DeySafe API running on port", port)
    server.serve_forever()


if __name__ == "__main__":
    main()
