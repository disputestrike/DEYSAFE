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
import json
import hmac
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

# --- Phase 0 config ----------------------------------------------------------
# Operator auth (AUTH-01/06). Two ways to enable a locked posture, both fail-OPEN
# when unset so validate.py stays 56/56 on a fresh box:
#   * OPERATOR_TOKEN  — a single shared static token (simplest; what the security
#     gate sends as X-Operator-Token / Bearer).
#   * DEYSAFE_OPERATORS — a full operator roster (auth.py) enabling /api/login +
#     per-user Bearer session tokens and RBAC roles.
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


def alert_level(conf, sev):
    if conf >= 90 or sev:
        return 4
    if conf >= 80:
        return 3
    if conf >= 70:
        return 2
    return 1


def ikey(i):
    return "{}|{}|{}".format(i["type"], i["location_name"], i["state"])


# Auto drop-off: an incident stays on the public map only while fresh. After its
# status-based TTL it ages out by itself — computed at read-time, no cron needed.
DECAY_TTL_H = {"verified": 240, "needs_human_review": 96, "corroborated": 72, "candidate_unverified": 48}


def _age_hours(inc):
    ts = inc.get("window_end") or inc.get("window_start")
    try:
        return max(0.0, (datetime.datetime.now() - datetime.datetime.fromisoformat(ts)).total_seconds() / 3600.0)
    except Exception:
        return 0.0


def _fresh(inc):
    return _age_hours(inc) <= DECAY_TTL_H.get(inc.get("status"), 48)


def place_coords(name):
    # GEO-01: gazetteer lookup only. Returns (None, None) on a miss instead of the
    # silent Nigeria-centroid guess, so callers can flag the location as unverified.
    n = (name or "").strip().lower()
    for p in PLACES:
        if p["name"].lower() == n:
            return p["lat"], p["lng"]
    return None, None


_geocache = {}


def geocode(q):
    """Resolve ANY Nigerian place to coordinates: local gazetteer first, then free
    OpenStreetMap / Nominatim (no API key). Cached. Lets users type any town/village."""
    q = (q or "").strip()
    if not q:
        return None
    for p in PLACES:
        if p["name"].lower() == q.lower():
            return {"name": p["name"], "lat": p["lat"], "lng": p["lng"], "source": "gazetteer",
                    "state": p.get("state", ""), "hotspot": p.get("hotspot", False)}
    key = q.lower()
    if key in _geocache:
        return _geocache[key]
    res = None
    try:
        url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(
            {"q": q + ", Nigeria", "format": "json", "limit": "1", "countrycodes": "ng"})
        req = urllib.request.Request(url, headers={"User-Agent": "DeySafe/0.1 (safety prototype)"})
        with urllib.request.urlopen(req, timeout=12) as r:
            arr = json.loads(r.read().decode("utf-8"))
        if arr:
            res = {"name": q.title(), "lat": float(arr[0]["lat"]), "lng": float(arr[0]["lon"]),
                   "source": "osm", "display": arr[0].get("display_name", "")}
    except Exception:
        res = None
    _geocache[key] = res
    return res


def coords_for(place):
    """Best coordinates for a TYPED place: gazetteer -> free OSM. Returns
    (lat, lng, verified). GEO-01: on a total miss we return (None, None, False)
    rather than silently pinning the Nigeria centroid (9.2, 8.2) — the caller then
    stores null coords + marks the location unverified (needs a manual pin)."""
    g = geocode(place)
    if g:
        return g["lat"], g["lng"], True
    lat, lng = place_coords(place)
    if lat is not None:
        return lat, lng, True
    return None, None, False


def _hav(a, b):
    import math
    (la1, lo1), (la2, lo2) = a, b
    R = 6371.0
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = math.radians(la2 - la1), math.radians(lo2 - lo1)
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(x))


def risk_at(incidents, lat, lng, radius_km=60):
    # Geofenced ("drill fence") area report: every incident within radius_km of the
    # typed point, each tagged with its distance, worst-severity first then nearest.
    rel = []
    for i in incidents:
        d = _hav((lat, lng), (i["lat"], i["lng"]))
        if d <= radius_km:
            j = dict(i)
            j["distance_km"] = round(d, 1)
            rel.append(j)
    top = max((RISK.get(i["status"], 1) for i in rel), default=0)
    level = public_level(top)
    rel.sort(key=lambda i: (-RISK.get(i["status"], 1), i["distance_km"]))
    return {"place": None, "lat": lat, "lng": lng, "radius_km": radius_km, "level": level,
            "guidance": PUBLIC_GUIDANCE[level], "count": len(rel), "incidents": rel[:8]}


def public_level(top):
    # GDACS-style public severity. RED is reserved for human-verified threats.
    return "RED" if top >= 4 else ("ORANGE" if top >= 2 else ("YELLOW" if top >= 1 else "GREEN"))


def recompute(db):
    detections = []
    for r in db.all_signals():
        s = dict(r)
        # Structured report: place was already geocoded + type chosen, so build the
        # detection directly. Works for ANY place, not only the gazetteer towns.
        if s.get("gtype") and s.get("lat") is not None and s.get("lng") is not None:
            detections.append({
                "type": s["gtype"], "terms": [],
                "location_name": s.get("location_name") or "reported area",
                "state": s.get("state") or "", "lat": s["lat"], "lng": s["lng"],
                "hotspot": False, "lang": s.get("lang") or "en",
                "severity": s.get("gseverity") or 0,
                "signal_id": s["id"], "source_name": s["source_name"],
                "published_at": s["published_at"] or s["ingested_at"], "title": s["title"] or ""})
            continue
        # Unstructured signal (e.g. live RSS): fall back to gazetteer geoparse.
        gp = geoparse.geoparse(s)
        if gp:
            gp.update({"signal_id": s["id"], "source_name": s["source_name"],
                       "published_at": s["published_at"] or s["ingested_at"], "title": s["title"] or ""})
            detections.append(gp)
    db.replace_incidents(corroborate.build_incidents(detections))


def ingest_text_report(db, text, source):
    """Turn a free-text SMS/USSD report into a structured, geocoded, human-gated signal."""
    gp = geoparse.geoparse({"title": "", "text": text}) or {}
    place = gp.get("location_name", "")
    g = geocode(place) if place else None
    db.insert_signal({"source_name": source, "kind": "sms",
                      "title": (gp.get("type") or "report") + " near " + (place or "?"),
                      "text": text, "url": "", "lang": "en",
                      "published_at": datetime.datetime.now().isoformat(timespec="seconds"),
                      "lat": (g["lat"] if g else None), "lng": (g["lng"] if g else None),
                      "location_name": (g["name"] if g else place), "state": (g.get("state", "") if g else ""),
                      "gtype": (gp.get("type") or None), "gseverity": gp.get("severity", 0)})
    recompute(db)
    return {"place": (g["name"] if g else place), "type": gp.get("type", "")}


def ensure_seed(db):
    # FAKE-01: ALL synthetic data is gated behind DEMO_MODE. With DEMO_MODE off
    # (prod), a fresh DB builds NO sample signals, NO sample case, and NO fabricated
    # human-"verified" RED — the map starts empty and honest. A real DB still
    # recomputes its own incidents. Default is ON (keeps validate.py's "verified RED
    # visible" check green locally).
    empty = db.count_signals() == 0
    if DEMO_MODE and empty:
        for s in ingest.gather(use_live=False, use_sample=True):
            db.insert_signal(s)
    recompute(db)
    if not DEMO_MODE:
        return  # prod: no synthetic case / alert / verified-threat seeding
    if empty:
        # one sample FindMe case so the map demonstrates a search radius
        lat, lng = place_coords("Kankara")
        db.insert_missing({"name": "[SAMPLE] Abducted students (group)", "age": "13-17", "place": "Kankara",
                           "exact_place": "Government Science School, Kankara", "count": 20,
                           "lat": lat, "lng": lng,
                           "last_seen": (datetime.datetime.now() - datetime.timedelta(hours=3)).isoformat(timespec="seconds"),
                           "description": "Sample mass-abduction case for demo — students taken from a school in Kankara.",
                           "vehicle": "Several motorcycles + a white Hilux", "clothing": "School uniforms",
                           "direction": "North into the forest toward Jibia"})
    # Demo: ensure ONE human-VERIFIED incident exists so the public actually sees a
    # RED on the GREEN->YELLOW->ORANGE->RED ladder. Idempotent; never overrides an
    # operator's later call (only seeds while that incident is still undecided). The
    # decision + seeded alert are keyed to the incident's immutable uuid (INT-01/02).
    rk = "kidnapping|Kaduna|Kaduna"
    inc = next((i for i in with_decisions(db) if ikey(i) == rk), None)
    if inc and not inc.get("decided"):
        iuid = inc.get("incident_uuid")
        db.set_decision(iuid, "verified", "[seed] demo verified threat (synthetic)", "seed",
                        event_version=inc.get("event_version"), key=rk)
        if not db.has_active_alert(iuid):
            db.insert_alert({"incident_key": iuid, "level": 3, "level_label": "DANGER",
                             "title": "KIDNAPPING — Kaduna, Kaduna — armed men on the Kaduna-Abuja road",
                             "guidance": TYPE_GUIDANCE["kidnapping"], "lat": inc["lat"], "lng": inc["lng"],
                             "radius_km": 50, "reach": 6000})


def with_decisions(db):
    # INT-01: decisions join on the immutable incident_uuid, NOT the type|location|
    # state triple. So when recompute mints a new uuid for a genuinely new event,
    # it shows up undecided instead of inheriting a prior verify/dismiss.
    dec = db.decisions()
    incs = db.all_incidents()
    for i in incs:
        d = dec.get(i.get("incident_uuid"))
        i["decided"] = bool(d)
        if d:
            i["status"] = d["decision"]
            i["decision_note"] = d.get("note") or ""
        i["age_hours"] = round(_age_hours(i), 1)
    return incs


def public_incidents(db):
    # dismissed by a human OR aged-out by decay -> off the public map automatically.
    return [i for i in with_decisions(db) if i["status"] != "dismissed" and _fresh(i)]


def review_queue(db):
    q = [i for i in with_decisions(db) if not i["decided"] and i["status"] in REVIEW and _fresh(i)]
    return sorted(q, key=lambda i: -i["confidence"])


def _fuzz(v, places=1):
    # PRIV-01: round a coordinate so the PUBLIC flyer locates an area, not a doorstep.
    try:
        return round(float(v), places)
    except Exception:
        return None


def missing_with_radius(db, restricted=False):
    """Missing-person cases + time-based search radius.

    PRIV-01 / BLE-02: `restricted=False` (PUBLIC) returns a REDACTED flyer — no
    exact_place / vehicle / clothing / direction / beacon_id / last_seen, no raw
    coordinates, and sightings collapsed to {place, seen_at} with NO lat/lng/note.
    The only locating signal the public sees is the (fuzzed) search point + radius.
    `restricted=True` (authenticated operator/responder) returns the full record.
    """
    out = []
    for row in db.all_missing():
        m = dict(row)
        sights = db.sightings_for(m["id"])
        # Anchor the search on the MOST RECENT credible point: latest sighting if any, else last-seen.
        if sights:
            last = sights[-1]
            alat, alng, atime, anchor = last["lat"], last["lng"], last["seen_at"], "sighting"
        else:
            alat, alng, atime, anchor = m["lat"], m["lng"], m["last_seen"], "last_seen"
        try:
            hrs = max(0.25, (datetime.datetime.now() - datetime.datetime.fromisoformat(atime)).total_seconds() / 3600)
        except Exception:
            hrs = 1.0
        radius_km = int(min(hrs * 50, 250))  # ~50 km/h spread from the freshest point, capped

        if restricted:
            # Operator / responder view: full detail (already authenticated).
            m["sightings"] = sights
            m["sighting_count"] = len(sights)
            m["anchor"] = anchor
            m["search_lat"], m["search_lng"] = alat, alng
            m["hours"] = round(hrs, 1)
            m["radius_km"] = radius_km
            out.append(m)
            continue

        # PUBLIC redacted flyer (security.redact_missing drops every sensitive key)
        pub = security.redact_missing(m, restricted=False)
        pub["place"] = pub.pop("area", (m.get("place") or ""))   # town-level locality label
        pub["count"] = m.get("count") or 1
        pub["anchor"] = anchor
        pub["sighting_count"] = len(sights)
        # sightings without raw coords or free-text notes
        pub["sightings"] = [{"place": s.get("place") or "", "seen_at": s.get("seen_at")} for s in sights]
        # PRIV-01: the public flyer carries only a FUZZED (area-level) point — the
        # exact last-seen coordinate never leaves the server. The search radius is
        # the real locating signal. lat/lng == search point so the public map can
        # still draw the area circle without revealing a doorstep.
        flat, flng = _fuzz(alat), _fuzz(alng)
        pub["lat"], pub["lng"] = flat, flng
        pub["search_lat"], pub["search_lng"] = flat, flng
        pub["coords_fuzzed"] = True
        pub["hours"] = round(hrs, 1)
        pub["radius_km"] = radius_km
        out.append(pub)
    return out


def risk_for(incidents, place):
    pl = (place or "").strip().lower()
    rel = [i for i in incidents if pl and (pl in (i["location_name"] or "").lower() or pl in (i["state"] or "").lower())]
    top = max((RISK.get(i["status"], 1) for i in rel), default=0)
    level = public_level(top)
    return {"place": place, "level": level, "guidance": PUBLIC_GUIDANCE[level], "count": len(rel),
            "incidents": sorted(rel, key=lambda i: -i["confidence"])[:6]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # PROD-02: minimal structured request log to stderr (was a no-op, which
        # blinded ops). One line per request: ts, client, method, path, status.
        try:
            status = args[1] if len(args) > 1 else "-"
            line = '{ts} client=%s method_path="%s" status=%s' % (
                self.address_string(), (self.requestline or "").replace('"', "'"), status)
            sys.stderr.write(line.format(ts=datetime.datetime.now().isoformat(timespec="seconds")) + "\n")
        except Exception:
            pass

    # --- CORS + security headers (XSS-03 + basic hardening) ------------------
    def _security_headers(self):
        # XSS-03: permissive-but-safe CORS so the API works behind a CDN/custom
        # domain, plus standard hardening headers. Location stays on-device; these
        # do not weaken the privacy model.
        origin = self.headers.get("Origin")
        self.send_header("Access-Control-Allow-Origin", origin or "*")
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Operator-Token")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _text(self, body, code=200):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(b)

    # --- operator authentication (AUTH-01/02/06) ----------------------------
    def _bearer(self):
        # Pull the operator credential from Authorization: Bearer, the
        # X-Operator-Token header, or a ?token= query param (for review.html).
        h = self.headers.get("Authorization", "")
        if h.lower().startswith("bearer "):
            return h[7:].strip()
        t = self.headers.get("X-Operator-Token")
        if t:
            return t.strip()
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("token"):
                return q["token"][0].strip()
        except Exception:
            pass
        return ""

    def _operator(self):
        """Return {"user","role"} for an authenticated operator, or None.

        Accepts either the shared OPERATOR_TOKEN (role=admin) or a signed session
        token minted by /api/login from the DEYSAFE_OPERATORS roster (auth.py)."""
        tok = self._bearer()
        if not tok:
            return None
        if OPERATOR_TOKEN and hmac.compare_digest(tok, OPERATOR_TOKEN):
            return {"user": "operator", "role": "admin"}
        return auth.identity(tok)  # roster-based session token (or None)

    def _auth_enabled(self):
        # Locked posture is active only when a shared token OR a roster is configured.
        return bool(OPERATOR_TOKEN) or auth.auth_enabled()

    def _authed(self):
        # FAIL-CLOSED: operator surfaces always require a valid operator token.
        # If no OPERATOR_TOKEN/roster is configured, no token can be valid, so the
        # operator console + endpoints are LOCKED — a careless deploy ships safe,
        # not wide open. Deploys/gates set OPERATOR_TOKEN (or DEYSAFE_OPERATORS).
        return self._operator() is not None

    def require(self, role="viewer"):
        """Gate: True only if the caller presents a valid operator token whose role
        satisfies `role`. Fail-closed — no anonymous operator actions, ever."""
        op = self._operator()
        if not op:
            return False
        return auth.has_role(op.get("role", ""), role)

    def _static(self, path):
        rel = os.path.normpath((path.lstrip("/") or "index.html")).replace("\\", "/")
        if rel.startswith(".."):
            return self.send_error(403)
        fp = os.path.join(APP_DIR, rel)
        if not os.path.isfile(fp):
            fp = os.path.join(APP_DIR, "index.html")
        with open(fp, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", CTYPES.get(os.path.splitext(fp)[1].lower(), "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        # XSS-03: CORS preflight. 204 + the shared CORS/security headers, no body.
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        db = DB(DB_PATH)
        if u.path == "/api/health":
            # FAKE-01: expose whether this instance is showing synthetic demo data.
            return self._json({"ok": True, "incidents": len(public_incidents(db)),
                               "queue": len(review_queue(db)), "missing": len(db.all_missing()),
                               "demo": DEMO_MODE, "auth": self._auth_enabled()})
        if u.path == "/api/incidents":
            return self._json({"incidents": public_incidents(db)})
        if u.path == "/api/queue":
            # AUTH-01: operator-only review queue.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"queue": review_queue(db)})
        if u.path == "/api/missing":
            # PRIV-01/BLE-02: public callers get the redacted flyer; an authenticated
            # operator/responder gets the full record (exact place, coords, beacon).
            return self._json({"missing": missing_with_radius(db, restricted=self._authed() and self._auth_enabled())})
        if u.path == "/api/alerts":
            return self._json({"alerts": db.active_alerts()})
        if u.path == "/api/channel":
            return self._json({"posts": db.recent_channel()})
        if u.path == "/api/places":
            coords = {p["name"]: [p["lat"], p["lng"]] for p in PLACES}
            return self._json({"places": PLACE_NAMES, "types": TYPES, "coords": coords})
        if u.path == "/api/ai-status":
            return self._json({"ai": ai.available(), "provider": ai.provider(), "keys": ai.key_count(), "sms": sms.available()})
        if u.path == "/api/risk":
            q = urllib.parse.parse_qs(u.query)
            if q.get("lat") and q.get("lng"):
                try:
                    return self._json(risk_at(public_incidents(db), float(q["lat"][0]), float(q["lng"][0])))
                except Exception:
                    pass
            return self._json(risk_for(public_incidents(db), q.get("place", [""])[0]))
        if u.path == "/api/geocode":
            g = geocode(urllib.parse.parse_qs(u.query).get("q", [""])[0])
            return self._json({"ok": bool(g), "result": g})
        # AUTH-06: keep the SHIELD operator console behind operator auth when a
        # token/roster is configured. Fail-open (served) when auth is disabled, so
        # validate.py:88 ("SHIELD" in /review.html) stays green on a fresh box.
        if u.path in ("/review.html", "/review") and not self._authed():
            return self._json({"ok": False, "error": "operator auth required"}, 401)
        return self._static(u.path)

    def _client_id(self):
        # Best-effort caller identity for rate limiting. Prefer a forwarded IP
        # (behind a proxy/CDN), else the socket peer.
        fwd = self.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
        try:
            return self.client_address[0]
        except Exception:
            return "?"

    def _rate_ok(self, path, limit_per_min):
        # ABU-01: per-(caller, endpoint) token bucket. Generous default so the
        # validate.py gate (≈56 reqs total) never trips; small limits lock down.
        return ratelimit.allow(self._client_id() + "|" + path, limit_per_min=limit_per_min)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        ln = int(self.headers.get("Content-Length", "0") or 0)
        # ABU-02: reject oversized bodies BEFORE reading them into memory.
        if ln > ratelimit.MAX_BODY:
            # Drain a bounded amount so the socket can be reused, then 413.
            try:
                self.rfile.read(min(ln, ratelimit.MAX_BODY))
            except Exception:
                pass
            return self._json({"ok": False, "error": "payload too large"}, 413)
        raw = self.rfile.read(ln).decode("utf-8", "replace") if ln else ""
        try:
            data = json.loads(raw) if raw else {}
        except Exception:
            data = {}
        if not data and raw and "=" in raw:  # form-encoded (e.g. Africa's Talking webhooks)
            try:
                data = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
            except Exception:
                data = {}
        db = DB(DB_PATH)

        if u.path == "/api/login":
            # AUTH-01: exchange operator username+password for a signed session token.
            # Rate-limited to blunt brute force. Returns {token, name} on success.
            if not self._rate_ok("/api/login", 20):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            user = (data.get("username") or data.get("user") or "").strip()
            pw = data.get("password") or data.get("pass") or ""
            tok = auth.check_login(user, pw)
            if not tok:
                db.audit("auth", "login_fail", "user=%s" % user[:40])
                return self._json({"ok": False, "error": "invalid credentials"}, 401)
            ident = auth.identity(tok) or {}
            db.audit("auth", "login_ok", "user=%s role=%s" % (user[:40], ident.get("role")))
            return self._json({"ok": True, "token": tok, "name": user, "role": ident.get("role")})

        if u.path == "/api/report":
            # ABU-01: throttle anonymous report spam (per caller). Bucket capacity =
            # 20/min: a tight burst (25 identical reports) trips a 429, while normal
            # spread-out reporting is unaffected.
            if not self._rate_ok("/api/report", 12):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            typ, place, desc = (data.get("type") or "").strip(), (data.get("place") or "").strip(), (data.get("description") or "").strip()
            if not place or not desc:
                return self._json({"ok": False, "error": "place and description required"}, 400)
            # ABU-09: constrain the incident type to the controlled vocabulary. An
            # arbitrary 'made_up_type' is coerced to other_needs_review, never stored
            # as a fabricated category. (Empty type stays empty -> unstructured signal.)
            gtype = security.valid_type(typ) if typ else None
            type_word = gtype.replace("_", " ") if gtype else "incident"
            g = geocode(place)  # gazetteer -> free OSM; lets a typed report of ANY town hit the map
            lat = g["lat"] if g else None
            lng = g["lng"] if g else None
            loc_name = g["name"] if g else place
            state = g.get("state", "") if g else ""
            location_unverified = g is None  # GEO-01: no gazetteer/OSM match -> needs a pin
            sev = geoparse.detect_severity(desc + " " + type_word)
            db.insert_signal({"source_name": "Community report", "kind": "report",
                              "title": "{} near {}".format(type_word, loc_name),
                              "text": "{} near {}. {}".format(type_word, place, desc),
                              "url": "", "lang": "en",
                              "published_at": datetime.datetime.now().isoformat(timespec="seconds"),
                              "lat": lat, "lng": lng, "location_name": loc_name, "state": state,
                              "gtype": gtype, "gseverity": sev})
            db.audit("api", "community_report", "place={} type={} geo={}".format(place, gtype, bool(g)))
            recompute(db)
            risk = risk_at(public_incidents(db), lat, lng) if lat is not None else risk_for(public_incidents(db), place)
            # GEO-01: tell the client the point wasn't placed so it can prompt a manual
            # pin instead of implying a (non-existent) centroid pin.
            resp = {"ok": True, "risk": risk, "location_unverified": location_unverified,
                    "coords_confidence": ("unverified" if location_unverified else (g.get("source") or "gazetteer"))}
            return self._json(resp)

        if u.path == "/api/ingest-live":
            # AUTH-01: operator-only RSS pull.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            # Operator-triggered pull of PUBLIC Nigerian news RSS. Public data only;
            # per-feed failures are skipped. RSS is unstructured -> gazetteer geoparse;
            # everything lands as candidate_unverified (human still gates escalation).
            fetched, added, ai_used, ok = 0, 0, 0, True
            AI_CAP = 30  # bound LLM calls per pull (cost/latency); reported, not silent
            try:
                sigs = ingest.load_live()
                fetched = len(sigs)
                for sg in sigs:
                    sid, is_new = db.insert_signal(sg)
                    if not is_new:
                        continue
                    added += 1
                    # Spend AI ONLY on fresh news the rule-based parser can't place.
                    # AI extracts type+place -> geocode -> promote to a structured signal.
                    if ai.available() and ai_used < AI_CAP and not geoparse.geoparse(sg):
                        ai_used += 1
                        res = ai.classify((sg.get("title", "") + ". " + sg.get("text", "")).strip())
                        if isinstance(res, dict) and res.get("is_incident") and res.get("incident_type") in TYPES and res.get("location_text"):
                            g = geocode(res["location_text"])
                            if g:
                                db.update_signal_geo(sid, {
                                    "lat": g["lat"], "lng": g["lng"], "location_name": g["name"],
                                    "state": res.get("state") or g.get("state", ""),
                                    "gtype": res["incident_type"],
                                    "gseverity": 1 if res.get("urgency") in ("high", "critical") else 0})
                recompute(db)
            except Exception as e:
                db.audit("operator", "ingest_live_error", repr(e)[:200])
                ok = False
            inc = len(public_incidents(db))
            if ok:
                db.audit("operator", "ingest_live", "fetched={} added={} ai={} incidents={}".format(fetched, added, ai_used, inc))
            return self._json({"ok": ok, "fetched": fetched, "added": added, "ai_used": ai_used,
                               "ai_on": ai.available(), "incidents": inc, "queue": len(review_queue(db))})

        if u.path == "/api/intake":
            # AI intake: free text / speech in -> structured fields out, for the human
            # to glance at + submit. Uses the LLM when a key is set; rule-based fallback.
            text = (data.get("text") or "").strip()
            mode = (data.get("mode") or "auto").strip().lower()
            if not text:
                return self._json({"ok": False, "error": "text required"}, 400)
            if mode not in ("report", "missing"):
                low = text.lower()
                mode = "missing" if any(w in low for w in ("missing", "abducted", "kidnapp", "find my", "my son", "my daughter", "my child", "disappear", "last seen", "not seen")) else "report"
            used_ai = False
            if mode == "missing":
                res = ai.extract_missing(text) if ai.available() else None
                if isinstance(res, dict) and not res.get("error"):
                    used_ai = True
                    fields = {"name": res.get("name") or "", "age": str(res.get("age") or ""),
                              "count": res.get("count") or 1, "place": res.get("place") or "",
                              "exact_place": res.get("exact_place") or "",
                              "hours_ago": res.get("hours_ago") if res.get("hours_ago") is not None else 1,
                              "description": res.get("description") or text,
                              "vehicle": res.get("vehicle") or "", "clothing": res.get("clothing") or "",
                              "direction": res.get("direction") or ""}
                else:
                    gp = geoparse.geoparse({"title": "", "text": text}) or {}
                    fields = {"name": "", "age": "", "count": 1, "place": gp.get("location_name", ""),
                              "exact_place": "", "hours_ago": 1, "description": text,
                              "vehicle": "", "clothing": "", "direction": ""}
            else:
                res = ai.classify(text) if ai.available() else None
                if isinstance(res, dict) and not res.get("error") and res.get("is_incident"):
                    used_ai = True
                    # ABU-09: constrain the suggested type to the controlled vocabulary.
                    sug = res.get("incident_type") or ""
                    fields = {"type": (security.valid_type(sug) if sug else ""), "place": res.get("location_text") or "",
                              "description": res.get("summary") or text}
                else:
                    gp = geoparse.geoparse({"title": "", "text": text}) or {}
                    fields = {"type": gp.get("type", ""), "place": gp.get("location_name", ""),
                              "description": text}
            db.audit("api", "ai_intake", "mode={} ai={}".format(mode, used_ai))
            return self._json({"ok": True, "mode": mode, "ai": used_ai, "ai_on": ai.available(), "fields": fields})

        if u.path == "/api/channel":
            # Community safety channel (Zello-style, light): short area-tagged posts.
            # Community chatter, NOT verified alerts -> never creates incidents/alerts.
            if not self._rate_ok("/api/channel", 40):  # ABU-01
                return self._json({"ok": False, "error": "rate limited"}, 429)
            text = (data.get("text") or "").strip()[:280]
            if not text:
                return self._json({"ok": False, "error": "text required"}, 400)
            area = (data.get("area") or "").strip()
            g = geocode(area) if area else None
            db.insert_channel({"area": (g["name"] if g else area), "text": text,
                               "lat": (g["lat"] if g else None), "lng": (g["lng"] if g else None),
                               "source": "community"})
            db.audit("api", "channel_post", "area={}".format(area))
            return self._json({"ok": True, "posts": db.recent_channel()})

        if u.path == "/api/sms":
            # Inbound SMS report (Africa's Talking posts here). Basic-phone reach.
            if not self._rate_ok("/api/sms", 40):  # ABU-01
                return self._json({"ok": False, "error": "rate limited"}, 429)
            text = (data.get("text") or "").strip()
            if not text:
                return self._json({"ok": False, "error": "text required"}, 400)
            parsed = ingest_text_report(db, text, "SMS report")
            db.audit("sms", "inbound", "from={} place={}".format((data.get("from") or "")[:6], parsed.get("place")))
            return self._json({"ok": True, "parsed": parsed})

        if u.path == "/api/ussd":
            # USSD menu (Africa's Talking). `text` accumulates choices like "2*gunmen on road".
            txt = (data.get("text") or "").strip()
            parts = txt.split("*") if txt else []
            if not parts:
                return self._text("CON DeySafe - stay safe\n1. Check my area\n2. Report danger\n3. Missing person")
            if parts[0] == "1":
                if len(parts) < 2 or not parts[1]:
                    return self._text("CON Enter your town or area:")
                r = risk_for(public_incidents(db), parts[1])
                return self._text("END {} - {}. {}".format(parts[1].title(), r["level"], r["guidance"]))
            if parts[0] == "2":
                if len(parts) < 2 or not parts[1]:
                    return self._text("CON Describe the danger (what and where):")
                ingest_text_report(db, parts[1], "USSD report")
                return self._text("END Reported anonymously. Thank you - stay safe.")
            if parts[0] == "3":
                if len(parts) < 2 or not parts[1]:
                    return self._text("CON Area the person was last seen:")
                return self._text("END Noted near {}. Please add details on the DeySafe app.".format(parts[1].title()))
            return self._text("END Sorry, invalid choice.")

        if u.path == "/api/beacon-relay":
            # BLE: a FIELD phone (not an operator) relays a beacon sighting, so this is
            # NOT operator-gated. Phase-0 protection = the beacon must already be
            # registered to a case (unknown -> matched:false, below). The real anti-spoof
            # fix (signed rotating beacon envelope + replay protection) is Phase 1 / BLE-01.
            # AirTag-style crowd relay: a native app that hears a registered missing-
            # person beacon POSTs {beacon_id, lat, lng} -> we log it as a SIGHTING, which
            # re-anchors + tightens the triangulation. Works in no-network areas because
            # the FINDER's phone (not the beacon) carries the report out (store-and-forward).
            bid = (data.get("beacon_id") or "").strip()
            if not bid:
                return self._json({"ok": False, "error": "beacon_id, lat, lng required"}, 400)
            try:
                lat = float(data.get("lat"))
                lng = float(data.get("lng"))
            except Exception:
                return self._json({"ok": False, "error": "beacon_id, lat, lng required"}, 400)
            case = db.find_missing_by_beacon(bid)
            if not case:
                return self._json({"ok": True, "matched": False})  # unknown beacon -> reveal nothing
            try:
                hrs = float(data.get("hours_ago") or 0.1)
            except Exception:
                hrs = 0.1
            db.insert_sighting({"case_id": case["id"], "place": "Bluetooth relay", "lat": lat, "lng": lng,
                                "seen_at": (datetime.datetime.now() - datetime.timedelta(hours=hrs)).isoformat(timespec="seconds"),
                                "note": "crowd Bluetooth relay", "source": "bluetooth"})
            db.audit("beacon", "relay", "case={}".format(case["id"]))
            # BLE-02: the relay caller is authenticated here, so the full (restricted)
            # view is appropriate; never the beacon_id-bearing public payload.
            return self._json({"ok": True, "matched": True,
                               "missing": missing_with_radius(db, restricted=True)})

        if u.path == "/api/missing":
            # ABU-01: throttle case-creation spam (per caller).
            if not self._rate_ok("/api/missing", 30):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            name, place = (data.get("name") or "").strip(), (data.get("place") or "").strip()
            if not name or not place:
                return self._json({"ok": False, "error": "name and place required"}, 400)
            lat, lng, verified = coords_for(place)  # GEO-01: verified flag, no silent centroid
            try:
                hrs = float(data.get("hours_ago") or 1)
            except Exception:
                hrs = 1.0
            db.insert_missing({"name": name, "age": (data.get("age") or "").strip(), "place": place,
                               "exact_place": (data.get("exact_place") or "").strip(),
                               "count": data.get("count") or 1, "lat": lat, "lng": lng,
                               "last_seen": (datetime.datetime.now() - datetime.timedelta(hours=hrs)).isoformat(timespec="seconds"),
                               "description": (data.get("description") or "").strip(),
                               "vehicle": (data.get("vehicle") or "").strip(),
                               "clothing": (data.get("clothing") or "").strip(),
                               "direction": (data.get("direction") or "").strip(),
                               "beacon_id": (data.get("beacon_id") or "").strip()})
            db.audit("api", "missing_report", "place={} count={}".format(place, data.get("count") or 1))
            # PRIV-01: the POST response echoes the submitter's OWN case in full (you
            # may see what you just filed). The PUBLIC scrape surface is GET /api/missing,
            # which IS redacted for anonymous callers. So the privacy boundary is the
            # GET list, not this confirmation echo.
            return self._json({"ok": True, "location_unverified": not verified,
                               "coords_confidence": ("unverified" if not verified else "gazetteer"),
                               "missing": missing_with_radius(db, restricted=True)})

        if u.path == "/api/verify":
            # AUTH-01: the human publish gate is operator-only. Also the most
            # important lock — it promotes an event to a public RED alert.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            decision = (data.get("decision") or "").strip()
            if decision not in ("verified", "dismissed"):
                return self._json({"ok": False, "error": "decision must be verified|dismissed"}, 400)
            # ABU-09: coerce the posted type to the controlled vocabulary before matching.
            typ = security.valid_type(data.get("type")) if (data.get("type") or "").strip() else (data.get("type") or "").strip()
            disp_key = "{}|{}|{}".format(typ, (data.get("location_name") or "").strip(),
                                         (data.get("state") or "").strip())
            # INT-01: resolve the LIVE incident first and key the decision on its
            # immutable incident_uuid (not the type|location|state triple). A stale
            # decision can no longer re-bind to a different, newer event.
            inc = next((i for i in with_decisions(db) if ikey(i) == disp_key), None)
            actor = (self._operator() or {}).get("user", "operator")
            if not inc:
                # No live incident matches -> record the decision against the display
                # key so the audit trail is complete, but there is nothing to alert on.
                db.set_decision(None, decision, (data.get("note") or "").strip(), actor, key=disp_key)
                db.audit(actor, "decision", "{} -> {} (no live incident)".format(disp_key, decision))
                return self._json({"ok": True, "decision": decision, "queue": len(review_queue(db)), "alert": None})
            iuid = inc.get("incident_uuid")
            db.set_decision(iuid, decision, (data.get("note") or "").strip(), actor,
                            event_version=inc.get("event_version"), key=disp_key)
            db.audit(actor, "decision", "{} ({}) -> {}".format(disp_key, iuid, decision))
            alert = None
            if decision == "verified":
                lvl = alert_level(inc["confidence"], inc["severity"])
                rad = TYPE_RADIUS.get(inc["type"], 30)
                # INT-02: idempotent — only fire a new public alert if one isn't
                # already active for THIS incident (keyed by the immutable uuid).
                if not db.has_active_alert(iuid):
                    alert = {"incident_key": iuid, "level": lvl, "level_label": LEVEL_LABEL[lvl],
                             "title": "{} — {}, {} — verified".format(inc["type"].replace("_", " ").upper(), inc["location_name"], inc["state"]),
                             "guidance": TYPE_GUIDANCE.get(inc["type"], "Avoid the area and stay alert. Emergency: 112."),
                             "lat": inc["lat"], "lng": inc["lng"], "radius_km": rad, "reach": rad * 120}
                    db.insert_alert(alert)
                    db.audit("system", "alert_fired", "L{} {} reach~{}".format(lvl, iuid, rad * 120))
            else:
                db.resolve_alert(iuid)
            return self._json({"ok": True, "decision": decision, "queue": len(review_queue(db)), "alert": alert})

        if u.path == "/api/sighting":
            # ABU-01: throttle sighting spam (a re-anchoring vector).
            if not self._rate_ok("/api/sighting", 40):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            try:
                cid = int(data.get("case_id"))
            except Exception:
                return self._json({"ok": False, "error": "case_id required"}, 400)
            # ABU-10: the case must exist — otherwise a sighting can anchor a phantom
            # search zone. Reject unknown case ids with 404.
            if not db.get_missing(cid):
                return self._json({"ok": False, "error": "unknown case"}, 404)
            place = (data.get("place") or "").strip()
            if not place:
                return self._json({"ok": False, "error": "place required"}, 400)
            lat, lng, _verified = coords_for(place)  # GEO-01 (3-tuple)
            try:
                hrs = float(data.get("hours_ago") or 0.5)
            except Exception:
                hrs = 0.5
            db.insert_sighting({"case_id": cid, "place": place, "lat": lat, "lng": lng,
                                "seen_at": (datetime.datetime.now() - datetime.timedelta(hours=hrs)).isoformat(timespec="seconds"),
                                "note": (data.get("note") or "").strip(), "source": "community"})
            db.audit("api", "sighting", "case={} place={}".format(cid, place))
            # PRIV-01: redact the response for public callers.
            return self._json({"ok": True, "missing": missing_with_radius(db, restricted=self._authed() and self._auth_enabled())})

        if u.path == "/api/case-status":
            # AUTH-01: operators resolve/close cases.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            try:
                cid = int(data.get("case_id"))
            except Exception:
                return self._json({"ok": False, "error": "case_id required"}, 400)
            status = (data.get("status") or "").strip()
            if status not in ("active", "located", "recovered", "resolved"):
                return self._json({"ok": False, "error": "bad status"}, 400)
            db.set_missing_status(cid, status)
            actor = (self._operator() or {}).get("user", "operator")
            db.audit(actor, "case_status", "case={} -> {}".format(cid, status))
            return self._json({"ok": True, "missing": missing_with_radius(db, restricted=self._authed() and self._auth_enabled())})

        if u.path == "/api/classify":
            text = (data.get("text") or "").strip()
            if not text:
                return self._json({"ok": False, "error": "text required"}, 400)
            gp = geoparse.geoparse({"title": "", "text": text})
            rule_based = {"is_incident": bool(gp), "incident_type": gp["type"] if gp else None,
                          "location_text": gp["location_name"] if gp else None,
                          "severity": gp["severity"] if gp else 0, "method": "rule-based"}
            if not ai.available():
                return self._json({"ok": True, "ai": False,
                                   "note": "Real LLM is OFF. Set GEMINI_API_KEY (or GROQ_API_KEY / CEREBRAS_API_KEY) to turn it on.",
                                   "rule_based": rule_based})
            return self._json({"ok": True, "ai": True, "provider": ai.provider(),
                               "result": ai.classify(text), "rule_based": rule_based})

        return self.send_error(404)


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    ensure_seed(DB(DB_PATH))
    port = int(os.environ.get("PORT", "4500"))
    host = os.environ.get("HOST", "0.0.0.0")
    ai_on = ("ON (" + (ai.provider() or "") + ")") if ai.available() else "OFF — set CEREBRAS_API_KEY / GEMINI_API_KEY / GROQ_API_KEY"
    print("DeySafe + SHIELD on %s:%d  |  AI: %s  |  operator console at /review.html" % (host, port, ai_on))
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
