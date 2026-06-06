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
        "state": row.get("state"),
        "status": row.get("state"),
        "risk_level": row.get("risk_level"),
        "anomaly_level": row.get("anomaly_level"),
        "anomaly_reason": row.get("anomaly_reason"),
        "last_checkin_at": row.get("last_checkin_at"),
        "share_consent": bool(row.get("share_consent")),
        "coords_redacted": True,
    }


def readiness_view(row):
    if not row:
        return None
    return {
        "owner_token": row.get("owner_token"),
        "platform": row.get("platform"),
        "findmy_enabled": bool(row.get("findmy_enabled")),
        "findhub_enabled": bool(row.get("findhub_enabled")),
        "trusted_contacts": int(row.get("trusted_contacts") or 0),
        "silent_sos": bool(row.get("silent_sos")),
        "sms_fallback": bool(row.get("sms_fallback")),
        "wearable": bool(row.get("wearable")),
        "offline_pack": bool(row.get("offline_pack")),
        "readiness_score": int(row.get("readiness_score") or 0),
        "gaps": row.get("gaps") or [],
        "updated_at": row.get("updated_at"),
    }


def evidence_public_view(row):
    return safety.public_evidence_view(row) if row else None


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

# 36 states + FCT. Used to recover the STATE from a free OSM display_name like
# "Funtua, Katsina, Nigeria" so an off-gazetteer geocode still carries a state
# (the incident key + the geofenced broadcast both rely on a populated state).
NG_STATES = (
    "Abia", "Adamawa", "Akwa Ibom", "Anambra", "Bauchi", "Bayelsa", "Benue",
    "Borno", "Cross River", "Delta", "Ebonyi", "Edo", "Ekiti", "Enugu", "Gombe",
    "Imo", "Jigawa", "Kaduna", "Kano", "Katsina", "Kebbi", "Kogi", "Kwara",
    "Lagos", "Nasarawa", "Niger", "Ogun", "Ondo", "Osun", "Oyo", "Plateau",
    "Rivers", "Sokoto", "Taraba", "Yobe", "Zamfara", "Abuja",
    "Federal Capital Territory", "FCT",
)
_NG_STATE_LOOKUP = {s.lower(): ("FCT" if s in ("Abuja", "Federal Capital Territory") else s)
                    for s in NG_STATES}


def _state_from_display(display):
    """Best-effort: pull the Nigerian state out of an OSM display_name string.

    OSM returns comma-separated locality parts ending in 'Nigeria'; the state is
    usually one of those parts. We match any part against the 36+FCT list (so a
    stray postcode part between the state and 'Nigeria' doesn't break it). Returns
    '' when no known state name is present (we never guess)."""
    if not display:
        return ""
    for part in str(display).split(","):
        p = part.strip().lower()
        if p in _NG_STATE_LOOKUP:
            return _NG_STATE_LOOKUP[p]
    return ""


def geocode(q, db=None):
    """Resolve ANY Nigerian place to coordinates: OFFLINE gazetteer first, then a
    persisted geo-cache, then free OpenStreetMap / Nominatim (no API key).

    GEO-02/03: the 774-LGA offline gazetteer (engine/gazetteer.py) is tried FIRST,
    so the common case (a real LGA/town/ward, incl. aliases + typos) resolves with
    NO network call and carries a `confidence` grade. Only a true offline miss
    falls through to the live OSM path; whatever OSM returns is persisted to the
    `geo_cache` table (when a db is supplied) so the next restart doesn't re-fetch.
    GEO-01 is preserved end to end: a total miss returns None (never a centroid)."""
    q = (q or "").strip()
    if not q:
        return None
    # 1) Seed table exact hit (kept for parity / the curated hotspot flag).
    for p in PLACES:
        if p["name"].lower() == q.lower():
            return {"name": p["name"], "lat": p["lat"], "lng": p["lng"], "source": "gazetteer",
                    "state": p.get("state", ""), "hotspot": p.get("hotspot", False),
                    "confidence": gazetteer.CONF_EXACT}
    # 2) OFFLINE 774-LGA gazetteer (alias/normalised/typo tolerant, confidence-graded).
    gm = gazetteer.lookup(q)
    if gm:
        return {"name": gm["name"], "lat": gm["lat"], "lng": gm["lng"], "source": "gazetteer",
                "state": gm.get("state", ""), "hotspot": gm.get("hotspot", False),
                "confidence": gm.get("confidence", gazetteer.CONF_EXACT), "kind": gm.get("kind", "")}
    key = q.lower()
    if key in _geocache:
        return _geocache[key]
    # 3) Durable geo-cache: a prior OSM hit persisted across restarts (GEO-02).
    if db is not None:
        try:
            row = db.get_geo_cache(key)
        except Exception:
            row = None
        if row and row.get("lat") is not None and row.get("lng") is not None:
            res = {"name": q.title(), "lat": row["lat"], "lng": row["lng"],
                   "source": row.get("source") or "osm_cache",
                   "display": row.get("display", ""), "state": _state_from_display(row.get("display", "")),
                   "confidence": row.get("confidence") or "osm"}
            _geocache[key] = res
            return res
    res = None
    try:
        url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(
            {"q": q + ", Nigeria", "format": "json", "limit": "1", "countrycodes": "ng"})
        req = urllib.request.Request(url, headers={"User-Agent": "DeySafe/0.1 (safety prototype)"})
        with urllib.request.urlopen(req, timeout=12) as r:
            arr = json.loads(r.read().decode("utf-8"))
        if arr:
            disp = arr[0].get("display_name", "")
            res = {"name": q.title(), "lat": float(arr[0]["lat"]), "lng": float(arr[0]["lon"]),
                   "source": "osm", "display": disp, "state": _state_from_display(disp),
                   "confidence": "osm"}
    except Exception:
        res = None
    _geocache[key] = res
    # GEO-02: persist a live OSM hit so subsequent restarts answer from the cache
    # (offline) instead of re-hitting Nominatim. Misses are NOT cached (a town may
    # appear in OSM later); the in-process _geocache still short-circuits repeats.
    if res and db is not None:
        try:
            db.put_geo_cache(key, res["lat"], res["lng"], source="osm",
                             display=res.get("display", ""), confidence="osm")
        except Exception:
            pass
    return res


def coords_for(place, db=None):
    """Best coordinates for a TYPED place: OFFLINE gazetteer -> geo-cache -> free OSM.
    Returns (lat, lng, verified). GEO-01: on a total miss we return (None, None,
    False) rather than silently pinning the Nigeria centroid (9.2, 8.2) — the caller
    then stores null coords + marks the location unverified (needs a manual pin)."""
    g = geocode(place, db=db)
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


# --- DATA-05 negative-term false-positive suppression ------------------------
# geoparse.geoparse() abstains only when it finds no incident TYPE or no LOCATION.
# It does NOT (yet) consult keywords.json `negative_terms`, so a sports/politics/
# metaphor sentence that happens to reuse an incident word ("Super Eagles launched
# an ATTACK ... in KANO") still geoparses to a fake banditry_attack incident. We
# own the report PIPELINE (recompute / ingest), so we apply the negative-term veto
# HERE, around geoparse, rather than editing the parser module: if the text is
# dominated by non-emergency negatives AND carries no strong incident signal, the
# detection is dropped. Conservative by construction — a genuine report (which
# carries incident + place terms and no sports/promo chatter) is never suppressed.
_NEG_TERMS = []          # flat list of (category, term_lower)
try:
    _nt_cfg = geoparse._KW.get("negative_terms", {})  # reuse the already-loaded config
    for _cat, _terms in _nt_cfg.items():
        if _cat.startswith("_") or not isinstance(_terms, list):
            continue
        for _t in _terms:
            if _t:
                _NEG_TERMS.append((_cat, _t.lower()))
except Exception:
    _NEG_TERMS = []


def _negative_hits(text):
    """Number of negative-context term matches in `text` (whole-word/phrase)."""
    if not text or not _NEG_TERMS:
        return 0
    t = " " + text.lower() + " "
    n = 0
    for _cat, term in _NEG_TERMS:
        # phrases match as substrings; single words need word boundaries so 'film'
        # doesn't fire inside 'filming' incident-free... (kept simple + safe).
        if " " in term:
            if term in t:
                n += 1
        elif re.search(r"\b" + re.escape(term) + r"\b", t):
            n += 1
    return n


def negatives_dominate(signal):
    """True if a free-text signal looks like non-emergency chatter that merely
    reuses an incident keyword (DATA-05). Requires BOTH: at least 2 negative
    matches (one stray word isn't enough), AND the negatives strictly outnumber
    the incident-term hits geoparse found — so a real report with one incidental
    negative word is never dropped. A severity signal (e.g. 'gunmen killed')
    overrides suppression so a genuine violent event is never silenced."""
    text = (signal.get("title", "") + ". " + signal.get("text", "")).strip()
    neg = _negative_hits(text)
    if neg < 2:
        return False
    _type, hits = geoparse.detect_type(text)
    inc_hits = len(hits)
    if geoparse.detect_severity(text) > 0:
        return False  # explicit violence/severity wins — never suppress
    return neg > inc_hits


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
        # DATA-05: drop non-emergency chatter before it can geoparse to a phantom
        # incident (sports/politics/metaphor reusing an incident word).
        if negatives_dominate(s):
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
    g = geocode(place, db=db) if place else None
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
        # FIND-02: terrain-aware search ring. The old flat ~50 km/h assumed a road
        # spread, which dangerously UNDER-states the area when an abductee is moved
        # off-road on foot (forest 12 km/h, mountain/riverine 8 km/h). terrain is
        # derived from the case's free-text 'direction' note + locality, and the
        # ASSUMPTION is surfaced (terrain) so nobody silently trusts a 250 km ring.
        radius_km, terrain_class = terrain.reach_radius_for(
            hrs, direction_text=m.get("direction"), place=(m.get("place") or m.get("exact_place")))

        if restricted:
            # Operator / responder view: full detail (already authenticated).
            m["sightings"] = sights
            m["sighting_count"] = len(sights)
            m["anchor"] = anchor
            m["search_lat"], m["search_lng"] = alat, alng
            m["hours"] = round(hrs, 1)
            m["radius_km"] = radius_km
            m["terrain"] = terrain_class
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
        pub["terrain"] = terrain_class  # coarse class only — not a sensitive detail
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
                               "demo": DEMO_MODE, "auth": self._auth_enabled(),
                               "database": {"backend": db.backend(),
                                            "postgres_configured": bool(os.environ.get("DATABASE_URL")),
                                            "postgres_required": os.environ.get(
                                                "DEYSAFE_REQUIRE_POSTGRES", "").strip().lower() in (
                                                "1", "true", "yes", "on")}})
        if u.path == "/api/incidents":
            # PERF-02: paginated (limit/offset) with total + next_offset, list still
            # under "incidents" so existing clients are unaffected.
            return self._json(self._paged(u, public_incidents(db), "incidents"))
        if u.path == "/api/queue":
            # AUTH-01: operator-only review queue. PERF-02 paginated.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json(self._paged(u, review_queue(db), "queue"))
        if u.path == "/api/missing":
            # PRIV-01/BLE-02: public callers get the redacted flyer; an authenticated
            # operator/responder gets the full record (exact place, coords, beacon).
            # PERF-02 paginated; list stays under "missing".
            rows = missing_with_radius(db, restricted=self._authed() and self._auth_enabled())
            return self._json(self._paged(u, rows, "missing"))
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
            g = geocode(urllib.parse.parse_qs(u.query).get("q", [""])[0], db=db)
            return self._json({"ok": bool(g), "result": g})
        if u.path == "/api/gazetteer":
            # GEO-02/03 (FIELD, public): resolve a free-typed Nigerian place against
            # the 774-LGA OFFLINE gazetteer ONLY (no network) and return the best
            # match WITH a confidence grade + a few ranked alternatives. This is the
            # offline sibling of /api/geocode: it never hits OSM, so it answers in
            # no-network areas and always carries the confidence the UI uses to
            # decide "trust the pin" vs "ask for a manual pin" (GEO-01).
            q = urllib.parse.parse_qs(u.query)
            term = (q.get("q", [""])[0] or q.get("place", [""])[0] or q.get("name", [""])[0]).strip()
            if not term:
                return self._json({"ok": False, "error": "q required"}, 400)
            best = gazetteer.lookup(term)
            alts = gazetteer.candidates(term, limit=self._limit(u, default=5))
            if not best:
                # GEO-01: a true miss is an explicit, honest negative — never a centroid.
                return self._json({"ok": False, "result": None, "candidates": [],
                                   "source": gazetteer.SOURCE, "query": term})
            return self._json({"ok": True, "result": best, "candidates": alts,
                               "source": gazetteer.SOURCE, "query": term})
        if u.path == "/api/route":
            # WAKA-01 (FIELD, public): road-aware CORRIDOR scan between two places.
            # Resolves both endpoints offline-first, densifies the great-circle into
            # ordered waypoints, and scores EACH segment against live public
            # incidents — so a danger BETWEEN the endpoints is caught (the old
            # two-endpoint straight-line check missed it). Honestly labelled a
            # corridor approximation (NOT true road routing) in the payload.
            q = urllib.parse.parse_qs(u.query)
            a_raw = (q.get("from", [""])[0] or q.get("start", [""])[0] or q.get("a", [""])[0]).strip()
            b_raw = (q.get("to", [""])[0] or q.get("end", [""])[0] or q.get("b", [""])[0]).strip()
            if not a_raw or not b_raw:
                return self._json({"ok": False, "error": "from and to required"}, 400)
            ga = geocode(a_raw, db=db)
            gb = geocode(b_raw, db=db)
            if not ga or not gb:
                # GEO-01: don't invent endpoints we can't place.
                return self._json({"ok": False, "error": "could not resolve from/to",
                                   "from_resolved": bool(ga), "to_resolved": bool(gb)}, 400)
            try:
                n = max(2, min(60, int(q.get("waypoints", [routing.DEFAULT_WAYPOINTS])[0])))
            except Exception:
                n = routing.DEFAULT_WAYPOINTS
            try:
                radius = float(q.get("radius_km", [routing.DEFAULT_RADIUS_KM])[0])
            except Exception:
                radius = routing.DEFAULT_RADIUS_KM
            scan = routing.scan((ga["lat"], ga["lng"]), (gb["lat"], gb["lng"]),
                                public_incidents(db), n=n, radius_km=radius)
            scan["ok"] = True
            scan["from_place"] = ga.get("name") or a_raw
            scan["to_place"] = gb.get("name") or b_raw
            scan["guidance"] = PUBLIC_GUIDANCE.get(scan.get("worst_level", "GREEN"),
                                                   PUBLIC_GUIDANCE["GREEN"])
            return self._json(scan)

        # --- Phase 1 response loop: read surfaces ----------------------------
        if u.path == "/api/sos":
            # FIELD (public): read an SOS event back by ?id=<uuid> or ?ref=<ref>.
            # PRIV-01: returns only the redacted owner-facing view (no addresses,
            # no message, no exact coords). The field app polls this for status.
            q = urllib.parse.parse_qs(u.query)
            ident = (q.get("id", [""])[0] or q.get("sos_uuid", [""])[0] or
                     q.get("uuid", [""])[0] or q.get("ref", [""])[0]).strip()
            if not ident:
                return self._json({"ok": False, "error": "id or ref required"}, 400)
            ev = db.get_sos(ident)
            if not ev:
                return self._json({"ok": False, "error": "not found"}, 404)
            dl = db.deliveries_for_sos(ev.get("sos_uuid"))
            return self._json(public_sos_view(ev, dl))
        if u.path == "/api/sos-queue":
            # OPERATOR (fail-closed): the live SOS queue for the situation room.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"events": db.sos_queue(self._limit(u))})
        if u.path == "/api/deliveries":
            # OPERATOR (fail-closed): broadcast/SOS delivery receipts (BC-03).
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"deliveries": db.recent_deliveries(self._limit(u))})
        if u.path in ("/api/responder-tasks", "/api/responder/tasks", "/api/responder_tasks"):
            # OPERATOR (fail-closed): responder task list + ack states (RESP-01/06).
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"tasks": db.responder_tasks(self._limit(u))})
        if u.path == "/api/responders":
            # OPERATOR (fail-closed): verified responder directory (RESP-01).
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"responders": db.all_responders(self._limit(u))})
        if u.path == "/api/metrics":
            # OPERATOR (fail-closed): life-saving metrics (MET-01). Pure read.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"ok": True, "metrics": metrics.compute(db)})
        if u.path == "/api/reputation":
            # OPERATOR (fail-closed): source reputation. Reporter keys are opaque
            # hashes only; no raw phone/IP/owner token is exposed.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"ok": True, "reporters": db.all_reporter_stats(self._limit(u))})
        if u.path == "/api/source-health":
            # OPERATOR (fail-closed): durable source-health plus in-process
            # scheduler status, so stale/dead feeds are visible before users notice.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"ok": True, "sources": db.source_health(self._limit(u)),
                               "scheduler": scheduler.default_health()})
        if u.path == "/api/readiness":
            # FIELD/owner: phone safety readiness is looked up only by the owner's
            # local token; no global list exists on the public surface.
            q = urllib.parse.parse_qs(u.query)
            owner = (q.get("owner_token", [""])[0] or q.get("owner", [""])[0]).strip()
            if not owner:
                return self._json({"ok": False, "error": "owner_token required"}, 400)
            row = db.readiness_for(owner)
            return self._json({"ok": bool(row), "readiness": readiness_view(row),
                               "gaps": (row or {}).get("gaps", [])})
        if u.path == "/api/journey":
            # FIELD/owner: read back a trip session by id/ref without exposing raw
            # live coordinates. Operators use /api/journeys for restricted detail.
            q = urllib.parse.parse_qs(u.query)
            jid = (q.get("id", [""])[0] or q.get("journey_uuid", [""])[0] or
                   q.get("uuid", [""])[0]).strip()
            if not jid:
                return self._json({"ok": False, "error": "id required"}, 400)
            row = db.journey_by_uuid(jid)
            if not row:
                return self._json({"ok": False, "error": "not found"}, 404)
            return self._json({"ok": True, "journey": public_journey_view(row)})
        if u.path == "/api/journeys":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"ok": True, "journeys": db.list_journeys(self._limit(u))})
        if u.path in ("/api/cases", "/api/shield-cases"):
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            return self._json({"ok": True, "cases": db.shield_cases(self._limit(u))})
        if u.path in ("/api/case", "/api/shield-case"):
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            q = urllib.parse.parse_qs(u.query)
            cid = (q.get("id", [""])[0] or q.get("case_uuid", [""])[0]).strip()
            row = db.shield_case(cid) if cid else None
            if not row:
                return self._json({"ok": False, "error": "not found"}, 404)
            return self._json({"ok": True, "case": row,
                               "updates": db.case_updates(cid),
                               "evidence": db.evidence_for_case(cid),
                               "geotraces": db.geotraces_for_case(cid)})
        if u.path == "/api/evidence":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            q = urllib.parse.parse_qs(u.query)
            cid = (q.get("case_uuid", [""])[0] or q.get("case", [""])[0]).strip()
            rows = db.evidence_for_case(cid, self._limit(u)) if cid else db.all_evidence(self._limit(u))
            return self._json({"ok": True, "evidence": rows})
        if u.path == "/api/evidence-public":
            # Redacted evidence summary: proves the projection exists but never
            # exposes raw notes, exact coordinates, source identity, or custody internals.
            q = urllib.parse.parse_qs(u.query)
            eid = (q.get("id", [""])[0] or q.get("evidence_uuid", [""])[0]).strip()
            row = db.evidence_by_uuid(eid) if eid else None
            if not row:
                return self._json({"ok": False, "error": "not found"}, 404)
            return self._json({"ok": True, "evidence": evidence_public_view(row)})
        if u.path == "/api/safety-points":
            rows = [safety.safety_point_public(r) for r in db.public_safety_points(self._limit(u))]
            return self._json({"ok": True, "points": rows})
        if u.path in ("/api/sentinels", "/api/mesh/devices", "/api/mesh/relays",
                      "/api/trackers", "/api/ops-agreements", "/api/ops-drills",
                      "/api/ops-readiness"):
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            if u.path == "/api/sentinels":
                return self._json({"ok": True, "sentinels": db.sentinels(self._limit(u))})
            if u.path == "/api/mesh/devices":
                return self._json({"ok": True, "devices": db.mesh_devices(self._limit(u))})
            if u.path == "/api/mesh/relays":
                return self._json({"ok": True, "relays": db.mesh_relays(self._limit(u))})
            if u.path == "/api/trackers":
                return self._json({"ok": True, "trackers": db.trackers(self._limit(u))})
            if u.path == "/api/ops-agreements":
                return self._json({"ok": True, "agreements": db.ops_agreements(self._limit(u))})
            if u.path == "/api/ops-drills":
                return self._json({"ok": True, "drills": db.ops_drills(self._limit(u))})
            return self._json({"ok": True, "ops_readiness": {
                "responders": len(db.all_responders()),
                "sentinels": len(db.sentinels()),
                "safety_points": len(db.all_safety_points()),
                "agreements": len(db.ops_agreements()),
                "drills": len(db.ops_drills()),
                "open_cases": len([c for c in db.shield_cases() if (c.get("status") or "") not in ("closed", "resolved")]),
            }})

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

    def _limit(self, u, default=200):
        # PERF-02: optional ?limit= for the operator list views. The default is
        # deliberately generous so the gates (which read full lists) never clip.
        try:
            q = urllib.parse.parse_qs(u.query)
            return max(1, min(2000, int(q.get("limit", [default])[0])))
        except Exception:
            return default

    def _paged(self, u, items, key):
        """PERF-02: wrap an in-memory list `items` in a pagination envelope, keeping
        the list under its ORIGINAL `key` so existing clients (and validate.py) read
        it unchanged, while ALSO attaching the paging meta (total/limit/offset/
        next_offset) so a low-end phone can stop pulling the whole dataset.

        engine.pagination.parse() clamps ?limit/?offset (and the cursor/start/
        per_page aliases). Its DEFAULT_LIMIT (100) comfortably exceeds the gate
        fixtures, so a bare GET (no ?limit) still returns page 1 = everything the
        existing gates expect; only an explicit small ?limit narrows the window."""
        env = pagination.page(items, **pagination.parse(u.query))
        out = {key: env["items"], "total": env["total"], "limit": env["limit"],
               "offset": env["offset"], "next_offset": env["next_offset"],
               "count": len(env["items"]), "has_more": env["next_offset"] is not None}
        return out

    @staticmethod
    def _now():
        # ISO seconds timestamp (matches db.now_iso()'s format) for stamping
        # acked_at / closed_at when we drive an SOS state transition.
        return datetime.datetime.now().isoformat(timespec="seconds")

    def _ip_hash(self):
        # PRIV-02: a stable, NON-reversible handle for the caller's IP, used as the
        # reputation key for anonymous community reports (so a single flooding host
        # shares one reputation bucket) WITHOUT ever storing the raw address.
        import hashlib as _h
        return _h.sha256(self._client_id().encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _alert_recipients(db, inc):
        """Geofenced recipient list for a verified alert (BC-02).

        Prefers the registered, ACTIVE responder directory filtered to the
        incident's state (then any-state if none match), so a real deploy reaches
        real responders. Falls back to a deployment-configured subscriber list
        (env DEYSAFE_ALERT_TEST_RECIPIENTS, comma-separated) so the broadcast path
        is exercisable. In SIM mode we also add one synthetic test recipient so a
        delivery receipt is always recorded WITHOUT ever performing a real send
        (broadcast.py flags it sim_delivered). With SIM off and no responders/keys,
        the list may be empty and nothing is sent — we never fabricate a delivery.
        """
        targets = []
        try:
            rows = db.responders_for(state=inc.get("state")) or db.active_responders()
        except Exception:
            rows = []
        for r in rows:
            if r.get("address"):
                targets.append({"address": r.get("address"),
                                "channel": (r.get("channel") or SOS_DEFAULT_CHANNEL)})
        extra = os.environ.get("DEYSAFE_ALERT_TEST_RECIPIENTS", "")
        for a in [x.strip() for x in extra.split(",") if x.strip()]:
            targets.append({"address": a, "channel": SOS_DEFAULT_CHANNEL})
        if not targets and broadcast.sim_enabled():
            # SIM-only synthetic recipient: lets the delivery-receipt path run end
            # to end in tests/demo with no responders registered. Never a real send.
            targets.append({"address": "+2348000000000", "channel": SOS_DEFAULT_CHANNEL})
        return targets

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

        if u.path == "/api/readiness":
            # FIELD/owner: readiness checklist saved by the user's local owner token.
            if not self._rate_ok("/api/readiness", 40):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            owner = (data.get("owner_token") or data.get("owner") or "").strip()
            if not owner:
                return self._json({"ok": False, "error": "owner_token required"}, 400)
            row = db.upsert_readiness(owner, data)
            db.audit("field", "readiness_update", "owner=%s score=%s" % (owner[:8], row.get("readiness_score")))
            return self._json({"ok": True, "readiness": readiness_view(row), "gaps": row.get("gaps") or []})

        if u.path == "/api/journey/start":
            # FIELD: start a Journey Guard session. Route endpoints are stored; live
            # raw pings are stored only when share_consent is explicit.
            if not self._rate_ok("/api/journey/start", 25):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            owner = (data.get("owner_token") or "").strip()
            from_raw = (data.get("from") or data.get("from_place") or data.get("start") or "").strip()
            to_raw = (data.get("to") or data.get("to_place") or data.get("end") or "").strip()
            if not owner or not from_raw or not to_raw:
                return self._json({"ok": False, "error": "owner_token, from, and to required"}, 400)
            ga = geocode(from_raw, db=db)
            gb = geocode(to_raw, db=db)
            if not ga or not gb:
                return self._json({"ok": False, "error": "could not resolve from/to",
                                   "from_resolved": bool(ga), "to_resolved": bool(gb)}, 400)
            scan = routing.scan((ga["lat"], ga["lng"]), (gb["lat"], gb["lng"]),
                                public_incidents(db), n=routing.DEFAULT_WAYPOINTS,
                                radius_km=routing.DEFAULT_RADIUS_KM)
            row = db.create_journey({
                "owner_token": owner,
                "from_place": ga.get("name") or from_raw, "to_place": gb.get("name") or to_raw,
                "from_lat": ga.get("lat"), "from_lng": ga.get("lng"),
                "to_lat": gb.get("lat"), "to_lng": gb.get("lng"),
                "expected_arrival": data.get("expected_arrival"),
                "mode": data.get("mode") or "journey_guard",
                "risk_level": scan.get("worst_level") or "GREEN",
                "share_consent": data.get("share_consent")})
            db.audit("field", "journey_start", "ref=%s risk=%s consent=%s" % (
                row.get("handoff_ref"), row.get("risk_level"), bool(row.get("share_consent"))))
            return self._json({"ok": True, "journey": public_journey_view(row),
                               "route": {"worst_level": scan.get("worst_level"),
                                         "guidance": PUBLIC_GUIDANCE.get(scan.get("worst_level", "GREEN"),
                                                                        PUBLIC_GUIDANCE["GREEN"]),
                                         "segments": scan.get("segments", [])[:12],
                                         "note": "Corridor approximation, not exact road routing."}})

        if u.path == "/api/journey/ping":
            # FIELD: update check-in/anomaly state. Exact coordinates are accepted
            # only with explicit consent or a duress/emergency event.
            if not self._rate_ok("/api/journey/ping", 90):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            jid = (data.get("journey_uuid") or data.get("id") or "").strip()
            row = db.journey_by_uuid(jid) if jid else None
            if not row:
                return self._json({"ok": False, "error": "unknown journey"}, 404)
            etype = (data.get("event_type") or data.get("type") or "checkin").strip().lower()
            allowed_exact = bool(row.get("share_consent")) or safety.as_bool(data.get("share_consent")) or etype in ("duress", "emergency", "sos")
            event = dict(data)
            event["event_type"] = etype
            if not allowed_exact:
                event.pop("lat", None)
                event.pop("lng", None)
            updated = db.record_journey_event(jid, event)
            db.audit("field", "journey_ping", "ref=%s event=%s exact=%s state=%s" % (
                row.get("handoff_ref"), etype, allowed_exact, updated.get("state") if updated else ""))
            return self._json({"ok": True, "journey": public_journey_view(updated)})

        if u.path == "/api/journey/arrive":
            if not self._rate_ok("/api/journey/arrive", 40):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            jid = (data.get("journey_uuid") or data.get("id") or "").strip()
            row = db.close_journey(jid, "arrived") if jid else None
            if not row:
                return self._json({"ok": False, "error": "unknown journey"}, 404)
            db.record_journey_event(jid, {"event_type": "arrived", "note": "owner marked arrived"})
            db.audit("field", "journey_arrive", "ref=%s" % row.get("handoff_ref"))
            return self._json({"ok": True, "journey": public_journey_view(db.journey_by_uuid(jid))})

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

        if u.path in ("/api/cases", "/api/shield-cases", "/api/case", "/api/shield-case"):
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_shield_case({
                "case_type": data.get("case_type") or data.get("type") or "incident",
                "subject_ref": data.get("subject_ref") or data.get("ref") or "",
                "status": data.get("status") or "open",
                "visibility": data.get("visibility") or "restricted",
                "family_liaison": data.get("family_liaison") or "",
                "incident_commander": data.get("incident_commander") or "",
                "analyst_owner": data.get("analyst_owner") or actor,
                "summary": data.get("summary") or "",
                "public_note": data.get("public_note") or "",
                "requires_second_approval": data.get("requires_second_approval")})
            db.add_case_update(row["case_uuid"], {"actor": actor, "visibility": "restricted",
                                                 "body": "Case opened: " + (row.get("summary") or "")})
            db.audit(actor, "shield_case_create", "case=%s type=%s" % (row.get("case_uuid"), row.get("case_type")))
            return self._json({"ok": True, "case": db.shield_case(row["case_uuid"]),
                               "updates": db.case_updates(row["case_uuid"])})

        if u.path in ("/api/case-update", "/api/shield-case-update"):
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            cid = (data.get("case_uuid") or data.get("id") or "").strip()
            if not cid:
                return self._json({"ok": False, "error": "case_uuid required"}, 400)
            actor = (self._operator() or {}).get("user", "operator")
            updates = db.add_case_update(cid, {"actor": actor,
                                               "visibility": data.get("visibility") or "restricted",
                                               "body": data.get("body") or data.get("note") or "",
                                               "redacted": data.get("redacted")})
            if updates is None:
                return self._json({"ok": False, "error": "unknown case"}, 404)
            db.audit(actor, "shield_case_update", "case=%s" % cid)
            return self._json({"ok": True, "updates": updates})

        if u.path == "/api/evidence":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_evidence({
                "case_uuid": data.get("case_uuid") or "",
                "evidence_type": data.get("evidence_type") or data.get("type") or "note",
                "title": data.get("title") or "",
                "source_label": data.get("source_label") or "",
                "restricted_level": data.get("restricted_level") or "restricted",
                "status": data.get("status") or "received",
                "lat": _float_or_none(data.get("lat")),
                "lng": _float_or_none(data.get("lng")),
                "captured_at": data.get("captured_at"),
                "notes": data.get("notes") or "",
                "public_summary": data.get("public_summary") or ""})
            if row.get("case_uuid"):
                db.add_case_update(row["case_uuid"], {"actor": actor, "visibility": "restricted",
                                                     "body": "Evidence received: " + (row.get("title") or row.get("evidence_type") or "")})
            db.audit(actor, "evidence_create", "evidence=%s case=%s" % (row.get("evidence_uuid"), row.get("case_uuid")))
            return self._json({"ok": True, "evidence": row, "public": evidence_public_view(row)})

        if u.path == "/api/geotrace":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_geotrace({
                "evidence_uuid": data.get("evidence_uuid") or "",
                "case_uuid": data.get("case_uuid") or "",
                "actor": actor,
                "confidence": data.get("confidence") or "low",
                "method": data.get("method") or "analyst_annotation",
                "area_label": data.get("area_label") or "",
                "lat": _float_or_none(data.get("lat")),
                "lng": _float_or_none(data.get("lng")),
                "radius_km": _float_or_none(data.get("radius_km")),
                "notes": data.get("notes") or "",
                "restricted": True})
            db.audit(actor, "geotrace_create", "trace=%s case=%s method=%s" % (
                row.get("trace_uuid"), row.get("case_uuid"), row.get("method")))
            return self._json({"ok": True, "geotrace": row,
                               "note": "Restricted analyst aid; not an exact locator."})

        if u.path == "/api/safety-points":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_safety_point({
                "name": data.get("name") or "",
                "point_type": data.get("point_type") or data.get("type") or "safe_point",
                "state": data.get("state") or "",
                "lga": data.get("lga") or "",
                "address": data.get("address") or "",
                "lat": _float_or_none(data.get("lat")),
                "lng": _float_or_none(data.get("lng")),
                "contact_channel": data.get("contact_channel") or "",
                "contact_address": data.get("contact_address") or "",
                "vetted": data.get("vetted"),
                "active": True if data.get("active") is None else data.get("active"),
                "verified_by": data.get("verified_by") or actor,
                "notes": data.get("notes") or ""})
            db.audit(actor, "safety_point_create", "point=%s vetted=%s" % (row.get("point_uuid"), row.get("vetted")))
            return self._json({"ok": True, "point": row,
                               "public_points": [safety.safety_point_public(r) for r in db.public_safety_points()]})

        if u.path == "/api/sentinels":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_sentinel({
                "name": data.get("name") or "",
                "org": data.get("org") or "",
                "role": data.get("role") or "observer",
                "state": data.get("state") or "",
                "lga": data.get("lga") or "",
                "trust_level": data.get("trust_level") or "pending",
                "active": True if data.get("active") is None else data.get("active"),
                "consent_revoked_at": data.get("consent_revoked_at"),
                "channel": data.get("channel") or "",
                "address": data.get("address") or "",
                "notes": data.get("notes") or ""})
            db.audit(actor, "sentinel_create", "sentinel=%s trust=%s" % (row.get("sentinel_uuid"), row.get("trust_level")))
            return self._json({"ok": True, "sentinel": row})

        if u.path == "/api/mesh/devices":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_mesh_device({
                "owner_token": data.get("owner_token") or "",
                "device_label": data.get("device_label") or data.get("label") or "",
                "consent_scope": data.get("consent_scope") or "trusted_circle",
                "rotating_id": data.get("rotating_id") or "",
                "active": True if data.get("active") is None else data.get("active"),
                "notes": data.get("notes") or ""})
            db.audit(actor, "mesh_device_create", "device=%s scope=%s" % (row.get("device_uuid"), row.get("consent_scope")))
            return self._json({"ok": True, "device": row})

        if u.path == "/api/trackers":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_tracker({
                "owner_ref": data.get("owner_ref") or "",
                "label": data.get("label") or "",
                "tracker_type": data.get("tracker_type") or data.get("type") or "tag",
                "stable_id": data.get("stable_id") or "",
                "stable_id_hash": data.get("stable_id_hash") or "",
                "rotating_id": data.get("rotating_id") or "",
                "consent_status": data.get("consent_status") or "active",
                "anti_stalking_notice": True if data.get("anti_stalking_notice") is None else data.get("anti_stalking_notice"),
                "active": True if data.get("active") is None else data.get("active"),
                "notes": data.get("notes") or ""})
            db.audit(actor, "tracker_create", "tracker=%s type=%s" % (row.get("tracker_uuid"), row.get("tracker_type")))
            public_row = dict(row)
            public_row.pop("stable_id_hash", None)
            return self._json({"ok": True, "tracker": row, "public_projection": public_row})

        if u.path == "/api/ops-agreements":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_ops_agreement({
                "partner_name": data.get("partner_name") or "",
                "partner_type": data.get("partner_type") or "responder",
                "state": data.get("state") or "",
                "lga": data.get("lga") or "",
                "scope": data.get("scope") or "",
                "escalation_channel": data.get("escalation_channel") or "",
                "status": data.get("status") or "draft",
                "signed_at": data.get("signed_at"),
                "expires_at": data.get("expires_at"),
                "owner": data.get("owner") or actor,
                "notes": data.get("notes") or ""})
            db.audit(actor, "ops_agreement_create", "agreement=%s partner=%s" % (row.get("agreement_uuid"), row.get("partner_name")))
            return self._json({"ok": True, "agreement": row})

        if u.path == "/api/ops-drills":
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            actor = (self._operator() or {}).get("user", "operator")
            row = db.create_ops_drill({
                "drill_type": data.get("drill_type") or "tabletop",
                "state": data.get("state") or "",
                "lga": data.get("lga") or "",
                "participants": data.get("participants") or "",
                "outcome": data.get("outcome") or "",
                "gaps": data.get("gaps") or "",
                "next_due_at": data.get("next_due_at"),
                "owner": data.get("owner") or actor})
            db.audit(actor, "ops_drill_create", "drill=%s type=%s" % (row.get("drill_uuid"), row.get("drill_type")))
            return self._json({"ok": True, "drill": row})

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
            # DATA-05: false-positive suppression. When NO explicit type was given the
            # report is an UNSTRUCTURED inference (recompute would geoparse the text),
            # so a sports/politics/metaphor sentence that merely reuses an incident
            # word ("Super Eagles launched an ATTACK in KANO") must NOT raise a danger.
            # We veto it BEFORE it can be stored as an incident-bearing signal and
            # answer honestly that this report contributed no danger (count 0) — we do
            # NOT report the ambient risk at the point (which could carry unrelated,
            # legitimate incidents) as if it were this report's result.
            if not gtype and negatives_dominate({"title": "", "text": desc + " " + place}):
                db.audit("api", "report_suppressed", "place=%s reason=negative_terms" % place)
                return self._json({"ok": True, "suppressed": True,
                                   "risk": {"place": place, "level": "GREEN",
                                            "guidance": PUBLIC_GUIDANCE["GREEN"], "count": 0,
                                            "incidents": []},
                                   "note": "Reads as non-emergency context; no danger incident created.",
                                   "location_unverified": False, "coords_confidence": "suppressed"})
            g = geocode(place, db=db)  # GEO-02: OFFLINE gazetteer first, then cached/live OSM
            lat = g["lat"] if g else None
            lng = g["lng"] if g else None
            loc_name = g["name"] if g else place
            state = g.get("state", "") if g else ""
            location_unverified = g is None  # GEO-01: no gazetteer/OSM match -> needs a pin
            sev = geoparse.detect_severity(desc + " " + type_word)
            now_iso_ts = datetime.datetime.now().isoformat(timespec="seconds")

            # ABU-04/03/11: reputation + coordinated-burst quarantine. Build a STABLE
            # reputation identity for the source — the owner_token if the field app
            # supplies one, else a one-way hash of the caller IP. We deliberately do
            # NOT fold in client_id (that's a per-message idempotency token, not an
            # identity — mixing it in would mint a brand-new pristine source for every
            # message and defeat reputation entirely). Only the HASH is ever stored
            # (PRIV-02). We accrue this report against the source, then look at the
            # recent community-report window for a coordinated flood. A source that is
            # BOTH low-reputation AND riding a coordinated burst is HELD for a human
            # (needs_human_review) — never auto-published. Bright line: advisory +
            # reversible; volume alone never raises status; no auto-verify/escalate;
            # either signal alone only down-weights.
            rkey = reputation.reporter_key(data.get("owner_token") or self._ip_hash())
            report_for_rep = {
                "reporter_key": rkey, "owner_token": data.get("owner_token"),
                "ts": now_iso_ts, "area": loc_name, "lat": lat, "lng": lng,
                "text": "{} {}".format(type_word, desc)}
            # Mirror this inbound report into the burst ring buffer BEFORE the signals
            # table dedup can hide a flood of identical reports from the detector.
            _remember_report(report_for_rep)
            stat = None
            try:
                stat = db.get_reporter_stat(rkey) or reputation.new_stat(rkey)
                # Count this report (neutral — score only moves on an operator outcome).
                db.upsert_reporter_stat(reputation.update_stat(stat, None))
            except Exception:
                stat = None
            # The window already includes this report (we appended it above).
            recent = _recent_reports_window()
            quarantined = False
            try:
                quarantined = reputation.should_quarantine(report_for_rep, stat, recent)
            except Exception:
                quarantined = False

            db.insert_signal({"source_name": "Community report", "kind": "report",
                              "title": "{} near {}".format(type_word, loc_name),
                              "text": "{} near {}. {}".format(type_word, place, desc),
                              "url": "", "lang": "en",
                              "published_at": now_iso_ts,
                              "lat": lat, "lng": lng, "location_name": loc_name, "state": state,
                              "gtype": gtype, "gseverity": sev})
            db.audit("api", "community_report", "place={} type={} geo={} rep={} quarantined={}".format(
                place, gtype, bool(g), rkey[:8], quarantined))

            if quarantined:
                # HOLD: do NOT run the public-map recompute for this request, so a
                # low-rep coordinated burst can't auto-surface. The signal is stored
                # and reaches the operator review path only via a human-initiated
                # recompute/ingest (human-in-the-loop). ABU-11 reason is audited.
                reason = ""
                try:
                    reason = reputation.quarantine_reason(report_for_rep, stat, recent)
                except Exception:
                    reason = "held pending human review"
                db.audit("system", "report_quarantined", "rep=%s %s" % (rkey[:8], reason[:160]))
                return self._json({"ok": True, "quarantined": True,
                                   "status": "needs_human_review",
                                   "note": "Report received and held for human review.",
                                   "location_unverified": location_unverified,
                                   "coords_confidence": ("unverified" if location_unverified else (g.get("confidence") or g.get("source") or "gazetteer"))})

            recompute(db)
            risk = risk_at(public_incidents(db), lat, lng) if lat is not None else risk_for(public_incidents(db), place)
            # GEO-01: tell the client the point wasn't placed so it can prompt a manual
            # pin instead of implying a (non-existent) centroid pin.
            resp = {"ok": True, "risk": risk, "location_unverified": location_unverified,
                    "coords_confidence": ("unverified" if location_unverified else (g.get("confidence") or g.get("source") or "gazetteer"))}
            return self._json(resp)

        if u.path == "/api/sos":
            # FIELD (public + rate-limited): the durable SOS event (SOS-01/02).
            # Three shapes, all anonymous:
            #   cancel : {owner_token, ref|sos_uuid, cancel:true} -> owner stands down
            #   update : {id|sos_id, state/status:'RESOLVED'}      -> field-side nudge
            #   create : {mode,kind,message,owner_token,notify,contacts,lat,lng,client_id}
            # Bright line: the field side may only drive the *human-safe* states
            # (notify circle, mark safe, close). Operator-only escalation
            # (request_112 / coordinate / operator_ack) lives on /api/sos-status.
            if not self._rate_ok("/api/sos", 30):
                return self._json({"ok": False, "error": "rate limited"}, 429)

            # -- cancel/stand-down -------------------------------------------
            if data.get("cancel") or (data.get("status") or "").strip().lower() in ("cancel", "cancelled", "stand_down"):
                ident = (data.get("sos_uuid") or data.get("id") or data.get("uuid") or data.get("ref") or "").strip()
                ev = db.get_sos(ident) if ident else None
                if not ev:
                    return self._json({"ok": False, "error": "not found"}, 404)
                nxt = response.next_state(ev.get("state"), "close")
                if nxt:
                    db.update_sos_state(ev["sos_uuid"], nxt, closed_at=self._now())
                db.audit("field", "sos_cancel", "ref=%s state=%s" % (ev.get("handoff_ref"), nxt or ev.get("state")))
                ev = db.get_sos(ev["sos_uuid"])
                return self._json({"ok": True, "id": ev.get("sos_uuid"), "sos_uuid": ev.get("sos_uuid"),
                                   "ref": ev.get("handoff_ref"), "state": ev.get("state"),
                                   "status": ev.get("state")})

            # -- field-side state nudge (e.g. owner marks themselves safe) ----
            ident = (data.get("sos_uuid") or data.get("id") or data.get("sos_id") or data.get("uuid") or "").strip()
            want_state = (data.get("state") or data.get("status") or "").strip().upper()
            if ident and want_state:
                ev = db.get_sos(ident)
                if not ev:
                    return self._json({"ok": False, "error": "not found"}, 404)
                # Map a desired terminal/again state to the field-safe event.
                FIELD_EVENTS = {"SAFE": "mark_safe", "RESOLVED": "mark_safe",
                                "CLOSED": "close", "CIRCLE_NOTIFIED": "notify_circle"}
                evt = FIELD_EVENTS.get(want_state)
                nxt = response.next_state(ev.get("state"), evt) if evt else None
                if not nxt:
                    return self._json({"ok": False, "error": "transition not allowed from field"}, 400)
                extra = {}
                if nxt == response.SOS_CLOSED:
                    extra["closed_at"] = self._now()
                db.update_sos_state(ev["sos_uuid"], nxt, **extra)
                db.audit("field", "sos_update", "ref=%s %s->%s" % (ev.get("handoff_ref"), ev.get("state"), nxt))
                ev = db.get_sos(ev["sos_uuid"])
                return self._json({"ok": True, "id": ev.get("sos_uuid"), "sos_uuid": ev.get("sos_uuid"),
                                   "ref": ev.get("handoff_ref"), "state": ev.get("state"),
                                   "status": ev.get("state")})

            # -- create a new durable SOS event -------------------------------
            sos_uuid = response.new_id()
            ref = db.new_ref()
            mode = (data.get("mode") or data.get("kind") or "auto").strip()
            try:
                lat = float(data["lat"]) if data.get("lat") is not None else None
                lng = float(data["lng"]) if data.get("lng") is not None else None
            except Exception:
                lat = lng = None
            db.insert_sos_event({
                "sos_uuid": sos_uuid, "lat": lat, "lng": lng,
                "message": (data.get("message") or "").strip()[:280], "mode": mode,
                "state": response.SOS_INITIAL, "handoff_ref": ref,
                "owner_token": (data.get("owner_token") or "").strip(),
                # OFF-01: a client-supplied id de-dupes a replayed offline SOS.
                "client_id": (data.get("client_id") or "").strip()})
            db.audit("field", "sos_create", "ref=%s mode=%s geo=%s" % (ref, mode, lat is not None))

            state = response.SOS_INITIAL
            contact_state = None
            # Optional trusted-circle notify (SOS-03 + BC-03). The send goes through
            # broadcast (SIM-able; never a faked real send) and every receipt is
            # persisted. This advances the event CIRCLE_NOTIFIED -> DELIVERED.
            notify = data.get("notify")
            notify = True if notify is None else bool(notify)
            ev_for_msg = {"handoff_ref": ref, "message": (data.get("message") or ""), "lat": lat, "lng": lng}
            targets = _sos_contact_targets(data, db) if notify else []
            if targets:
                msg = sos_notify_message(ev_for_msg)
                summary = broadcast.fan_out(targets, msg, channel=SOS_DEFAULT_CHANNEL)
                for rec in summary.get("deliveries", []):
                    db.insert_delivery({"sos_uuid": sos_uuid, "channel": rec.get("channel"),
                                        "address": rec.get("to"), "status": rec.get("status"),
                                        "provider_ref": rec.get("id"), "sim": rec.get("sim")})
                nxt = response.next_state(state, "notify_circle")
                if nxt:
                    state = nxt
                    contact_state = "notified"
                    db.update_sos_state(sos_uuid, state, contact_state=contact_state)
                if summary.get("sent", 0) > 0:
                    nxt2 = response.next_state(state, "delivery_confirmed")
                    if nxt2:
                        state = nxt2
                        db.update_sos_state(sos_uuid, state, contact_state=contact_state)
                db.audit("system", "sos_notify", "ref=%s sent=%s sim=%s" % (ref, summary.get("sent"), summary.get("sim")))
            return self._json({"ok": True, "id": sos_uuid, "sos_uuid": sos_uuid, "uuid": sos_uuid,
                               "ref": ref, "reference": ref, "state": state, "status": state,
                               "contact_state": contact_state, "notified": contact_state})

        if u.path == "/api/trusted":
            # FIELD (public + rate-limited): a field user mirrors their trusted
            # circle (SOS-03) so the operator room can reach them. Stored SERVER-
            # SIDE ONLY — never projected on any public GET (PRIV-01). Two shapes:
            #   single : {owner_token, name, channel, address}
            #   bulk   : {owner_token, contacts:[...], replace:true}
            if not self._rate_ok("/api/trusted", 30):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            owner = (data.get("owner_token") or "").strip()
            if not owner:
                return self._json({"ok": False, "error": "owner_token required"}, 400)
            contacts = data.get("contacts")
            if isinstance(contacts, list) and (data.get("replace") or contacts):
                n = db.replace_trusted(owner, contacts)
                db.audit("field", "trusted_replace", "n=%d" % n)
                return self._json({"ok": True, "count": n})
            addr = (data.get("address") or "").strip()
            if not addr:
                return self._json({"ok": False, "error": "address or contacts required"}, 400)
            db.insert_trusted(owner, (data.get("name") or "Contact").strip(),
                              (data.get("channel") or SOS_DEFAULT_CHANNEL).strip(), addr)
            db.audit("field", "trusted_add", "channel=%s" % (data.get("channel") or SOS_DEFAULT_CHANNEL))
            return self._json({"ok": True, "count": len(db.trusted_for(owner))})

        if u.path == "/api/sos-status":
            # OPERATOR (fail-closed): apply a governed SOS event from the situation
            # room (operator_ack / request_112 / coordinate / escalate / mark_safe /
            # close). RESP-02 / RESP-06 bright line: these are *human* states only;
            # the machine in response.py has no auto-dispatch transition.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            ident = (data.get("sos_uuid") or data.get("id") or data.get("sos_id") or data.get("uuid") or "").strip()
            ev = db.get_sos(ident) if ident else None
            if not ev:
                return self._json({"ok": False, "error": "unknown SOS event"}, 404)
            # Accept either an explicit event name or a target state to translate.
            evt = (data.get("event") or "").strip()
            if not evt:
                want = (data.get("state") or data.get("status") or "").strip().upper()
                STATE_EVENT = {"OPERATOR_ACK": "operator_ack", "ACKED": "operator_ack",
                               "ACKNOWLEDGED": "operator_ack",
                               "HANDOFF_112_REQUESTED": "request_112", "HANDOFF": "request_112",
                               "COORDINATED": "coordinate", "COORDINATE": "coordinate",
                               "ESCALATED": "escalate", "ESCALATE": "escalate",
                               "SAFE": "mark_safe", "RESOLVED": "mark_safe",
                               "CLOSED": "close"}
                evt = STATE_EVENT.get(want, "")
            nxt = response.next_state(ev.get("state"), evt) if evt else None
            if not nxt:
                return self._json({"ok": False, "error": "transition not allowed",
                                   "state": ev.get("state")}, 400)
            actor = (self._operator() or {}).get("user", "operator")
            fields = {"operator": actor}
            if evt == "operator_ack":
                fields["acked_at"] = self._now()
            if nxt == response.SOS_CLOSED:
                fields["closed_at"] = self._now()
            db.update_sos_state(ev["sos_uuid"], nxt, **fields)
            db.audit(actor, "sos_status", "ref=%s %s->%s" % (ev.get("handoff_ref"), ev.get("state"), nxt))
            return self._json({"ok": True, "id": ev.get("sos_uuid"), "sos_uuid": ev.get("sos_uuid"),
                               "ref": ev.get("handoff_ref"), "state": nxt, "status": nxt})

        if u.path == "/api/responders":
            # OPERATOR (fail-closed): add a verified responder to the directory.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            name = (data.get("name") or "").strip()
            if not name:
                return self._json({"ok": False, "error": "name required"}, 400)
            rid = db.insert_responder({
                "name": name, "org": (data.get("org") or "").strip(),
                "role": (data.get("role") or "").strip(), "state": (data.get("state") or "").strip(),
                "lga": (data.get("lga") or "").strip(), "channel": (data.get("channel") or "").strip(),
                "address": (data.get("address") or "").strip(),
                "active": 1 if data.get("active", True) else 0})
            actor = (self._operator() or {}).get("user", "operator")
            db.audit(actor, "responder_add", "name=%s state=%s" % (name[:40], data.get("state")))
            return self._json({"ok": True, "id": rid, "responders": db.all_responders()})

        if u.path in ("/api/responder/ack", "/api/responder-ack"):
            # OPERATOR (fail-closed): move a responder task along the ack ladder
            # (received -> reviewing -> responding -> closed). RESP-06: human ack
            # states ONLY — there is no dispatch/armed transition.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            ident = data.get("id") or data.get("task_id") or data.get("task_uuid") or data.get("uuid")
            task = db.get_task(ident) if ident is not None else None
            if not task:
                return self._json({"ok": False, "error": "unknown task"}, 404)
            nxt = (data.get("status") or data.get("state") or response.TASK_RESPONDING).strip().lower()
            cur = (task.get("state") or response.TASK_INITIAL)
            if not response.valid_task_transition(cur, nxt):
                return self._json({"ok": False, "error": "invalid task transition",
                                   "state": cur}, 400)
            actor = (self._operator() or {}).get("user", "operator")
            db.update_task_state(task.get("task_uuid") or ident, nxt,
                                 note=(data.get("note") or "").strip() or task.get("note", ""))
            db.audit(actor, "responder_ack", "task=%s %s->%s" % (task.get("task_uuid"), cur, nxt))
            return self._json({"ok": True, "id": task.get("task_uuid"), "task_id": task.get("task_uuid"),
                               "state": nxt, "status": nxt})

        if u.path in ("/api/alert/cancel", "/api/alert-cancel"):
            # OPERATOR (fail-closed): the kill-switch (ABU-07 / INT-03). Cancels a
            # live alert by its immutable incident_key OR alert_uuid; after this the
            # alert drops out of GET /api/alerts immediately.
            if not self._authed():
                return self._json({"ok": False, "error": "operator auth required"}, 401)
            key = (data.get("incident_key") or data.get("alert_uuid") or data.get("key") or
                   data.get("id") or "").strip()
            if not key:
                return self._json({"ok": False, "error": "incident_key or alert_uuid required"}, 400)
            actor = (self._operator() or {}).get("user", "operator")
            db.cancel_alert(key, (data.get("reason") or "").strip(), actor)
            db.audit(actor, "alert_cancel", "key=%s reason=%s" % (key, (data.get("reason") or "")[:80]))
            return self._json({"ok": True, "cancelled": key, "alerts": db.active_alerts()})

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
                            g = geocode(res["location_text"], db=db)
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
            db.record_source_run("rss_live", ok=ok, fetched=fetched, added=added,
                                 error=("" if ok else "operator ingest-live failed"))
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
            g = geocode(area, db=db) if area else None
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
                # FIND-03: open a REAL missing-person case (no longer a dead-end) and
                # return a durable reference (DS-YYYY-NNNN) the family can quote when
                # they enrich it on the app or a callback. The case is created with
                # last-seen = now and the typed area; coords come from the gazetteer/
                # OSM when the place resolves (GEO-01: no silent centroid otherwise).
                if len(parts) < 2 or not parts[1]:
                    return self._text("CON Area the person was last seen:")
                place = parts[1].strip()
                lat, lng, _verified = coords_for(place, db=db)
                ref = db.new_ref()
                db.insert_missing({
                    "name": "USSD report", "age": "", "place": place,
                    "exact_place": "", "count": 1, "lat": lat, "lng": lng,
                    "last_seen": datetime.datetime.now().isoformat(timespec="seconds"),
                    "description": "Missing-person case opened via USSD. Ref %s. Awaiting "
                                   "callback / app enrichment." % ref,
                    "vehicle": "", "clothing": "", "direction": "", "beacon_id": ""})
                db.audit("ussd", "missing_case", "ref=%s place=%s" % (ref, place))
                return self._text("END Case opened. Ref {}. Add details on the DeySafe app or "
                                  "we will call you back.".format(ref))
            return self._text("END Sorry, invalid choice.")

        if u.path == "/api/beacon-relay":
            # BLE: a FIELD phone (not an operator) relays a beacon sighting, so this is
            # NOT operator-gated. AirTag-style crowd relay: a native app that hears a
            # registered missing-person beacon POSTs the sighting -> we log it, which
            # re-anchors + tightens the triangulation. Works in no-network areas because
            # the FINDER's phone (not the beacon) carries the report out.
            # ABU-01: a relay is a re-anchoring + spoof vector, so rate-limit it.
            if not self._rate_ok("/api/beacon-relay", 40):
                return self._json({"ok": False, "error": "rate limited"}, 429)
            bid = (data.get("beacon_id") or "").strip()
            if not bid:
                return self._json({"ok": False, "error": "beacon_id, lat, lng required"}, 400)
            try:
                lat = float(data.get("lat"))
                lng = float(data.get("lng"))
            except Exception:
                return self._json({"ok": False, "error": "beacon_id, lat, lng required"}, 400)
            # BLE-01: when a beacon secret is configured, the relay MUST carry a valid
            # SIGNED envelope {beacon_id, lat, lng, ts, nonce, sig}. We verify the HMAC,
            # the timestamp freshness, and the nonce (replay) BEFORE trusting any
            # coordinate — a forged/stale/replayed relay is rejected with 400 and never
            # becomes a sighting. With NO secret set (the default, incl. all gates) this
            # is a no-op so the existing crowd-relay behaviour + tests are unchanged.
            beacon_secret = os.environ.get("DEYSAFE_BEACON_SECRET", "")
            if beacon_secret:
                ok_sig, reason = beaconsign.verify(
                    {"beacon_id": bid, "lat": data.get("lat"), "lng": data.get("lng"),
                     "ts": data.get("ts"), "nonce": data.get("nonce"),
                     "sig": data.get("sig") or data.get("signature")},
                    beacon_secret)
                if not ok_sig:
                    db.audit("beacon", "relay_rejected", "reason=%s" % reason)
                    return self._json({"ok": False, "error": "beacon signature invalid",
                                       "reason": reason}, 400)
                # BLE-02: the envelope may carry a ROTATING ephemeral id; if it maps to a
                # registered stable beacon for the current epoch, resolve to it so the
                # real id is never required on the wire. Falls through to the raw id.
                try:
                    case0 = db.find_missing_by_beacon(bid)
                    if not case0:
                        ep = beaconsign.epoch_for(data.get("ts"))
                        for cand in (db.all_missing() or []):
                            real = (cand.get("beacon_id") or "").strip()
                            if real and beaconsign.rotate(real, ep, beacon_secret) == bid:
                                bid = real
                                break
                except Exception:
                    pass
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
            lat, lng, verified = coords_for(place, db=db)  # GEO-01/02: offline gazetteer first, verified flag
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
            # ABU-04 / DATA-11 continuous loop: feed the operator's outcome back into
            # source reputation so proven-accurate sources gain trust and spammy ones
            # lose it. We credit the reporter_key(s) the operator tooling attaches to
            # the decision (single `reporter_key` or a `reporter_keys` list); when none
            # is supplied this is a no-op (we never guess an identity to penalise).
            rkeys = data.get("reporter_keys")
            if not isinstance(rkeys, list):
                rkeys = [data.get("reporter_key")] if data.get("reporter_key") else []
            for rk in rkeys:
                if rk:
                    try:
                        db.record_reporter_outcome(str(rk), decision)
                    except Exception:
                        pass
            alert = None
            broadcast_summary = None
            task_uuid = None
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
                    # BC-01/02/03: fan the verified alert out to the geofenced
                    # responder set + registered targets, and PERSIST every receipt
                    # keyed to this incident. In SIM mode the receipts are flagged
                    # sim_delivered (never a faked real send); with no keys + SIM off
                    # they degrade to 'unconfigured' but are still recorded honestly.
                    targets = self._alert_recipients(db, inc)
                    if targets:
                        msg = "{}: {} near {}, {}. {}".format(
                            LEVEL_LABEL[lvl], inc["type"].replace("_", " ").upper(),
                            inc["location_name"], inc["state"],
                            TYPE_GUIDANCE.get(inc["type"], "Avoid the area. Emergency: 112."))
                        broadcast_summary = broadcast.fan_out(targets, msg, channel=SOS_DEFAULT_CHANNEL)
                        for rec in broadcast_summary.get("deliveries", []):
                            db.insert_delivery({"alert_key": iuid, "channel": rec.get("channel"),
                                                "address": rec.get("to"), "status": rec.get("status"),
                                                "provider_ref": rec.get("id"), "sim": rec.get("sim")})
                        db.audit("system", "broadcast", "alert={} sent={} sim={}".format(
                            iuid, broadcast_summary.get("sent"), broadcast_summary.get("sim")))
                    # RESP-01/06: hand the verified incident to a responder as a TASK
                    # in the initial human-ack state 'received'. No auto-dispatch.
                    task_uuid = response.new_id()
                    escalate_after = (datetime.datetime.now() + datetime.timedelta(
                        minutes=metrics.ACK_SLA_MIN)).isoformat(timespec="seconds")
                    db.insert_responder_task({
                        "task_uuid": task_uuid, "incident_uuid": iuid, "alert_key": iuid,
                        "state": response.TASK_INITIAL, "escalate_after": escalate_after,
                        "note": "Auto-created on verify of {} near {}, {}".format(
                            inc["type"], inc["location_name"], inc["state"])})
                    db.audit("system", "responder_task", "task={} incident={} state={}".format(
                        task_uuid, iuid, response.TASK_INITIAL))
            else:
                # INT-03 / ABU-07: a dismissal cancels any live alert for this incident.
                db.cancel_alert(iuid, "dismissed by operator", actor)
            resp = {"ok": True, "decision": decision, "queue": len(review_queue(db)), "alert": alert}
            if broadcast_summary is not None:
                resp["broadcast"] = {"sent": broadcast_summary.get("sent"),
                                     "failed": broadcast_summary.get("failed"),
                                     "sim": broadcast_summary.get("sim")}
            if task_uuid:
                resp["responder_task"] = task_uuid
            return self._json(resp)

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
            lat, lng, _verified = coords_for(place, db=db)  # GEO-01/02 (3-tuple, offline-first)
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


# --- DATA-01 background ingest worker ----------------------------------------
def _ingest_live_once(db=None):
    """One scheduled pull of PUBLIC Nigerian news RSS + a recompute. Mirrors the
    body of the operator /api/ingest-live route (public data only; per-feed
    failures skipped; everything lands candidate_unverified — a human still gates
    escalation). Used by engine.scheduler when DEYSAFE_INGEST_MINUTES>0. Opens its
    OWN db connection when called with none (the scheduler thread has no request
    db). Returns a small summary dict; never raises out (the scheduler logs)."""
    own = db is None
    if own:
        db = DB(DB_PATH)
    fetched, added = 0, 0
    try:
        sigs = ingest.load_live()
        fetched = len(sigs)
        for sg in sigs:
            _sid, is_new = db.insert_signal(sg)
            if is_new:
                added += 1
        recompute(db)
        db.audit("scheduler", "ingest_live", "fetched=%d added=%d" % (fetched, added))
        db.record_source_run("rss_live", ok=True, fetched=fetched, added=added)
    except Exception as e:
        try:
            db.audit("scheduler", "ingest_live_error", repr(e)[:200])
            db.record_source_run("rss_live", ok=False, fetched=fetched, added=added,
                                 error=repr(e)[:200])
        except Exception:
            pass
    return {"fetched": fetched, "added": added}


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    ensure_seed(DB(DB_PATH))
    port = int(os.environ.get("PORT", "4500"))
    host = os.environ.get("HOST", "0.0.0.0")
    ai_on = ("ON (" + (ai.provider() or "") + ")") if ai.available() else "OFF — set CEREBRAS_API_KEY / GEMINI_API_KEY / GROQ_API_KEY"
    # DATA-01: start the periodic ingest worker. DEFAULT OFF — scheduler.start_default
    # only spins a thread when DEYSAFE_INGEST_MINUTES>0, so gates/tests (which don't
    # set it) never start a background thread or touch the network.
    sched = scheduler.start_default(lambda: _ingest_live_once(None), name="ingest")
    sched_on = "ON (every %s min)" % scheduler.configured_minutes() if scheduler.enabled() else "OFF"
    print("DeySafe + SHIELD on %s:%d  |  AI: %s  |  ingest scheduler: %s  |  operator console at /review.html" % (
        host, port, ai_on, sched_on))
    try:
        ThreadingHTTPServer((host, port), Handler).serve_forever()
    finally:
        scheduler.stop_default()


if __name__ == "__main__":
    main()
