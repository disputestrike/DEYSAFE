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
    n = (name or "").strip().lower()
    for p in PLACES:
        if p["name"].lower() == n:
            return p["lat"], p["lng"]
    return 9.2, 8.2  # Nigeria centroid fallback


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
    """Best coordinates for a TYPED place: gazetteer -> free OSM -> Nigeria centroid.
    Lets FindMe cases & sightings pin anywhere a user types, not just the 48 seed towns."""
    g = geocode(place)
    if g:
        return g["lat"], g["lng"]
    return place_coords(place)


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


def ensure_seed(db):
    # Seed sample data only on first boot (empty DB) so deployed data persists across restarts.
    empty = db.count_signals() == 0
    if empty:
        for s in ingest.gather(use_live=False, use_sample=True):
            db.insert_signal(s)
    recompute(db)
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
        # one seeded active alert so the public banner demonstrates the broadcast layer
        klat, klng = place_coords("Kaduna")
        db.insert_alert({"incident_key": "kidnapping|Kaduna|Kaduna", "level": 3, "level_label": "DANGER",
                         "title": "KIDNAPPING — Kaduna, Kaduna — armed men on the Kaduna-Abuja road",
                         "guidance": TYPE_GUIDANCE["kidnapping"], "lat": klat, "lng": klng,
                         "radius_km": 50, "reach": 6000})
    # Demo: ensure ONE human-VERIFIED incident exists so the public actually sees a
    # RED on the GREEN->YELLOW->ORANGE->RED ladder. Idempotent; never overrides an
    # operator's later call (only seeds while that incident is still undecided).
    rk = "kidnapping|Kaduna|Kaduna"
    if rk not in db.decisions() and any(ikey(i) == rk for i in with_decisions(db)):
        db.set_decision(rk, "verified", "[seed] demo verified threat (synthetic)", "seed")


def with_decisions(db):
    dec = db.decisions()
    incs = db.all_incidents()
    for i in incs:
        d = dec.get(ikey(i))
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


def missing_with_radius(db):
    out = []
    for m in db.all_missing():
        m = dict(m)
        sights = db.sightings_for(m["id"])
        m["sightings"] = sights
        m["sighting_count"] = len(sights)
        # Anchor the search on the MOST RECENT credible point: latest sighting if any, else last-seen.
        if sights:
            last = sights[-1]
            alat, alng, atime, m["anchor"] = last["lat"], last["lng"], last["seen_at"], "sighting"
        else:
            alat, alng, atime, m["anchor"] = m["lat"], m["lng"], m["last_seen"], "last_seen"
        try:
            hrs = max(0.25, (datetime.datetime.now() - datetime.datetime.fromisoformat(atime)).total_seconds() / 3600)
        except Exception:
            hrs = 1.0
        m["search_lat"], m["search_lng"] = alat, alng
        m["hours"] = round(hrs, 1)
        m["radius_km"] = int(min(hrs * 50, 250))  # ~50 km/h spread from the freshest point, capped
        out.append(m)
    return out


def risk_for(incidents, place):
    pl = (place or "").strip().lower()
    rel = [i for i in incidents if pl and (pl in (i["location_name"] or "").lower() or pl in (i["state"] or "").lower())]
    top = max((RISK.get(i["status"], 1) for i in rel), default=0)
    level = public_level(top)
    return {"place": place, "level": level, "guidance": PUBLIC_GUIDANCE[level], "count": len(rel),
            "incidents": sorted(rel, key=lambda i: -i["confidence"])[:6]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        db = DB(DB_PATH)
        if u.path == "/api/health":
            return self._json({"ok": True, "incidents": len(public_incidents(db)),
                               "queue": len(review_queue(db)), "missing": len(db.all_missing())})
        if u.path == "/api/incidents":
            return self._json({"incidents": public_incidents(db)})
        if u.path == "/api/queue":
            return self._json({"queue": review_queue(db)})
        if u.path == "/api/missing":
            return self._json({"missing": missing_with_radius(db)})
        if u.path == "/api/alerts":
            return self._json({"alerts": db.active_alerts()})
        if u.path == "/api/channel":
            return self._json({"posts": db.recent_channel()})
        if u.path == "/api/places":
            coords = {p["name"]: [p["lat"], p["lng"]] for p in PLACES}
            return self._json({"places": PLACE_NAMES, "types": TYPES, "coords": coords})
        if u.path == "/api/ai-status":
            return self._json({"ai": ai.available(), "provider": ai.provider(), "keys": ai.key_count()})
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
        return self._static(u.path)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        ln = int(self.headers.get("Content-Length", "0") or 0)
        try:
            data = json.loads(self.rfile.read(ln).decode("utf-8")) if ln else {}
        except Exception:
            data = {}
        db = DB(DB_PATH)

        if u.path == "/api/report":
            typ, place, desc = (data.get("type") or "").strip(), (data.get("place") or "").strip(), (data.get("description") or "").strip()
            if not place or not desc:
                return self._json({"ok": False, "error": "place and description required"}, 400)
            type_word = typ.replace("_", " ") if typ else "incident"
            g = geocode(place)  # gazetteer -> free OSM; lets a typed report of ANY town hit the map
            lat = g["lat"] if g else None
            lng = g["lng"] if g else None
            loc_name = g["name"] if g else place
            state = g.get("state", "") if g else ""
            sev = geoparse.detect_severity(desc + " " + type_word)
            db.insert_signal({"source_name": "Community report", "kind": "report",
                              "title": "{} near {}".format(type_word, loc_name),
                              "text": "{} near {}. {}".format(type_word, place, desc),
                              "url": "", "lang": "en",
                              "published_at": datetime.datetime.now().isoformat(timespec="seconds"),
                              "lat": lat, "lng": lng, "location_name": loc_name, "state": state,
                              "gtype": (typ or None), "gseverity": sev})
            db.audit("api", "community_report", "place={} type={} geo={}".format(place, typ, bool(g)))
            recompute(db)
            risk = risk_at(public_incidents(db), lat, lng) if lat is not None else risk_for(public_incidents(db), place)
            return self._json({"ok": True, "risk": risk})

        if u.path == "/api/ingest-live":
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
                    fields = {"type": res.get("incident_type") or "", "place": res.get("location_text") or "",
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

        if u.path == "/api/missing":
            name, place = (data.get("name") or "").strip(), (data.get("place") or "").strip()
            if not name or not place:
                return self._json({"ok": False, "error": "name and place required"}, 400)
            lat, lng = coords_for(place)
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
                               "direction": (data.get("direction") or "").strip()})
            db.audit("api", "missing_report", "place={} count={}".format(place, data.get("count") or 1))
            return self._json({"ok": True, "missing": missing_with_radius(db)})

        if u.path == "/api/verify":
            decision = (data.get("decision") or "").strip()
            if decision not in ("verified", "dismissed"):
                return self._json({"ok": False, "error": "decision must be verified|dismissed"}, 400)
            key = "{}|{}|{}".format((data.get("type") or "").strip(),
                                    (data.get("location_name") or "").strip(),
                                    (data.get("state") or "").strip())
            db.set_decision(key, decision, (data.get("note") or "").strip(), "operator")
            db.audit("operator", "decision", "{} -> {}".format(key, decision))
            alert = None
            if decision == "verified":
                inc = next((i for i in with_decisions(db) if ikey(i) == key), None)
                if inc:
                    lvl = alert_level(inc["confidence"], inc["severity"])
                    rad = TYPE_RADIUS.get(inc["type"], 30)
                    alert = {"incident_key": key, "level": lvl, "level_label": LEVEL_LABEL[lvl],
                             "title": "{} — {}, {} — verified".format(inc["type"].replace("_", " ").upper(), inc["location_name"], inc["state"]),
                             "guidance": TYPE_GUIDANCE.get(inc["type"], "Avoid the area and stay alert. Emergency: 112."),
                             "lat": inc["lat"], "lng": inc["lng"], "radius_km": rad, "reach": rad * 120}
                    db.insert_alert(alert)
                    db.audit("system", "alert_fired", "L{} {} reach~{}".format(lvl, key, rad * 120))
            else:
                db.resolve_alert(key)
            return self._json({"ok": True, "decision": decision, "queue": len(review_queue(db)), "alert": alert})

        if u.path == "/api/sighting":
            try:
                cid = int(data.get("case_id"))
            except Exception:
                return self._json({"ok": False, "error": "case_id required"}, 400)
            place = (data.get("place") or "").strip()
            if not place:
                return self._json({"ok": False, "error": "place required"}, 400)
            lat, lng = coords_for(place)
            try:
                hrs = float(data.get("hours_ago") or 0.5)
            except Exception:
                hrs = 0.5
            db.insert_sighting({"case_id": cid, "place": place, "lat": lat, "lng": lng,
                                "seen_at": (datetime.datetime.now() - datetime.timedelta(hours=hrs)).isoformat(timespec="seconds"),
                                "note": (data.get("note") or "").strip(), "source": "community"})
            db.audit("api", "sighting", "case={} place={}".format(cid, place))
            return self._json({"ok": True, "missing": missing_with_radius(db)})

        if u.path == "/api/case-status":
            try:
                cid = int(data.get("case_id"))
            except Exception:
                return self._json({"ok": False, "error": "case_id required"}, 400)
            status = (data.get("status") or "").strip()
            if status not in ("active", "located", "recovered", "resolved"):
                return self._json({"ok": False, "error": "bad status"}, 400)
            db.set_missing_status(cid, status)
            db.audit("operator", "case_status", "case={} -> {}".format(cid, status))
            return self._json({"ok": True, "missing": missing_with_radius(db)})

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
