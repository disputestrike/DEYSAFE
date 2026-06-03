"""SQLite storage for DeySafe / SHIELD (prototype). Standard library only.

Production target is Postgres/PostGIS (Supabase). This local store keeps the
build runnable with zero external accounts.
"""
import sqlite3
import hashlib
import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_name TEXT, kind TEXT, title TEXT, text TEXT, url TEXT, lang TEXT,
  published_at TEXT, ingested_at TEXT, raw_hash TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT, location_name TEXT, state TEXT, lat REAL, lng REAL,
  window_start TEXT, window_end TEXT,
  source_count INTEGER, source_diversity INTEGER, severity INTEGER,
  confidence INTEGER, status TEXT, summary TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS incident_signals ( incident_id INTEGER, signal_id INTEGER );
CREATE TABLE IF NOT EXISTS decisions (
  key TEXT PRIMARY KEY, decision TEXT, note TEXT, actor TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_key TEXT, level INTEGER, level_label TEXT, title TEXT, guidance TEXT,
  lat REAL, lng REAL, radius_km INTEGER, reach INTEGER, status TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS missing (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT, age TEXT, place TEXT, exact_place TEXT, lat REAL, lng REAL, count INTEGER DEFAULT 1,
  last_seen TEXT, description TEXT, vehicle TEXT, clothing TEXT, direction TEXT,
  status TEXT, found_at TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS sightings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER, place TEXT, lat REAL, lng REAL, seen_at TEXT, note TEXT, source TEXT, created_at TEXT
);
"""


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert_signal(self, sig):
        raw = "{}|{}|{}".format(sig.get("source_name", ""), sig.get("title", ""), sig.get("text", "")).encode("utf-8")
        h = hashlib.sha256(raw).hexdigest()
        row = self.conn.execute("SELECT id FROM signals WHERE raw_hash=?", (h,)).fetchone()
        if row:
            return row["id"], False
        cur = self.conn.execute(
            "INSERT INTO signals (source_name, kind, title, text, url, lang, published_at, ingested_at, raw_hash)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (sig.get("source_name"), sig.get("kind"), sig.get("title"), sig.get("text"),
             sig.get("url"), sig.get("lang"), sig.get("published_at"), now_iso(), h))
        self.conn.commit()
        return cur.lastrowid, True

    def replace_incidents(self, incidents):
        self.conn.execute("DELETE FROM incidents")
        self.conn.execute("DELETE FROM incident_signals")
        for inc in incidents:
            cur = self.conn.execute(
                "INSERT INTO incidents (type, location_name, state, lat, lng, window_start, window_end,"
                " source_count, source_diversity, severity, confidence, status, summary, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc["type"], inc["location_name"], inc["state"], inc["lat"], inc["lng"],
                 inc["window_start"], inc["window_end"], inc["source_count"], inc["source_diversity"],
                 inc["severity"], inc["confidence"], inc["status"], inc["summary"], now_iso()))
            iid = cur.lastrowid
            for sid in inc["signal_ids"]:
                self.conn.execute("INSERT INTO incident_signals (incident_id, signal_id) VALUES (?,?)", (iid, sid))
        self.conn.commit()

    def set_decision(self, key, decision, note, actor):
        self.conn.execute(
            "INSERT INTO decisions (key, decision, note, actor, ts) VALUES (?,?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET decision=excluded.decision, note=excluded.note,"
            " actor=excluded.actor, ts=excluded.ts",
            (key, decision, note, actor, now_iso()))
        self.conn.commit()

    def decisions(self):
        return {r["key"]: dict(r) for r in self.conn.execute("SELECT * FROM decisions")}

    def insert_missing(self, m):
        cur = self.conn.execute(
            "INSERT INTO missing (name, age, place, exact_place, lat, lng, count, last_seen, description, vehicle, clothing, direction, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (m["name"], m.get("age", ""), m["place"], m.get("exact_place", ""), m["lat"], m["lng"],
             int(m.get("count", 1) or 1), m["last_seen"], m.get("description", ""),
             m.get("vehicle", ""), m.get("clothing", ""), m.get("direction", ""), "active", now_iso()))
        self.conn.commit()
        return cur.lastrowid

    def all_missing(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM missing WHERE status IN ('active','located','recovered') ORDER BY id DESC")]

    def insert_sighting(self, s):
        self.conn.execute(
            "INSERT INTO sightings (case_id, place, lat, lng, seen_at, note, source, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (s["case_id"], s["place"], s["lat"], s["lng"], s["seen_at"],
             s.get("note", ""), s.get("source", "community"), now_iso()))
        self.conn.commit()

    def sightings_for(self, case_id):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM sightings WHERE case_id=? ORDER BY seen_at", (case_id,))]

    def set_missing_status(self, case_id, status):
        self.conn.execute("UPDATE missing SET status=?, found_at=? WHERE id=?",
                          (status, now_iso() if status in ("located", "recovered") else None, case_id))
        self.conn.commit()

    def audit(self, actor, action, detail):
        self.conn.execute("INSERT INTO audit (ts, actor, action, detail) VALUES (?,?,?,?)",
                          (now_iso(), actor, action, detail))
        self.conn.commit()

    def all_incidents(self):
        return [dict(r) for r in self.conn.execute("SELECT * FROM incidents ORDER BY confidence DESC")]

    def insert_alert(self, a):
        self.conn.execute(
            "INSERT INTO alerts (incident_key, level, level_label, title, guidance, lat, lng, radius_km, reach, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (a.get("incident_key"), a["level"], a["level_label"], a["title"], a["guidance"],
             a["lat"], a["lng"], a["radius_km"], a.get("reach", 0), "active", now_iso()))
        self.conn.commit()

    def active_alerts(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM alerts WHERE status='active' ORDER BY level DESC, id DESC")]

    def resolve_alert(self, key):
        self.conn.execute("UPDATE alerts SET status='resolved' WHERE incident_key=? AND status='active'", (key,))
        self.conn.commit()
