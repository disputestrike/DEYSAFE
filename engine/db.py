"""Storage for DeySafe / SHIELD.

Dual-mode:
  - Default: SQLite file (zero external accounts; great for local + a Railway volume).
  - Production: PostgreSQL when DATABASE_URL is set (persistent, concurrent, the
    Railway/Supabase target; PostGIS-ready when we push geo queries into SQL).

The public method surface is identical for both backends, so the rest of the app
(api.py) never needs to know which database is in use.
"""
import os
import sys
import sqlite3
import hashlib
import datetime

DATABASE_URL = os.environ.get("DATABASE_URL")

# SQLite schema — kept byte-identical to the original so existing local DBs are
# untouched (the 6 structured-signal columns are added by _migrate as before).
SCHEMA_SQLITE = """
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

# PostgreSQL schema — SERIAL ids, DOUBLE PRECISION coords; the structured-signal
# columns are inlined here (fresh DB on first deploy).
SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS signals (
  id SERIAL PRIMARY KEY,
  source_name TEXT, kind TEXT, title TEXT, text TEXT, url TEXT, lang TEXT,
  published_at TEXT, ingested_at TEXT, raw_hash TEXT UNIQUE,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION, location_name TEXT, state TEXT,
  gtype TEXT, gseverity INTEGER
);
CREATE TABLE IF NOT EXISTS incidents (
  id SERIAL PRIMARY KEY,
  type TEXT, location_name TEXT, state TEXT, lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  window_start TEXT, window_end TEXT,
  source_count INTEGER, source_diversity INTEGER, severity INTEGER,
  confidence INTEGER, status TEXT, summary TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS incident_signals ( incident_id INTEGER, signal_id INTEGER );
CREATE TABLE IF NOT EXISTS decisions (
  key TEXT PRIMARY KEY, decision TEXT, note TEXT, actor TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id SERIAL PRIMARY KEY, ts TEXT, actor TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id SERIAL PRIMARY KEY,
  incident_key TEXT, level INTEGER, level_label TEXT, title TEXT, guidance TEXT,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION, radius_km INTEGER, reach INTEGER,
  status TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS missing (
  id SERIAL PRIMARY KEY,
  name TEXT, age TEXT, place TEXT, exact_place TEXT, lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  count INTEGER DEFAULT 1,
  last_seen TEXT, description TEXT, vehicle TEXT, clothing TEXT, direction TEXT,
  status TEXT, found_at TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS sightings (
  id SERIAL PRIMARY KEY,
  case_id INTEGER, place TEXT, lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  seen_at TEXT, note TEXT, source TEXT, created_at TEXT
);
"""


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


class DB:
    def __init__(self, path):
        self.pg = False
        if DATABASE_URL:
            try:
                import psycopg2
                import psycopg2.extras
                self._extras = psycopg2.extras
                self.conn = psycopg2.connect(DATABASE_URL, connect_timeout=6)
                self.conn.autocommit = True
                cur = self.conn.cursor()
                cur.execute(SCHEMA_PG)
                cur.close()
                self.pg = True
            except Exception as e:
                # Never crash the app over a bad/unreachable DATABASE_URL — fall back
                # to SQLite and warn loudly so the misconfig is visible in the logs.
                sys.stderr.write("[db] DATABASE_URL is set but Postgres connect failed "
                                 "(%s) -- falling back to SQLite so the app stays up.\n" % e)
                self.pg = False
        if not self.pg:
            self.conn = sqlite3.connect(path)
            self.conn.row_factory = sqlite3.Row
            self.conn.executescript(SCHEMA_SQLITE)
            self.conn.commit()
        self._migrate()

    # --- backend-neutral helpers -------------------------------------------------
    def _sql(self, s):
        # SQLite uses ? placeholders; psycopg2 uses %s. Our SQL has no literal % or ?.
        return s.replace("?", "%s") if self.pg else s

    def _all(self, sql, params=()):
        sql = self._sql(sql)
        if self.pg:
            cur = self.conn.cursor(cursor_factory=self._extras.RealDictCursor)
            cur.execute(sql, params)
            rows = cur.fetchall()
            cur.close()
            return [dict(r) for r in rows]
        return [dict(r) for r in self.conn.execute(sql, params)]

    def _one(self, sql, params=()):
        sql = self._sql(sql)
        if self.pg:
            cur = self.conn.cursor(cursor_factory=self._extras.RealDictCursor)
            cur.execute(sql, params)
            row = cur.fetchone()
            cur.close()
            return dict(row) if row else None
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def _run(self, sql, params=()):
        sql = self._sql(sql)
        if self.pg:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            cur.close()
        else:
            self.conn.execute(sql, params)
            self.conn.commit()

    def _insert(self, sql, params):
        sql = self._sql(sql)
        if self.pg:
            cur = self.conn.cursor()
            cur.execute(sql + " RETURNING id", params)
            rid = cur.fetchone()[0]
            cur.close()
            return rid
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        return cur.lastrowid

    def _migrate(self):
        # Structured-report columns on `signals` (gazetteer-free geocoded pins).
        # PG schema already has them; SQLite upgrades legacy DBs here.
        cols = (("lat", "REAL", "DOUBLE PRECISION"), ("lng", "REAL", "DOUBLE PRECISION"),
                ("location_name", "TEXT", "TEXT"), ("state", "TEXT", "TEXT"),
                ("gtype", "TEXT", "TEXT"), ("gseverity", "INTEGER", "INTEGER"))
        for col, sdecl, pdecl in cols:
            try:
                if self.pg:
                    cur = self.conn.cursor()
                    cur.execute("ALTER TABLE signals ADD COLUMN IF NOT EXISTS %s %s" % (col, pdecl))
                    cur.close()
                else:
                    self.conn.execute("ALTER TABLE signals ADD COLUMN " + col + " " + sdecl)
            except Exception:
                pass  # column already exists
        if not self.pg:
            self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    # --- data access (identical surface for both backends) -----------------------
    def insert_signal(self, sig):
        raw = "{}|{}|{}".format(sig.get("source_name", ""), sig.get("title", ""), sig.get("text", "")).encode("utf-8")
        h = hashlib.sha256(raw).hexdigest()
        row = self._one("SELECT id FROM signals WHERE raw_hash=?", (h,))
        if row:
            return row["id"], False
        sid = self._insert(
            "INSERT INTO signals (source_name, kind, title, text, url, lang, published_at, ingested_at, raw_hash,"
            " lat, lng, location_name, state, gtype, gseverity)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sig.get("source_name"), sig.get("kind"), sig.get("title"), sig.get("text"),
             sig.get("url"), sig.get("lang"), sig.get("published_at"), now_iso(), h,
             sig.get("lat"), sig.get("lng"), sig.get("location_name"), sig.get("state"),
             sig.get("gtype"), sig.get("gseverity")))
        return sid, True

    def update_signal_geo(self, sid, geo):
        self._run(
            "UPDATE signals SET lat=?, lng=?, location_name=?, state=?, gtype=?, gseverity=? WHERE id=?",
            (geo.get("lat"), geo.get("lng"), geo.get("location_name"), geo.get("state"),
             geo.get("gtype"), geo.get("gseverity"), sid))

    def replace_incidents(self, incidents):
        self._run("DELETE FROM incidents")
        self._run("DELETE FROM incident_signals")
        for inc in incidents:
            iid = self._insert(
                "INSERT INTO incidents (type, location_name, state, lat, lng, window_start, window_end,"
                " source_count, source_diversity, severity, confidence, status, summary, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc["type"], inc["location_name"], inc["state"], inc["lat"], inc["lng"],
                 inc["window_start"], inc["window_end"], inc["source_count"], inc["source_diversity"],
                 inc["severity"], inc["confidence"], inc["status"], inc["summary"], now_iso()))
            for sid in inc["signal_ids"]:
                self._run("INSERT INTO incident_signals (incident_id, signal_id) VALUES (?,?)", (iid, sid))

    def set_decision(self, key, decision, note, actor):
        self._run(
            "INSERT INTO decisions (key, decision, note, actor, ts) VALUES (?,?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET decision=excluded.decision, note=excluded.note,"
            " actor=excluded.actor, ts=excluded.ts",
            (key, decision, note, actor, now_iso()))

    def decisions(self):
        return {r["key"]: r for r in self._all("SELECT * FROM decisions")}

    def insert_missing(self, m):
        return self._insert(
            "INSERT INTO missing (name, age, place, exact_place, lat, lng, count, last_seen, description, vehicle, clothing, direction, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (m["name"], m.get("age", ""), m["place"], m.get("exact_place", ""), m["lat"], m["lng"],
             int(m.get("count", 1) or 1), m["last_seen"], m.get("description", ""),
             m.get("vehicle", ""), m.get("clothing", ""), m.get("direction", ""), "active", now_iso()))

    def all_missing(self):
        return self._all(
            "SELECT * FROM missing WHERE status IN ('active','located','recovered') ORDER BY id DESC")

    def insert_sighting(self, s):
        self._run(
            "INSERT INTO sightings (case_id, place, lat, lng, seen_at, note, source, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (s["case_id"], s["place"], s["lat"], s["lng"], s["seen_at"],
             s.get("note", ""), s.get("source", "community"), now_iso()))

    def sightings_for(self, case_id):
        return self._all("SELECT * FROM sightings WHERE case_id=? ORDER BY seen_at", (case_id,))

    def set_missing_status(self, case_id, status):
        self._run("UPDATE missing SET status=?, found_at=? WHERE id=?",
                  (status, now_iso() if status in ("located", "recovered") else None, case_id))

    def audit(self, actor, action, detail):
        self._run("INSERT INTO audit (ts, actor, action, detail) VALUES (?,?,?,?)",
                  (now_iso(), actor, action, detail))

    def all_incidents(self):
        return self._all("SELECT * FROM incidents ORDER BY confidence DESC")

    def all_signals(self):
        return self._all("SELECT * FROM signals")

    def count_signals(self):
        r = self._one("SELECT COUNT(*) AS c FROM signals")
        return (r["c"] if r else 0)

    def insert_alert(self, a):
        self._run(
            "INSERT INTO alerts (incident_key, level, level_label, title, guidance, lat, lng, radius_km, reach, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (a.get("incident_key"), a["level"], a["level_label"], a["title"], a["guidance"],
             a["lat"], a["lng"], a["radius_km"], a.get("reach", 0), "active", now_iso()))

    def active_alerts(self):
        return self._all("SELECT * FROM alerts WHERE status='active' ORDER BY level DESC, id DESC")

    def resolve_alert(self, key):
        self._run("UPDATE alerts SET status='resolved' WHERE incident_key=? AND status='active'", (key,))
