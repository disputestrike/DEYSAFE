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

try:
    import security  # uuid / audit-hash helpers (stdlib-only sibling module)
except Exception:  # pragma: no cover - keep db importable even if security.py absent
    security = None

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
  incident_uuid TEXT, event_version INTEGER,
  type TEXT, location_name TEXT, state TEXT, lat REAL, lng REAL,
  window_start TEXT, window_end TEXT,
  source_count INTEGER, source_diversity INTEGER, severity INTEGER,
  confidence INTEGER, status TEXT, summary TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS incident_signals ( incident_id INTEGER, signal_id INTEGER );
-- INT-01 / PRIV-05: decisions are keyed to an immutable incident_uuid (so a NEW
-- incident never inherits an OLD decision) and append-only with a tamper-evident
-- hash chain. The latest row per incident_uuid is the live decision.
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_uuid TEXT, event_version INTEGER, key TEXT,
  decision TEXT, note TEXT, actor TEXT, ts TEXT,
  prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT
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
CREATE TABLE IF NOT EXISTS channel (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  area TEXT, text TEXT, lat REAL, lng REAL, source TEXT, created_at TEXT
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
  incident_uuid TEXT, event_version INTEGER,
  type TEXT, location_name TEXT, state TEXT, lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  window_start TEXT, window_end TEXT,
  source_count INTEGER, source_diversity INTEGER, severity INTEGER,
  confidence INTEGER, status TEXT, summary TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS incident_signals ( incident_id INTEGER, signal_id INTEGER );
CREATE TABLE IF NOT EXISTS decisions (
  id SERIAL PRIMARY KEY,
  incident_uuid TEXT, event_version INTEGER, key TEXT,
  decision TEXT, note TEXT, actor TEXT, ts TEXT,
  prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id SERIAL PRIMARY KEY, ts TEXT, actor TEXT, action TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT
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
CREATE TABLE IF NOT EXISTS channel (
  id SERIAL PRIMARY KEY,
  area TEXT, text TEXT, lat DOUBLE PRECISION, lng DOUBLE PRECISION, source TEXT, created_at TEXT
);
"""


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _fallback_uuid():
    import uuid as _uuid
    return _uuid.uuid4().hex


def _fallback_hash(prev_hash, row_dict):
    import json as _json
    canon = _json.dumps(row_dict, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(((prev_hash or "") + canon).encode("utf-8")).hexdigest()


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
        try:  # beacon id on missing cases (Bluetooth crowd-relay / AirTag model)
            if self.pg:
                cur = self.conn.cursor(); cur.execute("ALTER TABLE missing ADD COLUMN IF NOT EXISTS beacon_id TEXT"); cur.close()
            else:
                self.conn.execute("ALTER TABLE missing ADD COLUMN beacon_id TEXT")
        except Exception:
            pass
        # INT-01: immutable incident identity on legacy `incidents`.
        for col, sdecl, pdecl in (("incident_uuid", "TEXT", "TEXT"), ("event_version", "INTEGER", "INTEGER")):
            try:
                if self.pg:
                    cur = self.conn.cursor()
                    cur.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS %s %s" % (col, pdecl))
                    cur.close()
                else:
                    self.conn.execute("ALTER TABLE incidents ADD COLUMN " + col + " " + sdecl)
            except Exception:
                pass
        # PRIV-05: tamper-evident hash columns on `audit`.
        for col in ("prev_hash", "hash"):
            try:
                if self.pg:
                    cur = self.conn.cursor()
                    cur.execute("ALTER TABLE audit ADD COLUMN IF NOT EXISTS %s TEXT" % col)
                    cur.close()
                else:
                    self.conn.execute("ALTER TABLE audit ADD COLUMN " + col + " TEXT")
            except Exception:
                pass
        # INT-01 / PRIV-05: legacy `decisions` was keyed by `key TEXT PRIMARY KEY`
        # (single upsertable row). Rebuild it as the append-only, uuid-keyed,
        # hash-chained table when the new columns are absent. Old rows are dropped
        # (they were keyed by the colliding type|location|state triple anyway).
        try:
            self._migrate_decisions_table()
        except Exception:
            pass
        if not self.pg:
            self.conn.commit()

    def _decisions_has_uuid(self):
        if self.pg:
            cur = self.conn.cursor()
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='decisions'")
            cols = {r[0] for r in cur.fetchall()}
            cur.close()
        else:
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(decisions)")}
        return "incident_uuid" in cols and "hash" in cols

    def _migrate_decisions_table(self):
        if self._decisions_has_uuid():
            return  # already the new shape (fresh DB or already migrated)
        if self.pg:
            cur = self.conn.cursor()
            cur.execute("DROP TABLE IF EXISTS decisions")
            cur.execute(
                "CREATE TABLE decisions ("
                " id SERIAL PRIMARY KEY, incident_uuid TEXT, event_version INTEGER, key TEXT,"
                " decision TEXT, note TEXT, actor TEXT, ts TEXT, prev_hash TEXT, hash TEXT)")
            cur.close()
        else:
            self.conn.execute("DROP TABLE IF EXISTS decisions")
            self.conn.execute(
                "CREATE TABLE decisions ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT, incident_uuid TEXT, event_version INTEGER, key TEXT,"
                " decision TEXT, note TEXT, actor TEXT, ts TEXT, prev_hash TEXT, hash TEXT)")
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

    @staticmethod
    def _stable_key(inc):
        # Display/matching key (NOT the decision key). Maps a returning cluster to
        # its prior immutable incident_uuid so identity + decisions survive recompute.
        return "{}|{}|{}".format(inc.get("type"), inc.get("location_name"), inc.get("state"))

    @staticmethod
    def _content_fingerprint(member_ids, status, source_count):
        # Material content of a cluster. When this changes for the same stable_key,
        # the event has moved on -> bump event_version (lineage), keeping the uuid.
        return "{}|{}|{}".format(sorted(member_ids or []), status, source_count)

    def replace_incidents(self, incidents):
        # INT-01: preserve immutable identity across the delete+reinsert. Load the
        # prior (stable_key -> uuid, version, fingerprint) so a returning event keeps
        # its uuid (and therefore its operator decision); genuinely new clusters mint
        # a fresh uuid; a changed cluster keeps its uuid but bumps event_version.
        members = {}  # incident_uuid -> [signal_id,...] from the prior generation
        for r in self._all("SELECT i.incident_uuid AS u, s.signal_id AS sid FROM incidents i"
                           " JOIN incident_signals s ON s.incident_id=i.id"):
            members.setdefault(r["u"], []).append(r["sid"])
        prior = {}
        for r in self._all("SELECT incident_uuid, event_version, type, location_name, state,"
                           " source_count, status FROM incidents"):
            sk = self._stable_key(r)
            fp = self._content_fingerprint(members.get(r.get("incident_uuid"), []),
                                           r.get("status"), r.get("source_count"))
            prior[sk] = {"uuid": r.get("incident_uuid"), "version": r.get("event_version") or 1, "fp": fp}

        self._run("DELETE FROM incidents")
        self._run("DELETE FROM incident_signals")
        for inc in incidents:
            sk = self._stable_key(inc)
            fp_new = self._content_fingerprint(inc.get("signal_ids"), inc.get("status"), inc.get("source_count"))
            p = prior.get(sk)
            if p and p.get("uuid"):
                uuid_val = p["uuid"]
                version = p["version"] + 1 if fp_new != p.get("fp") else p["version"]
            else:
                uuid_val = security.new_uuid() if security else _fallback_uuid()
                version = 1
            iid = self._insert(
                "INSERT INTO incidents (incident_uuid, event_version, type, location_name, state, lat, lng,"
                " window_start, window_end, source_count, source_diversity, severity, confidence, status,"
                " summary, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (uuid_val, version, inc["type"], inc["location_name"], inc["state"], inc["lat"], inc["lng"],
                 inc["window_start"], inc["window_end"], inc["source_count"], inc["source_diversity"],
                 inc["severity"], inc["confidence"], inc["status"], inc["summary"], now_iso()))
            for sid in inc["signal_ids"]:
                self._run("INSERT INTO incident_signals (incident_id, signal_id) VALUES (?,?)", (iid, sid))

    def _last_decision_hash(self):
        r = self._one("SELECT hash FROM decisions ORDER BY id DESC LIMIT 1")
        return (r.get("hash") if r else "") or ""

    def set_decision(self, incident_uuid, decision, note, actor, event_version=None, key=None):
        # INT-01 + PRIV-05: append-only, keyed to the immutable incident_uuid, with a
        # tamper-evident hash chain (prev_hash -> hash). The latest row per uuid wins.
        ts = now_iso()
        prev = self._last_decision_hash()
        row = {"incident_uuid": incident_uuid, "event_version": event_version,
               "decision": decision, "note": note, "actor": actor, "ts": ts}
        h = security.audit_hash(prev, row) if security else _fallback_hash(prev, row)
        self._run(
            "INSERT INTO decisions (incident_uuid, event_version, key, decision, note, actor, ts, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (incident_uuid, event_version, key, decision, note, actor, ts, prev, h))
        return h

    def decisions(self):
        # Latest decision per incident_uuid (append-only history -> live view).
        out = {}
        for r in self._all("SELECT * FROM decisions ORDER BY id ASC"):
            if r.get("incident_uuid"):
                out[r["incident_uuid"]] = r
        return out

    def decision_log(self):
        # Full append-only chain (for tamper-evident export / audit; PRIV-05).
        return self._all("SELECT * FROM decisions ORDER BY id ASC")

    def insert_missing(self, m):
        return self._insert(
            "INSERT INTO missing (name, age, place, exact_place, lat, lng, count, last_seen, description, vehicle, clothing, direction, status, created_at, beacon_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (m["name"], m.get("age", ""), m["place"], m.get("exact_place", ""), m["lat"], m["lng"],
             int(m.get("count", 1) or 1), m["last_seen"], m.get("description", ""),
             m.get("vehicle", ""), m.get("clothing", ""), m.get("direction", ""), "active", now_iso(),
             m.get("beacon_id", "")))

    def find_missing_by_beacon(self, beacon_id):
        if not beacon_id:
            return None
        return self._one("SELECT * FROM missing WHERE beacon_id=? AND status IN ('active','located') ORDER BY id DESC", (beacon_id,))

    def all_missing(self):
        return self._all(
            "SELECT * FROM missing WHERE status IN ('active','located','recovered') ORDER BY id DESC")

    def get_missing(self, case_id):
        # ABU-10: existence check so a sighting can't be bound to a phantom case.
        try:
            cid = int(case_id)
        except Exception:
            return None
        return self._one("SELECT * FROM missing WHERE id=?", (cid,))

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

    def _last_audit_hash(self):
        r = self._one("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
        return (r.get("hash") if r else "") or ""

    def audit(self, actor, action, detail):
        # PRIV-05: tamper-evident, append-only audit log. Each row links to the
        # previous via prev_hash -> hash so any retroactive edit breaks the chain.
        ts = now_iso()
        prev = self._last_audit_hash()
        row = {"ts": ts, "actor": actor, "action": action, "detail": detail}
        h = security.audit_hash(prev, row) if security else _fallback_hash(prev, row)
        self._run("INSERT INTO audit (ts, actor, action, detail, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                  (ts, actor, action, detail, prev, h))
        return h

    def verify_audit_chain(self):
        # Recompute the chain and report the first broken link (None if intact).
        prev = ""
        for r in self._all("SELECT * FROM audit ORDER BY id ASC"):
            row = {"ts": r.get("ts"), "actor": r.get("actor"), "action": r.get("action"), "detail": r.get("detail")}
            expect = security.audit_hash(prev, row) if security else _fallback_hash(prev, row)
            if expect != (r.get("hash") or ""):
                return r.get("id")
            prev = r.get("hash") or ""
        return None

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

    def has_active_alert(self, key):
        # INT-02: is there already a live alert for this incident? Used to make
        # re-verifying the same incident idempotent (no duplicate active alerts).
        return self._one("SELECT id FROM alerts WHERE incident_key=? AND status='active'", (key,)) is not None

    def resolve_alert(self, key):
        self._run("UPDATE alerts SET status='resolved' WHERE incident_key=? AND status='active'", (key,))

    def insert_channel(self, c):
        self._run(
            "INSERT INTO channel (area, text, lat, lng, source, created_at) VALUES (?,?,?,?,?,?)",
            (c.get("area", ""), c.get("text", ""), c.get("lat"), c.get("lng"),
             c.get("source", "community"), now_iso()))

    def recent_channel(self, limit=40):
        return self._all("SELECT * FROM channel ORDER BY id DESC LIMIT %d" % int(limit))
