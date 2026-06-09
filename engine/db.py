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
import hmac
import json
import datetime

try:
    import security  # uuid / audit-hash helpers (stdlib-only sibling module)
except Exception:  # pragma: no cover - keep db importable even if security.py absent
    security = None

try:
    # Phase 1 response loop: pure DDL strings + state helpers (sibling module).
    # db.py only consumes its DDL/TTL helpers; it never moves a state machine.
    import response
except Exception:  # pragma: no cover - keep db importable even if response.py absent
    response = None

try:
    # Phase 4 abuse-integrity: pure DDL strings + reputation update math.
    import reputation
except Exception:  # pragma: no cover - keep db importable even if reputation.py absent
    reputation = None

try:
    # Product-safety layer: Journey Guard / readiness / case workspace / evidence /
    # safety network / mesh / tracker / ops-readiness schema + pure helpers.
    import safety
except Exception:  # pragma: no cover - keep db importable even if safety.py absent
    safety = None

try:
    # Citizen identity/session + Safety Vault + MySafe/PWA push schema.
    import identity
except Exception:  # pragma: no cover - keep db importable even if identity.py absent
    identity = None

DATABASE_URL = os.environ.get("DATABASE_URL")
REQUIRE_POSTGRES = os.environ.get("DEYSAFE_REQUIRE_POSTGRES", "").strip().lower() in (
    "1", "true", "yes", "on")

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

# ---------------------------------------------------------------------------
# Additional Phase 2-4 tables that don't belong to a sibling module's DDL.
#   geo_cache    (GEO-02): persist geocode lookups across restarts so we stop
#                hammering Nominatim (today api._geocache is in-process only).
#   source_health (DATA-01): the scheduler's per-feed run/health record so an
#                operator panel can see when each source last pulled cleanly.
# Both are CREATE TABLE IF NOT EXISTS so they are safe to run on every boot,
# matching db.py's schema-execute-on-connect pattern. (name -> (sqlite, pg)).
GEO_CACHE_SQLITE = """
CREATE TABLE IF NOT EXISTS geo_cache (
  query TEXT PRIMARY KEY,
  lat REAL, lng REAL,
  source TEXT, display TEXT, confidence TEXT,
  ts TEXT
);
"""
GEO_CACHE_PG = """
CREATE TABLE IF NOT EXISTS geo_cache (
  query TEXT PRIMARY KEY,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  source TEXT, display TEXT, confidence TEXT,
  ts TEXT
);
"""

SOURCE_HEALTH_SQLITE = """
CREATE TABLE IF NOT EXISTS source_health (
  source TEXT PRIMARY KEY,
  last_run_at TEXT, last_success_at TEXT, last_error_at TEXT,
  last_error TEXT,
  runs INTEGER DEFAULT 0, successes INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
  fetched INTEGER DEFAULT 0, added INTEGER DEFAULT 0
);
"""
SOURCE_HEALTH_PG = """
CREATE TABLE IF NOT EXISTS source_health (
  source TEXT PRIMARY KEY,
  last_run_at TEXT, last_success_at TEXT, last_error_at TEXT,
  last_error TEXT,
  runs INTEGER DEFAULT 0, successes INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
  fetched INTEGER DEFAULT 0, added INTEGER DEFAULT 0
);
"""

# subscribers (P1-01): citizens who OPT IN to geofenced public alerts. This is the
# missing other half of the response loop — operator verifies a threat -> the alert
# must actually reach the people in that state/LGA. Privacy/NDPA posture:
#   - address is consent-gated PII (a phone/endpoint the citizen themselves supplied
#     by opting in); the row carries consent_at as opt-in proof and the table lives
#     only in the runtime DB (data/ is never committed; the public repo never sees it);
#   - address_hash = sha256(channel|lower(address)) is UNIQUE, so a repeat opt-in
#     reactivates rather than duplicating, and unsubscribe/erasure can target a
#     subscriber WITHOUT a plaintext scan;
#   - active=0 on opt-out keeps an auditable record; erase_subscriber() hard-deletes
#     for a full NDPA erasure request (P2-02).
# Empty `state` == nationwide subscriber (always in range). Both DDLs are
# CREATE TABLE IF NOT EXISTS so this applies to the live Railway DB on next boot
# with no manual migration.
SUBSCRIBERS_SQLITE = """
CREATE TABLE IF NOT EXISTS subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sub_uuid TEXT,
  channel TEXT, address TEXT, address_hash TEXT UNIQUE,
  state TEXT, lga TEXT,
  active INTEGER DEFAULT 1,
  consent_at TEXT, created_at TEXT, unsubscribed_at TEXT
);
"""
SUBSCRIBERS_PG = """
CREATE TABLE IF NOT EXISTS subscribers (
  id SERIAL PRIMARY KEY,
  sub_uuid TEXT,
  channel TEXT, address TEXT, address_hash TEXT UNIQUE,
  state TEXT, lga TEXT,
  active INTEGER DEFAULT 1,
  consent_at TEXT, created_at TEXT, unsubscribed_at TEXT
);
"""

# pending_approvals (P0-08): TWO-PERSON integrity for promoting an event to a public
# RED alert. With DEYSAFE_DUAL_APPROVAL on, operator #1's /api/verify only records a
# pending approval here; a SECOND, DIFFERENT operator must /api/confirm before the
# alert fires. Keyed by the immutable incident_uuid so a stale proposal can't re-bind.
# Off by default — single-operator deploys are unaffected and existing gates stay green.
PENDING_APPROVALS_SQLITE = """
CREATE TABLE IF NOT EXISTS pending_approvals (
  incident_uuid TEXT PRIMARY KEY,
  first_actor TEXT, first_at TEXT,
  level INTEGER DEFAULT 0, note TEXT, disp_key TEXT
);
"""
PENDING_APPROVALS_PG = """
CREATE TABLE IF NOT EXISTS pending_approvals (
  incident_uuid TEXT PRIMARY KEY,
  first_actor TEXT, first_at TEXT,
  level INTEGER DEFAULT 0, note TEXT, disp_key TEXT
);
"""

# media_quota (P0-16): per-identity DAILY counter of signed evidence-upload URLs
# minted, so /api/media/presign cannot be used as an open write-proxy to the object
# store. Keyed by (quota_key, day) where quota_key is the citizen session uuid when
# present, else an anonymized caller hash. type + size are already enforced in
# api.r2_presign_put; this is the abuse/cost cap on top.
MEDIA_QUOTA_SQLITE = """
CREATE TABLE IF NOT EXISTS media_quota (
  quota_key TEXT, day TEXT, count INTEGER DEFAULT 0,
  PRIMARY KEY (quota_key, day)
);
"""
MEDIA_QUOTA_PG = """
CREATE TABLE IF NOT EXISTS media_quota (
  quota_key TEXT, day TEXT, count INTEGER DEFAULT 0,
  PRIMARY KEY (quota_key, day)
);
"""

# delivery_acks (outcome measurement / MET): a RECIPIENT acknowledgement that a human
# actually received an alert/SOS notification ("I got it"). This is the honest other
# half of the reach loop: a provider accepting a message is NOT proof a person saw it.
# Keyed by the delivery receipt's provider_ref (carried in the notification).
DELIVERY_ACKS_SQLITE = """
CREATE TABLE IF NOT EXISTS delivery_acks ( ref TEXT PRIMARY KEY, acked_at TEXT );
"""
DELIVERY_ACKS_PG = """
CREATE TABLE IF NOT EXISTS delivery_acks ( ref TEXT PRIMARY KEY, acked_at TEXT );
"""

# Local (db.py-owned) extra tables, mirroring response.RESPONSE_TABLES shape.
_EXTRA_TABLES = {
    "geo_cache": (GEO_CACHE_SQLITE, GEO_CACHE_PG),
    "source_health": (SOURCE_HEALTH_SQLITE, SOURCE_HEALTH_PG),
    "subscribers": (SUBSCRIBERS_SQLITE, SUBSCRIBERS_PG),
    "pending_approvals": (PENDING_APPROVALS_SQLITE, PENDING_APPROVALS_PG),
    "media_quota": (MEDIA_QUOTA_SQLITE, MEDIA_QUOTA_PG),
    "delivery_acks": (DELIVERY_ACKS_SQLITE, DELIVERY_ACKS_PG),
}

# Phase 4: SafeMeet tables from safety module
if safety:
    _EXTRA_TABLES["safemeet_sessions"] = (safety.SAFEMEET_SQLITE, safety.SAFEMEET_PG)
    _EXTRA_TABLES["safemeet_checkins"] = (safety.SAFEMEET_CHECKINS_SQLITE, safety.SAFEMEET_CHECKINS_PG)
if identity:
    for _n, _pair in identity.IDENTITY_TABLES.items():
        _EXTRA_TABLES[_n] = _pair


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
                if REQUIRE_POSTGRES:
                    raise RuntimeError("DATABASE_URL is set but Postgres connect failed: %s" % e)
                # Never crash the app over a bad/unreachable DATABASE_URL — fall back
                # to SQLite and warn loudly so the misconfig is visible in the logs.
                sys.stderr.write("[db] DATABASE_URL is set but Postgres connect failed "
                                 "(%s) -- falling back to SQLite so the app stays up.\n" % e)
                self.pg = False
        if not self.pg:
            self.conn = sqlite3.connect(path, timeout=30)
            self.conn.row_factory = sqlite3.Row
            # WAL + busy_timeout: ThreadingHTTPServer runs each request in its own thread
            # and /api/report's recompute does a bulk delete+insert; without this, concurrent
            # writes raise "database is locked" (which, unhandled, dropped the connection).
            try:
                self.conn.execute("PRAGMA journal_mode=WAL")
                self.conn.execute("PRAGMA busy_timeout=30000")
            except Exception:
                pass
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
        # Phase 1-4 schema: create every new table for BOTH backends and splice the
        # alert-lifecycle columns onto the existing `alerts` table. All CREATE
        # statements are IF NOT EXISTS; the ALTERs use the same guarded pattern as
        # the column loops above (PG: ADD COLUMN IF NOT EXISTS; SQLite: bare ALTER
        # in a try/except). Wrapped so a partial/old sibling module can't break boot.
        try:
            self._migrate_phase_tables()
        except Exception:
            pass
        if not self.pg:
            self.conn.commit()

    def _create_table(self, sqlite_ddl, pg_ddl):
        """Create one table from a (sqlite_ddl, pg_ddl) pair on the active backend.

        Both DDLs are CREATE TABLE IF NOT EXISTS, so this is idempotent and safe on
        every boot. Used to splice in the response/reputation/extra tables without
        duplicating their schema text in db.py."""
        if self.pg:
            cur = self.conn.cursor()
            for stmt in [s.strip() for s in pg_ddl.split(";") if s.strip()]:
                cur.execute(stmt)
            cur.close()
        else:
            self.conn.executescript(sqlite_ddl)

    def _add_columns(self, table, columns):
        """Splice (name, sqlite_decl, pg_decl) columns onto an existing table.

        Mirrors the incident_uuid / audit-hash migrations above: PG uses
        ADD COLUMN IF NOT EXISTS; legacy SQLite issues a bare ALTER ADD COLUMN and
        swallows the duplicate-column error so re-running is a no-op."""
        for col, sdecl, pdecl in columns:
            try:
                if self.pg:
                    cur = self.conn.cursor()
                    cur.execute("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s" % (table, col, pdecl))
                    cur.close()
                else:
                    self.conn.execute("ALTER TABLE " + table + " ADD COLUMN " + col + " " + sdecl)
            except Exception:
                pass  # column already exists

    def _migrate_phase_tables(self):
        # Response-loop tables (sos_events / trusted_contacts / responders /
        # responder_tasks / deliveries) — described by response.py, created here.
        if response is not None:
            for _name, (sdl, pdl) in getattr(response, "RESPONSE_TABLES", {}).items():
                try:
                    self._create_table(sdl, pdl)
                except Exception:
                    pass
            # INT-03: alert lifecycle columns spliced onto the existing alerts table.
            self._add_columns("alerts", getattr(response, "ALERT_LIFECYCLE_COLUMNS", ()))
        # Abuse-integrity reputation table (reporter_stats) — described by reputation.py.
        if reputation is not None:
            for _name, (sdl, pdl) in getattr(reputation, "REPUTATION_TABLES", {}).items():
                try:
                    self._create_table(sdl, pdl)
                except Exception:
                    pass
        # db.py-owned extra tables (geo_cache, source_health).
        for _name, (sdl, pdl) in _EXTRA_TABLES.items():
            try:
                self._create_table(sdl, pdl)
            except Exception:
                pass
        # Product-safety tables: Journey Guard, readiness, SHIELD cases,
        # evidence/GeoTrace, Safety Points/Sentinels, mesh relays, trackers,
        # agreements, and drills. These are also idempotent for SQLite/Postgres.
        if safety is not None:
            for _name, (sdl, pdl) in getattr(safety, "SAFETY_TABLES", {}).items():
                try:
                    self._create_table(sdl, pdl)
                except Exception:
                    pass
        self._add_columns("guardian_contacts", (
            ("address_ciphertext", "TEXT", "TEXT"),
            ("verification_ref", "TEXT", "TEXT"),
            ("verification_hash", "TEXT", "TEXT"),
            ("verified_at", "TEXT", "TEXT"),
        ))
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

    def backend(self):
        return "postgres" if self.pg else "sqlite"

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
        # The legacy `status` ('active'/'resolved') column is preserved exactly so
        # has_active_alert / resolve_alert / the existing list filter keep working.
        # INT-03 lifecycle columns (alert_uuid/state/version/expires_at/updated_at)
        # are stamped on top in a guarded second step so a DB whose alerts table was
        # not yet migrated still inserts fine (the UPDATE simply no-ops on error).
        ts = now_iso()
        rid = self._insert(
            "INSERT INTO alerts (incident_key, level, level_label, title, guidance, lat, lng, radius_km, reach, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (a.get("incident_key"), a["level"], a["level_label"], a["title"], a["guidance"],
             a["lat"], a["lng"], a["radius_km"], a.get("reach", 0), "active", ts))
        # Compute the TTL/expiry from the alert level label (response owns the policy).
        expires_at = a.get("expires_at")
        if not expires_at and response is not None:
            try:
                ttl_h = response.ttl_for_level(a.get("level_label"))
                created = response._parse_iso(ts) or datetime.datetime.now()
                expires_at = (created + datetime.timedelta(hours=ttl_h)).isoformat(timespec="seconds")
            except Exception:
                expires_at = None
        alert_uuid = a.get("alert_uuid") or (response.new_id() if response else _fallback_uuid())
        state = a.get("state") or (getattr(response, "ALERT_INITIAL", "PUBLISHED") if response else "PUBLISHED")
        try:
            self._run(
                "UPDATE alerts SET alert_uuid=?, state=?, version=?, expires_at=?, updated_at=? WHERE id=?",
                (alert_uuid, state, int(a.get("version", 1) or 1), expires_at, ts, rid))
        except Exception:
            pass  # alerts table not yet migrated with lifecycle columns — legacy mode
        return rid

    def _alert_row_active(self, r):
        # INT-03 read-time liveness: an alert is live when its legacy status is
        # 'active' AND (if it carries lifecycle data) its lifecycle state is live and
        # it is within TTL. Rows without lifecycle columns fall back to status only,
        # so legacy/un-migrated alerts behave exactly as before (no gate regression).
        if (r.get("status") or "active") != "active":
            return False
        state = r.get("state")
        if not state or response is None:
            return True  # no lifecycle info -> legacy behaviour (status governs)
        ttl_h = 0
        try:
            ttl_h = response.ttl_for_level(r.get("level_label"))
        except Exception:
            ttl_h = 0
        # Prefer an explicit expires_at when present; otherwise derive from created_at+TTL.
        exp = r.get("expires_at")
        if exp:
            try:
                return state in getattr(response, "ALERT_LIVE", frozenset()) and \
                    response._parse_iso(exp) is not None and \
                    response._parse_iso(exp) >= datetime.datetime.now()
            except Exception:
                return state in getattr(response, "ALERT_LIVE", frozenset())
        return response.alert_is_active(state, r.get("created_at"), ttl_h)

    def _ensure_alert_lifecycle(self, r):
        if response is None or not r:
            return r
        if r.get("alert_uuid") and r.get("state") and r.get("expires_at"):
            return r
        ts = r.get("updated_at") or now_iso()
        created = response._parse_iso(r.get("created_at")) or datetime.datetime.now()
        try:
            ttl_h = response.ttl_for_level(r.get("level_label"))
            expires_at = r.get("expires_at") or (created + datetime.timedelta(hours=ttl_h)).isoformat(timespec="seconds")
        except Exception:
            expires_at = r.get("expires_at") or (created + datetime.timedelta(hours=24)).isoformat(timespec="seconds")
        alert_uuid = r.get("alert_uuid") or (response.new_id() if response else _fallback_uuid())
        state = r.get("state") or getattr(response, "ALERT_INITIAL", "PUBLISHED")
        version = int(r.get("version") or 1)
        try:
            self._run(
                "UPDATE alerts SET alert_uuid=?, state=?, version=?, expires_at=?, updated_at=? WHERE id=?",
                (alert_uuid, state, version, expires_at, ts, r.get("id")))
            r["alert_uuid"] = alert_uuid
            r["state"] = state
            r["version"] = version
            r["expires_at"] = expires_at
            r["updated_at"] = ts
        except Exception:
            pass
        return r

    def active_alerts(self):
        # Keep the SQL filter on the legacy status column (fast, index-friendly,
        # preserves current behaviour) then drop any lifecycle-dead / past-TTL rows
        # at read-time. validate_response.py gate D checks both the expires_at field
        # is present and that no past-TTL alert is still listed.
        rows = [self._ensure_alert_lifecycle(r) for r in
                self._all("SELECT * FROM alerts WHERE status='active' ORDER BY level DESC, id DESC")]
        return [r for r in rows if self._alert_row_active(r)]

    def has_active_alert(self, key):
        # INT-02: is there already a live alert for this incident? Used to make
        # re-verifying the same incident idempotent (no duplicate active alerts).
        return self._one("SELECT id FROM alerts WHERE incident_key=? AND status='active'", (key,)) is not None

    def resolve_alert(self, key):
        self._run("UPDATE alerts SET status='resolved' WHERE incident_key=? AND status='active'", (key,))

    def cancel_alert(self, key, reason="", actor="operator"):
        # ABU-07 kill-switch + INT-03: an operator cancels a live alert. Sets the
        # legacy status to 'resolved' (so it drops out of active_alerts immediately)
        # and, when lifecycle columns exist, stamps state=CANCELLED + cancel metadata.
        # `key` may match either the immutable incident_key or the alert_uuid so the
        # api layer can cancel on whichever id it holds. Returns rows affected.
        ts = now_iso()
        cancelled = getattr(response, "ALERT_CANCELLED", "CANCELLED") if response else "CANCELLED"
        # First resolve the legacy status for matching live rows (both key columns).
        self._run("UPDATE alerts SET status='resolved' WHERE status='active' AND (incident_key=? OR alert_uuid=?)",
                  (key, key))
        try:
            self._run(
                "UPDATE alerts SET state=?, cancelled_at=?, cancel_reason=?, updated_at=?"
                " WHERE (incident_key=? OR alert_uuid=?)",
                (cancelled, ts, (reason or "")[:300], ts, key, key))
        except Exception:
            pass  # lifecycle columns absent — legacy resolve already applied above
        return True

    def insert_channel(self, c):
        self._run(
            "INSERT INTO channel (area, text, lat, lng, source, created_at) VALUES (?,?,?,?,?,?)",
            (c.get("area", ""), c.get("text", ""), c.get("lat"), c.get("lng"),
             c.get("source", "community"), now_iso()))

    def recent_channel(self, limit=40):
        return self._all("SELECT * FROM channel ORDER BY id DESC LIMIT %d" % int(limit))

    # ======================================================================
    # PHASE 1-4 DATA ACCESS (response loop / reputation / geo / source health)
    # All methods are parameterised and dual-mode (?-placeholders rewritten to %s
    # for Postgres by _sql). They never move a state machine themselves — the api
    # layer computes the next state via response.py and passes it in.
    # ======================================================================

    # --- reference numbers (FIND-03): DS-YYYY-NNNN --------------------------
    def new_ref(self, prefix="DS"):
        """Mint a human-facing reference like DS-2026-0007.

        Deterministic + collision-resistant: counts existing SOS events + missing
        cases created in the current year and adds 1, zero-padded to 4 digits. Used
        by both SOS creation and the USSD missing-person case (FIND-03)."""
        year = datetime.datetime.now().year
        n = 0
        for tbl in ("sos_events", "missing"):
            try:
                r = self._one(
                    "SELECT COUNT(*) AS c FROM %s WHERE created_at LIKE ?" % tbl,
                    ("%d-%%" % year,))
                n += int((r or {}).get("c", 0) or 0)
            except Exception:
                pass  # table may not exist yet on a very old DB
        return "%s-%d-%04d" % (prefix, year, n + 1)

    # --- SOS events (SOS-01/02) --------------------------------------------
    def insert_sos_event(self, d):
        """Persist a new durable SOS event. Returns the row id.

        Accepts a client-supplied `client_id` for offline-replay idempotency
        (OFF-01): if a row with the same sos_uuid already exists we return it rather
        than double-creating. `reporter_hint` carries the opt-in owner_token so the
        operator can reach the trusted circle; it is NEVER projected on a public GET."""
        suid = d.get("sos_uuid") or (response.new_id() if response else _fallback_uuid())
        existing = self._one("SELECT id FROM sos_events WHERE sos_uuid=?", (suid,))
        if existing:
            return existing["id"]
        ts = now_iso()
        return self._insert(
            "INSERT INTO sos_events (sos_uuid, created_at, updated_at, lat, lng, message, mode, state,"
            " contact_state, operator, acked_at, handoff_ref, reporter_hint, closed_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (suid, ts, ts, d.get("lat"), d.get("lng"), d.get("message", ""), d.get("mode", ""),
             d.get("state") or (getattr(response, "SOS_INITIAL", "TRIGGERED") if response else "TRIGGERED"),
             d.get("contact_state"), d.get("operator"), d.get("acked_at"),
             d.get("handoff_ref"), d.get("reporter_hint") or d.get("owner_token"), d.get("closed_at")))

    def get_sos_by_uuid(self, sos_uuid):
        if not sos_uuid:
            return None
        return self._one("SELECT * FROM sos_events WHERE sos_uuid=? ORDER BY id DESC", (sos_uuid,))

    def get_sos_by_ref(self, ref):
        # The ref lives in handoff_ref (we stamp it there at create time).
        if not ref:
            return None
        return self._one("SELECT * FROM sos_events WHERE handoff_ref=? ORDER BY id DESC", (ref,))

    def get_sos(self, ident):
        """Resolve an SOS by uuid first, then by reference (api convenience)."""
        return self.get_sos_by_uuid(ident) or self.get_sos_by_ref(ident)

    def update_sos_state(self, sos_uuid, state, **fields):
        """Advance an SOS event to `state` (the caller validated the transition via
        response.next_state) and optionally stamp any of the timestamp/operator
        columns (operator, acked_at, handoff_ref, contact_state, closed_at, lat,
        lng, message). updated_at is always refreshed. Returns nothing."""
        allowed = ("operator", "acked_at", "handoff_ref", "contact_state",
                   "closed_at", "lat", "lng", "message", "mode")
        sets = ["state=?", "updated_at=?"]
        params = [state, now_iso()]
        for k in allowed:
            if k in fields:
                sets.append("%s=?" % k)
                params.append(fields[k])
        params.append(sos_uuid)
        self._run("UPDATE sos_events SET %s WHERE sos_uuid=?" % ", ".join(sets), tuple(params))

    def sos_queue(self, limit=200):
        """Operator SOS list, live/newest first. Non-terminal events float to the
        top (TRIGGERED/escalated need attention before SAFE/CLOSED)."""
        terminal = tuple(getattr(response, "SOS_TERMINAL", ("SAFE", "CLOSED"))) if response else ("SAFE", "CLOSED")
        rows = self._all("SELECT * FROM sos_events ORDER BY id DESC LIMIT %d" % int(limit))
        live = [r for r in rows if (r.get("state") not in terminal)]
        done = [r for r in rows if (r.get("state") in terminal)]
        return live + done

    # --- trusted circle (SOS-03) — server-side only, never on a public GET ---
    def insert_trusted(self, owner_token, name, channel, address):
        return self._insert(
            "INSERT INTO trusted_contacts (owner_token, name, channel, address, created_at, verified)"
            " VALUES (?,?,?,?,?,?)",
            (owner_token, name, channel, address, now_iso(), 0))

    def replace_trusted(self, owner_token, contacts):
        """Bulk mirror a field user's circle: drop their existing rows and insert the
        supplied list (each {name, channel, address}). Idempotent re-sync."""
        self._run("DELETE FROM trusted_contacts WHERE owner_token=?", (owner_token,))
        out = 0
        for c in (contacts or []):
            if not isinstance(c, dict):
                continue
            self.insert_trusted(owner_token, c.get("name", ""), c.get("channel", ""), c.get("address", ""))
            out += 1
        return out

    def trusted_for(self, owner_token):
        if not owner_token:
            return []
        return self._all("SELECT * FROM trusted_contacts WHERE owner_token=? ORDER BY id", (owner_token,))

    # --- responder directory (RESP-01) -------------------------------------
    def insert_responder(self, d):
        return self._insert(
            "INSERT INTO responders (name, org, role, state, lga, channel, address, active, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (d.get("name", ""), d.get("org", ""), d.get("role", ""), d.get("state", ""),
             d.get("lga", ""), d.get("channel", ""), d.get("address", ""),
             int(d.get("active", 1) or 0), now_iso()))

    def active_responders(self):
        return self._all("SELECT * FROM responders WHERE active=1 ORDER BY id DESC")

    def responders_for(self, state=None, lga=None):
        """Active responders optionally filtered by state and/or LGA (case-insensitive)."""
        sql = "SELECT * FROM responders WHERE active=1"
        params = []
        if state:
            sql += " AND lower(state)=lower(?)"
            params.append(state)
        if lga:
            sql += " AND lower(lga)=lower(?)"
            params.append(lga)
        sql += " ORDER BY id DESC"
        return self._all(sql, tuple(params))

    def all_responders(self, limit=500):
        return self._all("SELECT * FROM responders ORDER BY id DESC LIMIT %d" % int(limit))

    # --- citizen alert subscribers (P1-01) ---------------------------------
    # The opt-in audience an operator-verified alert actually fans out to. Kept
    # deliberately separate from the responder directory (responders ACT on an
    # alert; subscribers RECEIVE the public warning).
    @staticmethod
    def _sub_hash(channel, address):
        ch = (channel or "sms").strip().lower()
        addr = (address or "").strip().lower()
        return hashlib.sha256((ch + "|" + addr).encode("utf-8")).hexdigest()

    def insert_subscriber(self, d):
        """Opt a citizen in to geofenced public alerts (NDPA: consent_at stored).
        Idempotent on (channel,address) via address_hash UNIQUE — a repeat opt-in
        reactivates and refreshes the geofence instead of duplicating. Returns
        (id, created) where created is False on a reactivate/no-op."""
        ch = (d.get("channel") or "sms").strip().lower()
        addr = (d.get("address") or "").strip()
        if not addr:
            return None, False
        ahash = self._sub_hash(ch, addr)
        ts = now_iso()
        st = (d.get("state") or "").strip()
        lga = (d.get("lga") or "").strip()
        existing = self._one("SELECT id FROM subscribers WHERE address_hash=?", (ahash,))
        if existing:
            self._run("UPDATE subscribers SET active=1, state=?, lga=?, consent_at=?,"
                      " unsubscribed_at=NULL WHERE address_hash=?", (st, lga, ts, ahash))
            return existing["id"], False
        suid = _fallback_uuid()
        sid = self._insert(
            "INSERT INTO subscribers (sub_uuid, channel, address, address_hash, state, lga,"
            " active, consent_at, created_at) VALUES (?,?,?,?,?,?,1,?,?)",
            (suid, ch, addr, ahash, st, lga, ts, ts))
        return sid, True

    def subscribers_for(self, state=None, lga=None):
        """Active subscribers for a geofenced alert. An empty-state subscriber is
        nationwide (always included). Case-insensitive; sqlite + PG compatible."""
        sql = "SELECT * FROM subscribers WHERE active=1"
        params = []
        if state:
            sql += " AND (state='' OR lower(state)=lower(?))"
            params.append(state)
        if lga:
            sql += " AND (lga='' OR lower(lga)=lower(?))"
            params.append(lga)
        sql += " ORDER BY id DESC"
        return self._all(sql, tuple(params))

    def deactivate_subscriber(self, channel, address):
        """NDPA opt-out: flip active=0 (row kept for audit). True if a row matched."""
        addr = (address or "").strip()
        if not addr:
            return False
        ahash = self._sub_hash(channel, addr)
        row = self._one("SELECT id FROM subscribers WHERE address_hash=? AND active=1", (ahash,))
        self._run("UPDATE subscribers SET active=0, unsubscribed_at=? WHERE address_hash=?",
                  (now_iso(), ahash))
        return bool(row)

    def erase_subscriber(self, channel, address):
        """NDPA erasure (P2-02): hard-delete the subscriber row. True if matched."""
        addr = (address or "").strip()
        if not addr:
            return False
        ahash = self._sub_hash(channel, addr)
        row = self._one("SELECT id FROM subscribers WHERE address_hash=?", (ahash,))
        self._run("DELETE FROM subscribers WHERE address_hash=?", (ahash,))
        return bool(row)

    def erase_subject(self, channel=None, address=None, owner_token=None, user_uuid=None, phone=None):
        """NDPA P2-02: hard-erase a data subject's PII across EVERY table that holds it,
        matched by any identifier supplied (address/phone, owner_token, or session
        user_uuid). Returns {table: rows_deleted}. Best-effort + table-by-table guarded
        so a deploy missing an optional table still erases the rest. The caller audits
        with a HASH of the identifier, never the raw value."""
        deleted = {}
        def _del(table, where, params):
            try:
                r = self._one("SELECT COUNT(*) AS c FROM %s WHERE %s" % (table, where), params)
                n = (r["c"] if r else 0)
            except Exception:
                return 0
            if n:
                try:
                    self._run("DELETE FROM %s WHERE %s" % (table, where), params)
                except Exception:
                    return 0
            deleted[table] = deleted.get(table, 0) + n
            return n
        if address:
            _del("subscribers", "address_hash=?", (self._sub_hash(channel or "sms", address),))
        if owner_token:
            _del("trusted_contacts", "owner_token=?", (owner_token,))
            _del("sos_events", "reporter_hint=?", (owner_token,))
        # Citizen identity + sessions: by uuid if known, otherwise resolve via phone_hash.
        ph = None
        if not user_uuid and (phone or address) and identity is not None:
            try:
                ph = identity.phone_hash((phone or address).strip())
            except Exception:
                ph = None
        if user_uuid:
            _del("personal_sessions", "user_uuid=?", (user_uuid,))
            _del("citizen_users", "user_uuid=?", (user_uuid,))
        elif ph:
            row = self._one("SELECT user_uuid FROM citizen_users WHERE phone_hash=?", (ph,))
            if row and row.get("user_uuid"):
                _del("personal_sessions", "user_uuid=?", (row["user_uuid"],))
            _del("citizen_users", "phone_hash=?", (ph,))
        return deleted

    def subscriber_count(self, active_only=True):
        sql = "SELECT COUNT(*) AS c FROM subscribers" + (" WHERE active=1" if active_only else "")
        r = self._one(sql)
        return (r["c"] if r else 0)

    # --- two-person RED approval (P0-08) ------------------------------------
    def add_pending_approval(self, iuid, actor, level=0, note="", disp_key=""):
        """Record operator #1's proposal to publish a RED alert. Idempotent per
        incident: a repeat proposal refreshes the proposer/time so the same operator
        can never appear as two."""
        ts = now_iso()
        existing = self._one("SELECT incident_uuid FROM pending_approvals WHERE incident_uuid=?", (iuid,))
        if existing:
            self._run("UPDATE pending_approvals SET first_actor=?, first_at=?, level=?, note=?, disp_key=?"
                      " WHERE incident_uuid=?", (actor, ts, int(level or 0), note, disp_key, iuid))
        else:
            self._insert("INSERT INTO pending_approvals (incident_uuid, first_actor, first_at, level, note, disp_key)"
                         " VALUES (?,?,?,?,?,?)", (iuid, actor, ts, int(level or 0), note, disp_key))
        return ts

    def get_pending_approval(self, iuid):
        return self._one("SELECT * FROM pending_approvals WHERE incident_uuid=?", (iuid,))

    def clear_pending_approval(self, iuid):
        self._run("DELETE FROM pending_approvals WHERE incident_uuid=?", (iuid,))

    def all_pending_approvals(self, limit=200):
        return self._all("SELECT * FROM pending_approvals ORDER BY first_at DESC LIMIT %d" % int(limit))

    # --- media upload quota (P0-16) -----------------------------------------
    def media_quota_used(self, quota_key, day):
        r = self._one("SELECT count FROM media_quota WHERE quota_key=? AND day=?", (quota_key, day))
        return (r["count"] if r else 0)

    def bump_media_quota(self, quota_key, day):
        existing = self._one("SELECT count FROM media_quota WHERE quota_key=? AND day=?", (quota_key, day))
        if existing:
            self._run("UPDATE media_quota SET count=count+1 WHERE quota_key=? AND day=?", (quota_key, day))
            return existing["count"] + 1
        self._insert("INSERT INTO media_quota (quota_key, day, count) VALUES (?,?,1)", (quota_key, day))
        return 1

    # --- responder tasks (RESP-01/06) — human ack ladder only ---------------
    def insert_responder_task(self, d):
        """Create a responder task in its initial 'received' state (RESP-06: human
        ack only, never auto-dispatch). escalate_after is an ISO deadline the ack
        SLA is measured against (MET-01). Returns row id."""
        tuid = d.get("task_uuid") or (response.new_id() if response else _fallback_uuid())
        ts = now_iso()
        return self._insert(
            "INSERT INTO responder_tasks (task_uuid, created_at, updated_at, incident_uuid, alert_key,"
            " sos_uuid, responder_id, state, ack_at, closed_at, escalate_after, note, after_action)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tuid, ts, ts, d.get("incident_uuid"), d.get("alert_key"), d.get("sos_uuid"),
             d.get("responder_id"),
             d.get("state") or (getattr(response, "TASK_INITIAL", "received") if response else "received"),
             d.get("ack_at"), d.get("closed_at"), d.get("escalate_after"),
             d.get("note", ""), d.get("after_action", "")))

    def responder_tasks(self, limit=200):
        return self._all("SELECT * FROM responder_tasks ORDER BY id DESC LIMIT %d" % int(limit))

    def get_task(self, ident):
        """Resolve a task by task_uuid first, then by numeric row id (api convenience)."""
        if ident is None:
            return None
        row = self._one("SELECT * FROM responder_tasks WHERE task_uuid=? ORDER BY id DESC", (ident,))
        if row:
            return row
        try:
            return self._one("SELECT * FROM responder_tasks WHERE id=?", (int(ident),))
        except Exception:
            return None

    def update_task_state(self, task_uuid, state, **fields):
        """Move a responder task to `state` (caller validated via response.
        valid_task_transition). Stamps ack_at when entering 'responding' and
        closed_at when entering 'closed' unless the caller supplies them. Resolves
        the row by task_uuid OR numeric id so the api can use whichever it holds."""
        sets = ["state=?", "updated_at=?"]
        params = [state, now_iso()]
        responding = getattr(response, "TASK_RESPONDING", "responding") if response else "responding"
        closed = getattr(response, "TASK_CLOSED", "closed") if response else "closed"
        if state == responding and "ack_at" not in fields:
            fields["ack_at"] = now_iso()
        if state == closed and "closed_at" not in fields:
            fields["closed_at"] = now_iso()
        for k in ("ack_at", "closed_at", "note", "after_action", "responder_id"):
            if k in fields:
                sets.append("%s=?" % k)
                params.append(fields[k])
        # Match on task_uuid OR id (id only if ident is int-coercible).
        try:
            rid = int(task_uuid)
            where = "(task_uuid=? OR id=?)"
            tail = [task_uuid, rid]
        except Exception:
            where = "task_uuid=?"
            tail = [task_uuid]
        self._run("UPDATE responder_tasks SET %s WHERE %s" % (", ".join(sets), where),
                  tuple(params + tail))

    # --- delivery receipts (BC-03) — SIM flag preserved ---------------------
    def insert_delivery(self, d):
        """Persist a broadcast/SOS-notify receipt. `sim` (0/1) records whether this
        was a SIM-mode send so a simulated delivery is NEVER shown as a real one;
        provider_ref holds the real gateway id for genuine sends. Returns row id."""
        return self._insert(
            "INSERT INTO deliveries (created_at, alert_key, sos_uuid, channel, address, status, provider_ref, sim)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now_iso(), d.get("alert_key"), d.get("sos_uuid"), d.get("channel", ""),
             d.get("address", ""), d.get("status", ""), d.get("provider_ref"),
             1 if d.get("sim") else 0))

    def recent_deliveries(self, limit=200):
        return self._all("SELECT * FROM deliveries ORDER BY id DESC LIMIT %d" % int(limit))

    def ack_delivery(self, ref):
        """A recipient confirms they actually received the notification (provider_ref =
        the receipt id in the message). Idempotent; only acks a ref that maps to a real
        delivery receipt, so a random ref can't inflate the reach number. True if acked."""
        ref = (ref or "").strip()
        if not ref:
            return False
        if self._one("SELECT ref FROM delivery_acks WHERE ref=?", (ref,)):
            return True
        if not self._one("SELECT id FROM deliveries WHERE provider_ref=?", (ref,)):
            return False
        self._insert("INSERT INTO delivery_acks (ref, acked_at) VALUES (?,?)", (ref, now_iso()))
        return True

    def delivery_ack_count(self):
        r = self._one("SELECT COUNT(*) AS c FROM delivery_acks")
        return (r["c"] if r else 0)

    def deliveries_for_alert(self, alert_key, limit=200):
        return self._all("SELECT * FROM deliveries WHERE alert_key=? ORDER BY id DESC LIMIT %d"
                         % int(limit), (alert_key,))

    def deliveries_for_sos(self, sos_uuid, limit=200):
        return self._all("SELECT * FROM deliveries WHERE sos_uuid=? ORDER BY id DESC LIMIT %d"
                         % int(limit), (sos_uuid,))

    # --- reputation (ABU-04) — upsert by opaque reporter_key ----------------
    def get_reporter_stat(self, reporter_key):
        if not reporter_key:
            return None
        return self._one("SELECT * FROM reporter_stats WHERE reporter_key=?", (reporter_key,))

    def upsert_reporter_stat(self, stat):
        """Insert or update a reporter_stats row from a dict produced by
        reputation.update_stat(). Keyed by reporter_key (PK). No raw PII stored."""
        key = stat.get("reporter_key")
        if not key:
            return
        existing = self._one("SELECT reporter_key FROM reporter_stats WHERE reporter_key=?", (key,))
        if existing:
            self._run(
                "UPDATE reporter_stats SET reports=?, verified=?, dismissed=?, score=?, updated_at=?"
                " WHERE reporter_key=?",
                (int(stat.get("reports", 0) or 0), int(stat.get("verified", 0) or 0),
                 int(stat.get("dismissed", 0) or 0), float(stat.get("score", 50.0) or 50.0),
                 stat.get("updated_at") or now_iso(), key))
        else:
            self._run(
                "INSERT INTO reporter_stats (reporter_key, reports, verified, dismissed, score, updated_at)"
                " VALUES (?,?,?,?,?,?)",
                (key, int(stat.get("reports", 0) or 0), int(stat.get("verified", 0) or 0),
                 int(stat.get("dismissed", 0) or 0), float(stat.get("score", 50.0) or 50.0),
                 stat.get("updated_at") or now_iso()))

    def record_reporter_outcome(self, reporter_key, outcome):
        """Convenience: load the current stat, apply one operator outcome
        (verified/dismissed) via reputation.update_stat, persist, return the new
        stat. No-op (returns None) if reputation.py is unavailable. Continuous-
        learning hook (DATA-11) driven from the verify decision."""
        if reputation is None or not reporter_key:
            return None
        cur = self.get_reporter_stat(reporter_key) or reputation.new_stat(reporter_key)
        new = reputation.update_stat(cur, outcome)
        self.upsert_reporter_stat(new)
        return new

    def all_reporter_stats(self, limit=500):
        return self._all("SELECT * FROM reporter_stats ORDER BY score ASC LIMIT %d" % int(limit))

    # --- geocode cache (GEO-02) — persist OSM hits across restarts ----------
    def get_geo_cache(self, query):
        if not query:
            return None
        return self._one("SELECT * FROM geo_cache WHERE query=?", (query.strip().lower(),))

    def put_geo_cache(self, query, lat, lng, source="", display="", confidence=""):
        """Upsert a geocode result keyed by the normalised query string."""
        if not query:
            return
        q = query.strip().lower()
        existing = self._one("SELECT query FROM geo_cache WHERE query=?", (q,))
        if existing:
            self._run(
                "UPDATE geo_cache SET lat=?, lng=?, source=?, display=?, confidence=?, ts=? WHERE query=?",
                (lat, lng, source, display, confidence, now_iso(), q))
        else:
            self._run(
                "INSERT INTO geo_cache (query, lat, lng, source, display, confidence, ts)"
                " VALUES (?,?,?,?,?,?,?)",
                (q, lat, lng, source, display, confidence, now_iso()))

    # --- source health (DATA-01 scheduler) ---------------------------------
    def record_source_run(self, source, ok=True, fetched=0, added=0, error=""):
        """Record one scheduled-ingest run for `source`, accumulating run/success/
        error counters and stamping the relevant timestamps. Upsert by source."""
        ts = now_iso()
        row = self._one("SELECT * FROM source_health WHERE source=?", (source,))
        if row:
            runs = int(row.get("runs", 0) or 0) + 1
            successes = int(row.get("successes", 0) or 0) + (1 if ok else 0)
            errors = int(row.get("errors", 0) or 0) + (0 if ok else 1)
            self._run(
                "UPDATE source_health SET last_run_at=?, last_success_at=?, last_error_at=?, last_error=?,"
                " runs=?, successes=?, errors=?, fetched=?, added=? WHERE source=?",
                (ts, ts if ok else row.get("last_success_at"),
                 row.get("last_error_at") if ok else ts,
                 "" if ok else (error or "")[:300],
                 runs, successes, errors,
                 int(row.get("fetched", 0) or 0) + int(fetched or 0),
                 int(row.get("added", 0) or 0) + int(added or 0), source))
        else:
            self._run(
                "INSERT INTO source_health (source, last_run_at, last_success_at, last_error_at, last_error,"
                " runs, successes, errors, fetched, added) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (source, ts, ts if ok else None, None if ok else ts,
                 "" if ok else (error or "")[:300],
                 1, 1 if ok else 0, 0 if ok else 1, int(fetched or 0), int(added or 0)))

    def source_health(self, limit=200):
        return self._all("SELECT * FROM source_health ORDER BY source LIMIT %d" % int(limit))

    # --- privacy retention / erasure support -------------------------------
    def retention_plan(self, apply=False):
        """Dry-run or apply conservative NDPA-style retention purges.

        Deletes only clearly stale operational exhaust by default. Case evidence,
        missing-person records, and verified incident history are deliberately not
        auto-deleted here; they need case-owner/operator policy decisions.
        """
        now = datetime.datetime.now()

        def days_env(name, default):
            try:
                return max(1, int(os.environ.get(name, str(default))))
            except Exception:
                return default

        policies = [
            {
                "name": "expired_otp_challenges",
                "table": "otp_challenges",
                "date_col": "expires_at",
                "days": days_env("DEYSAFE_RETENTION_OTP_DAYS", 2),
                "extra": "",
            },
            {
                "name": "expired_personal_sessions",
                "table": "personal_sessions",
                "date_col": "expires_at",
                "days": days_env("DEYSAFE_RETENTION_SESSION_DAYS", 45),
                "extra": "",
            },
            {
                "name": "old_delivery_receipts",
                "table": "deliveries",
                "date_col": "created_at",
                "days": days_env("DEYSAFE_RETENTION_DELIVERY_DAYS", 180),
                "extra": "",
            },
            {
                "name": "old_community_channel_posts",
                "table": "channel",
                "date_col": "created_at",
                "days": days_env("DEYSAFE_RETENTION_CHANNEL_DAYS", 90),
                "extra": "",
            },
            {
                "name": "old_journey_events",
                "table": "journey_events",
                "date_col": "created_at",
                "days": days_env("DEYSAFE_RETENTION_JOURNEY_EVENT_DAYS", 90),
                "extra": "",
            },
            {
                "name": "old_safemeet_checkins",
                "table": "safemeet_checkins",
                "date_col": "created_at",
                "days": days_env("DEYSAFE_RETENTION_SAFEMEET_CHECKIN_DAYS", 180),
                "extra": "",
            },
            {
                "name": "closed_sos_events",
                "table": "sos_events",
                "date_col": "updated_at",
                "days": days_env("DEYSAFE_RETENTION_CLOSED_SOS_DAYS", 180),
                "extra": " AND state IN ('SAFE','CLOSED')",
            },
        ]
        results = []
        total = 0
        for p in policies:
            cutoff = (now - datetime.timedelta(days=p["days"])).isoformat(timespec="seconds")
            where = "%s < ?%s" % (p["date_col"], p["extra"])
            try:
                row = self._one("SELECT COUNT(*) AS c FROM %s WHERE %s" % (p["table"], where), (cutoff,))
                count = int((row or {}).get("c") or 0)
                if apply and count:
                    self._run("DELETE FROM %s WHERE %s" % (p["table"], where), (cutoff,))
                results.append({"name": p["name"], "table": p["table"], "cutoff": cutoff,
                                "days": p["days"], "matched": count,
                                "deleted": count if apply else 0})
                total += count
            except Exception as e:
                results.append({"name": p["name"], "table": p["table"], "error": repr(e)[:160],
                                "matched": 0, "deleted": 0})
        return {"ok": True, "applied": bool(apply), "total_matched": total,
                "total_deleted": total if apply else 0, "policies": results}

    # ======================================================================
    # PRODUCT-SAFETY ACCESSORS
    # Journey Guard / readiness / SHIELD cases / restricted evidence /
    # Safety Points + Sentinel Network / Guardian Mesh / trackers / ops gaps.
    # ======================================================================

    def _uid(self):
        try:
            return security.new_uuid()
        except Exception:
            return _fallback_uuid()

    @staticmethod
    def _bool(v):
        return 1 if (safety.as_bool(v) if safety else bool(v)) else 0

    # --- Citizen identity / Safety Vault ------------------------------------
    def create_otp_challenge(self, phone):
        if identity is None:
            raise RuntimeError("identity module unavailable")
        p = identity.normalize_phone(phone)
        if not p or len(p) < 8:
            raise ValueError("valid phone required")
        ref = identity.new_id("otp")
        code = identity.otp_code()
        now = now_iso()
        exp = (datetime.datetime.now() + datetime.timedelta(minutes=identity.OTP_TTL_MINUTES)).isoformat(timespec="seconds")
        self._run(
            "INSERT INTO otp_challenges (otp_ref, phone_hash, phone_display, otp_hash, created_at, expires_at, attempts)"
            " VALUES (?,?,?,?,?,?,?)",
            (ref, identity.phone_hash(p), p, identity.otp_hash(ref, code), now, exp, 0))
        return {"otp_ref": ref, "code": code, "expires_at": exp, "phone": p}

    def consume_otp(self, otp_ref, code, first_name="", language="en", device_id=""):
        if identity is None:
            raise RuntimeError("identity module unavailable")
        ref = (otp_ref or "").strip()
        row = self._one("SELECT * FROM otp_challenges WHERE otp_ref=?", (ref,))
        if not row:
            return None, "invalid_otp"
        if row.get("consumed_at"):
            return None, "otp_used"
        exp = row.get("expires_at") or ""
        try:
            if datetime.datetime.now() > datetime.datetime.fromisoformat(exp):
                return None, "otp_expired"
        except Exception:
            return None, "otp_expired"
        attempts = int(row.get("attempts") or 0) + 1
        self._run("UPDATE otp_challenges SET attempts=? WHERE otp_ref=?", (attempts, ref))
        if attempts > 6:
            return None, "too_many_attempts"
        if not hmac.compare_digest(identity.otp_hash(ref, code), row.get("otp_hash") or ""):
            return None, "invalid_otp"
        now = now_iso()
        ph = row.get("phone_hash")
        user = self._one("SELECT * FROM citizen_users WHERE phone_hash=?", (ph,))
        if not user:
            user_uuid = identity.new_id("user")
            policy_id = identity.new_id("gp")
            self._run(
                "INSERT INTO citizen_users (user_uuid, phone_hash, phone_display, first_name, language,"
                " guardian_policy_id, created_at, verified_at, status) VALUES (?,?,?,?,?,?,?,?,?)",
                (user_uuid, ph, row.get("phone_display"), (first_name or "").strip()[:60],
                 (language or "en").strip()[:12], policy_id, now, now, "active"))
            user = self._one("SELECT * FROM citizen_users WHERE user_uuid=?", (user_uuid,))
        else:
            self._run("UPDATE citizen_users SET first_name=?, language=?, verified_at=?, status='active' WHERE user_uuid=?",
                      ((first_name or user.get("first_name") or "").strip()[:60],
                       (language or user.get("language") or "en").strip()[:12], now, user.get("user_uuid")))
            user = self._one("SELECT * FROM citizen_users WHERE user_uuid=?", (user.get("user_uuid"),))
        self._run("UPDATE otp_challenges SET consumed_at=? WHERE otp_ref=?", (now, ref))
        did = (device_id or identity.new_id("dev")).strip()[:80]
        token = identity.session_token(user.get("user_uuid"), did)
        payload = identity.parse_session_token(token) or {}
        self._run(
            "INSERT INTO personal_sessions (session_hash, user_uuid, device_id, created_at, expires_at, last_seen_at)"
            " VALUES (?,?,?,?,?,?)",
            (identity.session_hash(token), user.get("user_uuid"), did, now,
             datetime.datetime.fromtimestamp(int(payload.get("exp") or identity.utc_epoch())).isoformat(timespec="seconds"), now))
        return {"user": user, "session_token": token, "device_id": did}, ""

    def session_user(self, token):
        if identity is None:
            return None
        payload = identity.parse_session_token(token)
        if not payload:
            return None
        sh = identity.session_hash(token)
        row = self._one("SELECT * FROM personal_sessions WHERE session_hash=? AND revoked_at IS NULL", (sh,))
        if not row:
            return None
        try:
            if datetime.datetime.now() > datetime.datetime.fromisoformat(row.get("expires_at")):
                return None
        except Exception:
            return None
        user = self._one("SELECT * FROM citizen_users WHERE user_uuid=? AND status='active'", (payload.get("u"),))
        if not user:
            return None
        self._run("UPDATE personal_sessions SET last_seen_at=? WHERE session_hash=?", (now_iso(), sh))
        user["device_id"] = payload.get("d") or row.get("device_id")
        return user

    def set_user_pins(self, user_uuid, app_pin="", safety_pin="", duress_pin=""):
        if identity is None:
            return None
        row = self._one("SELECT * FROM user_pins WHERE user_uuid=?", (user_uuid,))
        vals = {
            "app_pin_hash": identity.pin_hash(user_uuid, app_pin, "app") if app_pin else (row or {}).get("app_pin_hash"),
            "safety_pin_hash": identity.pin_hash(user_uuid, safety_pin, "safety") if safety_pin else (row or {}).get("safety_pin_hash"),
            "duress_pin_hash": identity.pin_hash(user_uuid, duress_pin, "duress") if duress_pin else (row or {}).get("duress_pin_hash"),
        }
        if row:
            self._run("UPDATE user_pins SET app_pin_hash=?, safety_pin_hash=?, duress_pin_hash=?, updated_at=? WHERE user_uuid=?",
                      (vals["app_pin_hash"], vals["safety_pin_hash"], vals["duress_pin_hash"], now_iso(), user_uuid))
        else:
            self._run("INSERT INTO user_pins (user_uuid, app_pin_hash, safety_pin_hash, duress_pin_hash, updated_at)"
                      " VALUES (?,?,?,?,?)",
                      (user_uuid, vals["app_pin_hash"], vals["safety_pin_hash"], vals["duress_pin_hash"], now_iso()))
        return self._one("SELECT * FROM user_pins WHERE user_uuid=?", (user_uuid,))

    def classify_pin(self, user_uuid, pin):
        if identity is None:
            return ""
        row = self._one("SELECT * FROM user_pins WHERE user_uuid=?", (user_uuid,))
        if not row:
            return ""
        if identity.verify_pin(user_uuid, pin, row.get("duress_pin_hash"), "duress"):
            return "duress"
        if identity.verify_pin(user_uuid, pin, row.get("safety_pin_hash"), "safety"):
            return "safety"
        if identity.verify_pin(user_uuid, pin, row.get("app_pin_hash"), "app"):
            return "app"
        return ""

    def guardian_count(self, user_uuid=None, owner_token=None):
        if user_uuid:
            r = self._one("SELECT COUNT(*) AS c FROM guardian_contacts WHERE user_uuid=? AND active=1", (user_uuid,))
            return int((r or {}).get("c") or 0)
        if owner_token:
            return len(self.trusted_for(owner_token))
        return 0

    def add_guardian(self, user_uuid, policy_id, name, channel, address):
        if identity is None:
            return None
        gid = identity.new_id("guard")
        now = now_iso()
        addr = (address or "").strip()[:120]
        cipher = identity.encrypt_secret(addr, aad=gid)
        verify_ref = identity.new_id("gv")
        verify_code = identity.otp_code()
        self._run(
            "INSERT INTO guardian_contacts (guardian_uuid, user_uuid, policy_id, name, channel, address,"
            " address_ciphertext, address_hash, verification_ref, verification_hash, verified, active, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (gid, user_uuid, policy_id, (name or "Guardian").strip()[:80],
             (channel or "sms").strip()[:24], "", cipher, identity.hmac_hex("guardian", addr),
             verify_ref, identity.otp_hash(verify_ref, verify_code), 0, 1, now, now))
        row = self._one("SELECT * FROM guardian_contacts WHERE guardian_uuid=?", (gid,))
        if row:
            row["verification_code"] = verify_code
        return row

    def list_guardians(self, user_uuid):
        return self._all("SELECT * FROM guardian_contacts WHERE user_uuid=? AND active=1 ORDER BY id", (user_uuid,))

    def verify_guardian(self, user_uuid, guardian_uuid, code):
        if identity is None:
            return None
        gid = (guardian_uuid or "").strip()
        row = self._one(
            "SELECT * FROM guardian_contacts WHERE user_uuid=? AND guardian_uuid=? AND active=1",
            (user_uuid, gid))
        if not row:
            return None
        ref = row.get("verification_ref") or ""
        expected = row.get("verification_hash") or ""
        if not ref or not expected:
            return None
        if not hmac.compare_digest(identity.otp_hash(ref, code), expected):
            return None
        self._run("UPDATE guardian_contacts SET verified=1, verified_at=?, updated_at=? WHERE guardian_uuid=?",
                  (now_iso(), now_iso(), gid))
        return self._one("SELECT * FROM guardian_contacts WHERE guardian_uuid=?", (gid,))

    def guardian_targets_for_policy(self, policy_id):
        rows = self._all("SELECT * FROM guardian_contacts WHERE policy_id=? AND active=1 ORDER BY id", (policy_id,))
        out = []
        for r in rows:
            addr = identity.guardian_address(r) if identity else (r.get("address") or "")
            if addr:
                out.append({"address": addr, "channel": r.get("channel") or "sms",
                            "verified": bool(r.get("verified"))})
        return out

    def upsert_push_subscription(self, user_uuid, device_id, subscription):
        if identity is None:
            return None
        raw = json.dumps(subscription or {}, sort_keys=True, separators=(",", ":"))
        endpoint = (subscription or {}).get("endpoint") or ""
        eh = identity.hmac_hex("push", endpoint or raw)
        existing = self._one("SELECT * FROM push_subscriptions WHERE user_uuid=? AND endpoint_hash=?", (user_uuid, eh))
        now = now_iso()
        if existing:
            self._run("UPDATE push_subscriptions SET subscription_json=?, device_id=?, status='registered' WHERE id=?",
                      (raw, device_id, existing.get("id")))
            return self._one("SELECT * FROM push_subscriptions WHERE id=?", (existing.get("id"),))
        sid = identity.new_id("push")
        self._run(
            "INSERT INTO push_subscriptions (sub_uuid, user_uuid, device_id, endpoint_hash, subscription_json, created_at, status)"
            " VALUES (?,?,?,?,?,?,?)",
            (sid, user_uuid, device_id, eh, raw, now, "registered"))
        return self._one("SELECT * FROM push_subscriptions WHERE sub_uuid=?", (sid,))

    def mark_push_test(self, sub_uuid, confirmed=False, status="test_sent"):
        col = "last_confirmed_at" if confirmed else "last_test_at"
        self._run("UPDATE push_subscriptions SET %s=?, status=? WHERE sub_uuid=?" % col,
                  (now_iso(), status, sub_uuid))
        return self._one("SELECT * FROM push_subscriptions WHERE sub_uuid=?", (sub_uuid,))

    def add_mysafe_place(self, user_uuid, alias, place, lat=None, lng=None):
        pid = identity.new_id("place") if identity else self._uid()
        self._run("INSERT INTO mysafe_places (place_uuid, user_uuid, alias, place, lat, lng, created_at, active)"
                  " VALUES (?,?,?,?,?,?,?,1)",
                  (pid, user_uuid, (alias or "").strip()[:40], (place or "").strip()[:160], lat, lng, now_iso()))
        return self._one("SELECT * FROM mysafe_places WHERE place_uuid=?", (pid,))

    def list_mysafe_places(self, user_uuid):
        return self._all("SELECT * FROM mysafe_places WHERE user_uuid=? AND active=1 ORDER BY id", (user_uuid,))

    def add_mysafe_route(self, user_uuid, origin_alias, destination_alias, days, departure_window, expected_arrival, escalation_policy="guardian"):
        rid = identity.new_id("route") if identity else self._uid()
        self._run("INSERT INTO mysafe_routes (route_uuid, user_uuid, origin_alias, destination_alias, days,"
                  " departure_window, expected_arrival, escalation_policy, created_at, active)"
                  " VALUES (?,?,?,?,?,?,?,?,?,1)",
                  (rid, user_uuid, (origin_alias or "").strip()[:40], (destination_alias or "").strip()[:40],
                   (days or "").strip()[:80], (departure_window or "").strip()[:40],
                   (expected_arrival or "").strip()[:40], (escalation_policy or "guardian").strip()[:40], now_iso()))
        return self._one("SELECT * FROM mysafe_routes WHERE route_uuid=?", (rid,))

    def list_mysafe_routes(self, user_uuid):
        return self._all("SELECT * FROM mysafe_routes WHERE user_uuid=? AND active=1 ORDER BY id", (user_uuid,))

    def beacon_nonce_seen(self, nonce):
        if not nonce:
            return False
        return self._one("SELECT nonce FROM beacon_nonces WHERE nonce=?", (nonce,)) is not None

    def remember_beacon_nonce(self, nonce, beacon_id=""):
        if not nonce:
            return
        try:
            self._run("INSERT INTO beacon_nonces (nonce, beacon_id, seen_at) VALUES (?,?,?)",
                      (str(nonce).strip()[:120], str(beacon_id or "").strip()[:120], now_iso()))
        except Exception:
            pass

    # --- Phone Safety Readiness --------------------------------------------
    def upsert_readiness(self, owner_token, data):
        owner = (owner_token or "").strip()
        if not owner:
            raise ValueError("owner_token required")
        trusted = 0
        try:
            trusted = len(self.trusted_for(owner))
        except Exception:
            trusted = 0
        checks, score, gaps = safety.readiness_from(data or {}, trusted) if safety else ({}, 0, [])
        now = now_iso()
        row = self._one("SELECT owner_token FROM safety_readiness WHERE owner_token=?", (owner,))
        vals = {
            "platform": (data.get("platform") or "").strip() if isinstance(data, dict) else "",
            "findmy_enabled": self._bool(checks.get("findmy_enabled")),
            "findhub_enabled": self._bool(checks.get("findhub_enabled")),
            "trusted_contacts": int(checks.get("trusted_contacts") or 0),
            "silent_sos": self._bool(checks.get("silent_sos")),
            "sms_fallback": self._bool(checks.get("sms_fallback")),
            "wearable": self._bool(checks.get("wearable")),
            "offline_pack": self._bool(checks.get("offline_pack")),
            "readiness_score": int(score),
            "gaps": json.dumps(gaps),
            "notes": (data.get("notes") or "").strip()[:500] if isinstance(data, dict) else "",
        }
        if row:
            self._run(
                "UPDATE safety_readiness SET updated_at=?, platform=?, findmy_enabled=?, findhub_enabled=?,"
                " trusted_contacts=?, silent_sos=?, sms_fallback=?, wearable=?, offline_pack=?,"
                " readiness_score=?, gaps=?, notes=? WHERE owner_token=?",
                (now, vals["platform"], vals["findmy_enabled"], vals["findhub_enabled"],
                 vals["trusted_contacts"], vals["silent_sos"], vals["sms_fallback"],
                 vals["wearable"], vals["offline_pack"], vals["readiness_score"],
                 vals["gaps"], vals["notes"], owner))
        else:
            self._run(
                "INSERT INTO safety_readiness (owner_token, created_at, updated_at, platform,"
                " findmy_enabled, findhub_enabled, trusted_contacts, silent_sos, sms_fallback,"
                " wearable, offline_pack, readiness_score, gaps, notes)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (owner, now, now, vals["platform"], vals["findmy_enabled"],
                 vals["findhub_enabled"], vals["trusted_contacts"], vals["silent_sos"],
                 vals["sms_fallback"], vals["wearable"], vals["offline_pack"],
                 vals["readiness_score"], vals["gaps"], vals["notes"]))
        return self.readiness_for(owner)

    def readiness_for(self, owner_token):
        row = self._one("SELECT * FROM safety_readiness WHERE owner_token=?", ((owner_token or "").strip(),))
        if not row:
            return None
        try:
            row["gaps"] = json.loads(row.get("gaps") or "[]")
        except Exception:
            row["gaps"] = []
        return row

    # --- Journey Guard ------------------------------------------------------
    def create_journey(self, d):
        jid = d.get("journey_uuid") or self._uid()
        existing = self._one("SELECT * FROM journey_sessions WHERE journey_uuid=?", (jid,))
        if existing:
            return existing
        now = now_iso()
        ref = d.get("handoff_ref") or self.new_ref("JG")
        self._run(
            "INSERT INTO journey_sessions (journey_uuid, owner_token, created_at, updated_at,"
            " started_at, expected_arrival, from_place, to_place, from_lat, from_lng,"
            " to_lat, to_lng, mode, state, risk_level, anomaly_level, anomaly_reason,"
            " handoff_ref, share_consent) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (jid, (d.get("owner_token") or "").strip(), now, now, d.get("started_at") or now,
             d.get("expected_arrival"), d.get("from_place") or "", d.get("to_place") or "",
             d.get("from_lat"), d.get("from_lng"), d.get("to_lat"), d.get("to_lng"),
             d.get("mode") or "journey_guard", d.get("state") or "active",
             d.get("risk_level") or "GREEN", d.get("anomaly_level") or "normal",
             d.get("anomaly_reason") or "", ref, self._bool(d.get("share_consent"))))
        return self.journey_by_uuid(jid)

    def journey_by_uuid(self, journey_uuid):
        if not journey_uuid:
            return None
        return self._one("SELECT * FROM journey_sessions WHERE journey_uuid=?", (journey_uuid,))

    def list_journeys(self, limit=200):
        return self._all("SELECT * FROM journey_sessions ORDER BY id DESC LIMIT %d" % int(limit))

    def journey_events(self, journey_uuid, limit=100):
        return self._all("SELECT * FROM journey_events WHERE journey_uuid=? ORDER BY id DESC LIMIT %d" % int(limit),
                         (journey_uuid,))

    def record_journey_event(self, journey_uuid, d):
        row = self.journey_by_uuid(journey_uuid)
        if not row:
            return None
        now = now_iso()
        level, reason, state = safety.assess_journey(row, d) if safety else ("normal", "", row.get("state") or "active")
        etype = (d.get("event_type") or d.get("type") or "checkin").strip().lower()
        lat = d.get("lat")
        lng = d.get("lng")
        try:
            lat = float(lat) if lat is not None else None
            lng = float(lng) if lng is not None else None
        except Exception:
            lat = lng = None
        self._run(
            "INSERT INTO journey_events (journey_uuid, created_at, event_type, state, lat, lng,"
            " speed, heading, battery, network, note, anomaly_level, anomaly_reason)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (journey_uuid, now, etype, state, lat, lng, d.get("speed"), d.get("heading"),
             d.get("battery"), (d.get("network") or "").strip(), (d.get("note") or "").strip()[:500],
             level, reason))
        sets = ["updated_at=?", "last_packet_at=?", "state=?", "anomaly_level=?", "anomaly_reason=?"]
        params = [now, now, state, level, reason]
        if etype in ("checkin", "arrived", "manual_checkin"):
            sets.append("last_checkin_at=?")
            params.append(now)
        for col, val in (("last_lat", lat), ("last_lng", lng), ("last_speed", d.get("speed")),
                         ("last_heading", d.get("heading")), ("last_battery", d.get("battery")),
                         ("last_network", (d.get("network") or "").strip())):
            if val is not None and val != "":
                sets.append(col + "=?")
                params.append(val)
        params.append(journey_uuid)
        self._run("UPDATE journey_sessions SET %s WHERE journey_uuid=?" % ", ".join(sets), tuple(params))
        return self.journey_by_uuid(journey_uuid)

    def close_journey(self, journey_uuid, state="arrived"):
        self._run("UPDATE journey_sessions SET state=?, updated_at=?, anomaly_level=?, anomaly_reason=? WHERE journey_uuid=?",
                  (state, now_iso(), "normal", "", journey_uuid))
        return self.journey_by_uuid(journey_uuid)

    def set_journey_anomaly(self, journey_uuid, level, reason, state=None):
        sets = ["updated_at=?", "anomaly_level=?", "anomaly_reason=?"]
        vals = [now_iso(), level, reason]
        if state:
            sets.append("state=?")
            vals.append(state)
        vals.append(journey_uuid)
        self._run("UPDATE journey_sessions SET %s WHERE journey_uuid=?" % ", ".join(sets), vals)
        return self.journey_by_uuid(journey_uuid)

    def active_journeys(self, limit=500):
        return self._all(
            "SELECT * FROM journey_sessions WHERE state NOT IN ('arrived','closed','cancelled','CLOSED_VERIFIED')"
            " ORDER BY id DESC LIMIT %d" % int(limit))

    # --- SHIELD case workspace ---------------------------------------------
    def create_shield_case(self, d):
        cid = d.get("case_uuid") or self._uid()
        now = now_iso()
        existing = self._one("SELECT * FROM shield_cases WHERE case_uuid=?", (cid,))
        if existing:
            return existing
        self._run(
            "INSERT INTO shield_cases (case_uuid, created_at, updated_at, last_update_at, case_type,"
            " subject_ref, status, visibility, family_liaison, incident_commander, analyst_owner,"
            " summary, public_note, requires_second_approval) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cid, now, now, now, (d.get("case_type") or "incident").strip(),
             (d.get("subject_ref") or "").strip(), (d.get("status") or "open").strip(),
             (d.get("visibility") or "restricted").strip(),
             (d.get("family_liaison") or "").strip(), (d.get("incident_commander") or "").strip(),
             (d.get("analyst_owner") or "").strip(), (d.get("summary") or "").strip()[:1000],
             (d.get("public_note") or "").strip()[:500],
             self._bool(d.get("requires_second_approval"))))
        return self.shield_case(cid)

    def shield_case(self, case_uuid):
        if not case_uuid:
            return None
        return self._one("SELECT * FROM shield_cases WHERE case_uuid=?", (case_uuid,))

    def shield_cases(self, limit=200):
        return self._all("SELECT * FROM shield_cases ORDER BY id DESC LIMIT %d" % int(limit))

    def add_case_update(self, case_uuid, d):
        if not self.shield_case(case_uuid):
            return None
        now = now_iso()
        self._run(
            "INSERT INTO case_updates (case_uuid, created_at, actor, visibility, body, redacted)"
            " VALUES (?,?,?,?,?,?)",
            (case_uuid, now, (d.get("actor") or "").strip(), (d.get("visibility") or "restricted").strip(),
             (d.get("body") or d.get("note") or "").strip()[:2000], self._bool(d.get("redacted"))))
        self._run("UPDATE shield_cases SET updated_at=?, last_update_at=? WHERE case_uuid=?",
                  (now, now, case_uuid))
        return self.case_updates(case_uuid)

    def case_updates(self, case_uuid, limit=100):
        return self._all("SELECT * FROM case_updates WHERE case_uuid=? ORDER BY id DESC LIMIT %d" % int(limit),
                         (case_uuid,))

    # --- Restricted evidence + GeoTrace -------------------------------------
    def create_evidence(self, d):
        eid = d.get("evidence_uuid") or self._uid()
        now = now_iso()
        prev = ""
        try:
            row = self._one("SELECT custody_hash FROM evidence_items ORDER BY id DESC LIMIT 1")
            prev = (row or {}).get("custody_hash") or ""
        except Exception:
            prev = ""
        payload = {
            "evidence_uuid": eid,
            "case_uuid": d.get("case_uuid") or "",
            "title": d.get("title") or "",
            "source_label": d.get("source_label") or "",
            "created_at": now,
        }
        custody = security.audit_hash(prev, payload) if security else _fallback_hash(prev, payload)
        self._run(
            "INSERT INTO evidence_items (evidence_uuid, case_uuid, created_at, updated_at, evidence_type,"
            " title, source_label, custody_hash, prev_hash, restricted_level, status, lat, lng,"
            " captured_at, notes, public_summary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, d.get("case_uuid") or "", now, now, (d.get("evidence_type") or "note").strip(),
             (d.get("title") or "").strip()[:200], (d.get("source_label") or "").strip()[:120],
             custody, prev, (d.get("restricted_level") or "restricted").strip(),
             (d.get("status") or "received").strip(), d.get("lat"), d.get("lng"),
             d.get("captured_at"), (d.get("notes") or "").strip()[:2000],
             (d.get("public_summary") or "").strip()[:500]))
        return self.evidence_by_uuid(eid)

    def evidence_by_uuid(self, evidence_uuid):
        return self._one("SELECT * FROM evidence_items WHERE evidence_uuid=?", (evidence_uuid,))

    def evidence_for_case(self, case_uuid, limit=100):
        return self._all("SELECT * FROM evidence_items WHERE case_uuid=? ORDER BY id DESC LIMIT %d" % int(limit),
                         (case_uuid,))

    def all_evidence(self, limit=200):
        return self._all("SELECT * FROM evidence_items ORDER BY id DESC LIMIT %d" % int(limit))

    def create_geotrace(self, d):
        tid = d.get("trace_uuid") or self._uid()
        self._run(
            "INSERT INTO geotrace_annotations (trace_uuid, evidence_uuid, case_uuid, created_at,"
            " actor, confidence, method, area_label, lat, lng, radius_km, notes, restricted)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, d.get("evidence_uuid") or "", d.get("case_uuid") or "", now_iso(),
             (d.get("actor") or "").strip(), (d.get("confidence") or "low").strip(),
             (d.get("method") or "analyst_annotation").strip(),
             (d.get("area_label") or "").strip()[:200], d.get("lat"), d.get("lng"),
             d.get("radius_km"), (d.get("notes") or "").strip()[:2000],
             self._bool(True if d.get("restricted") is None else d.get("restricted"))))
        return self._one("SELECT * FROM geotrace_annotations WHERE trace_uuid=?", (tid,))

    def geotraces_for_case(self, case_uuid, limit=100):
        return self._all("SELECT * FROM geotrace_annotations WHERE case_uuid=? ORDER BY id DESC LIMIT %d" % int(limit),
                         (case_uuid,))

    # --- Safety Points + Sentinel Network -----------------------------------
    def create_safety_point(self, d):
        pid = d.get("point_uuid") or self._uid()
        now = now_iso()
        self._run(
            "INSERT INTO safety_points (point_uuid, created_at, updated_at, name, point_type, state,"
            " lga, address, lat, lng, contact_channel, contact_address, vetted, active,"
            " verified_by, last_verified_at, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, now, now, (d.get("name") or "").strip(), (d.get("point_type") or "safe_point").strip(),
             (d.get("state") or "").strip(), (d.get("lga") or "").strip(),
             (d.get("address") or "").strip(), d.get("lat"), d.get("lng"),
             (d.get("contact_channel") or "").strip(), (d.get("contact_address") or "").strip(),
             self._bool(d.get("vetted")), self._bool(True if d.get("active") is None else d.get("active")),
             (d.get("verified_by") or "").strip(), d.get("last_verified_at") or now,
             (d.get("notes") or "").strip()[:1000]))
        return self._one("SELECT * FROM safety_points WHERE point_uuid=?", (pid,))

    def public_safety_points(self, limit=200):
        return self._all("SELECT * FROM safety_points WHERE vetted=1 AND active=1 ORDER BY id DESC LIMIT %d" % int(limit))

    def all_safety_points(self, limit=500):
        return self._all("SELECT * FROM safety_points ORDER BY id DESC LIMIT %d" % int(limit))

    def create_sentinel(self, d):
        sid = d.get("sentinel_uuid") or self._uid()
        now = now_iso()
        self._run(
            "INSERT INTO sentinels (sentinel_uuid, created_at, updated_at, name, org, role, state,"
            " lga, trust_level, active, consent_revoked_at, channel, address, last_checkin_at, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, now, now, (d.get("name") or "").strip(), (d.get("org") or "").strip(),
             (d.get("role") or "observer").strip(), (d.get("state") or "").strip(),
             (d.get("lga") or "").strip(), (d.get("trust_level") or "pending").strip(),
             self._bool(True if d.get("active") is None else d.get("active")),
             d.get("consent_revoked_at"), (d.get("channel") or "").strip(),
             (d.get("address") or "").strip(), d.get("last_checkin_at"),
             (d.get("notes") or "").strip()[:1000]))
        return self._one("SELECT * FROM sentinels WHERE sentinel_uuid=?", (sid,))

    def sentinels(self, limit=500):
        return self._all("SELECT * FROM sentinels ORDER BY id DESC LIMIT %d" % int(limit))

    # --- Guardian Mesh + trackers ------------------------------------------
    def create_mesh_device(self, d):
        did = d.get("device_uuid") or self._uid()
        now = now_iso()
        self._run(
            "INSERT INTO mesh_devices (device_uuid, owner_token, created_at, updated_at, device_label,"
            " consent_scope, rotating_id, active, revoked_at, last_seen_at, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (did, (d.get("owner_token") or "").strip(), now, now,
             (d.get("device_label") or "").strip(), (d.get("consent_scope") or "trusted_circle").strip(),
             (d.get("rotating_id") or "").strip(),
             self._bool(True if d.get("active") is None else d.get("active")),
             d.get("revoked_at"), d.get("last_seen_at"), (d.get("notes") or "").strip()[:1000]))
        return self._one("SELECT * FROM mesh_devices WHERE device_uuid=?", (did,))

    def mesh_devices(self, limit=500):
        return self._all("SELECT * FROM mesh_devices ORDER BY id DESC LIMIT %d" % int(limit))

    def record_mesh_relay(self, d):
        rid = d.get("relay_uuid") or self._uid()
        self._run(
            "INSERT INTO mesh_relays (relay_uuid, created_at, device_uuid, relay_type, rotating_id,"
            " lat, lng, sig_status, accepted, reason) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (rid, now_iso(), d.get("device_uuid") or "", (d.get("relay_type") or "nearby").strip(),
             (d.get("rotating_id") or "").strip(), d.get("lat"), d.get("lng"),
             (d.get("sig_status") or "unsigned").strip(), self._bool(d.get("accepted")),
             (d.get("reason") or "").strip()[:300]))
        return self._one("SELECT * FROM mesh_relays WHERE relay_uuid=?", (rid,))

    def mesh_relays(self, limit=500):
        return self._all("SELECT * FROM mesh_relays ORDER BY id DESC LIMIT %d" % int(limit))

    def create_tracker(self, d):
        tid = d.get("tracker_uuid") or self._uid()
        stable = (d.get("stable_id") or d.get("stable_id_hash") or "").strip()
        if stable and len(stable) != 64:
            stable = hashlib.sha256(stable.encode("utf-8")).hexdigest()
        now = now_iso()
        self._run(
            "INSERT INTO tracker_devices (tracker_uuid, created_at, updated_at, owner_ref, label,"
            " tracker_type, stable_id_hash, rotating_id, consent_status, anti_stalking_notice,"
            " active, revoked_at, last_seen_at, last_lat, last_lng, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, now, now, (d.get("owner_ref") or "").strip(), (d.get("label") or "").strip(),
             (d.get("tracker_type") or "tag").strip(), stable, (d.get("rotating_id") or "").strip(),
             (d.get("consent_status") or "active").strip(),
             self._bool(True if d.get("anti_stalking_notice") is None else d.get("anti_stalking_notice")),
             self._bool(True if d.get("active") is None else d.get("active")),
             d.get("revoked_at"), d.get("last_seen_at"), d.get("last_lat"), d.get("last_lng"),
             (d.get("notes") or "").strip()[:1000]))
        return self._one("SELECT * FROM tracker_devices WHERE tracker_uuid=?", (tid,))

    def trackers(self, limit=500):
        return self._all("SELECT * FROM tracker_devices ORDER BY id DESC LIMIT %d" % int(limit))

    # --- Operational weak-spot records --------------------------------------
    def create_ops_agreement(self, d):
        aid = d.get("agreement_uuid") or self._uid()
        now = now_iso()
        self._run(
            "INSERT INTO ops_agreements (agreement_uuid, created_at, updated_at, partner_name,"
            " partner_type, state, lga, scope, escalation_channel, status, signed_at, expires_at,"
            " owner, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, now, now, (d.get("partner_name") or "").strip(),
             (d.get("partner_type") or "responder").strip(), (d.get("state") or "").strip(),
             (d.get("lga") or "").strip(), (d.get("scope") or "").strip(),
             (d.get("escalation_channel") or "").strip(), (d.get("status") or "draft").strip(),
             d.get("signed_at"), d.get("expires_at"), (d.get("owner") or "").strip(),
             (d.get("notes") or "").strip()[:1000]))
        return self._one("SELECT * FROM ops_agreements WHERE agreement_uuid=?", (aid,))

    def ops_agreements(self, limit=500):
        return self._all("SELECT * FROM ops_agreements ORDER BY id DESC LIMIT %d" % int(limit))

    def create_ops_drill(self, d):
        did = d.get("drill_uuid") or self._uid()
        self._run(
            "INSERT INTO ops_drills (drill_uuid, created_at, drill_type, state, lga, participants,"
            " outcome, gaps, next_due_at, owner) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (did, now_iso(), (d.get("drill_type") or "tabletop").strip(),
             (d.get("state") or "").strip(), (d.get("lga") or "").strip(),
             (d.get("participants") or "").strip()[:1000], (d.get("outcome") or "").strip()[:1000],
             (d.get("gaps") or "").strip()[:1000], d.get("next_due_at"), (d.get("owner") or "").strip()))
        return self._one("SELECT * FROM ops_drills WHERE drill_uuid=?", (did,))

    def ops_drills(self, limit=500):
        return self._all("SELECT * FROM ops_drills ORDER BY id DESC LIMIT %d" % int(limit))

    # ========================================================================
    # Phase 4: SafeMeet - High-Risk Meeting Protection
    # ========================================================================
    
    def insert_safemeet_session(self, d):
        """Create a new SafeMeet session for high-risk meeting protection."""
        session_uuid = d.get("session_uuid") or self._uid()
        owner_token = d.get("owner_token", "")
        
        # Calculate risk level if not provided
        risk_level = d.get("risk_level")
        if not risk_level and safety:
            risk_level = safety.calculate_meeting_risk(
                d.get("meeting_type", ""),
                d.get("meeting_lat"),
                d.get("meeting_lng"),
                d.get("expected_arrival")
            )
        
        # Hash PINs if provided
        safe_pin_hash = None
        duress_pin_hash = None
        if d.get("safe_pin"):
            safe_pin_hash = hashlib.sha256(str(d["safe_pin"]).encode("utf-8")).hexdigest()
        if d.get("duress_pin"):
            duress_pin_hash = hashlib.sha256(str(d["duress_pin"]).encode("utf-8")).hexdigest()
        
        self._run(
            """INSERT INTO safemeet_sessions (
                session_uuid, owner_token, created_at, updated_at,
                meeting_type, risk_level,
                meeting_place, meeting_address, meeting_lat, meeting_lng,
                contact_name, contact_phone, contact_photo_url, contact_social_profile,
                vehicle_description, license_plate,
                expected_arrival, expected_departure,
                checkin_interval_minutes, next_checkin_due,
                state, safe_pin_hash, duress_pin_hash,
                user_notes
            ) VALUES (?,?, ?,?, ?,?, ?,?,?,?, ?,?,?,?, ?,?, ?,?, ?,?, ?,?,?, ?)""",
            (session_uuid, owner_token, now_iso(), now_iso(),
             (d.get("meeting_type") or "").strip(), risk_level or "medium",
             (d.get("meeting_place") or "").strip(), (d.get("meeting_address") or "").strip(),
             d.get("meeting_lat"), d.get("meeting_lng"),
             (d.get("contact_name") or "").strip(), (d.get("contact_phone") or "").strip(),
             (d.get("contact_photo_url") or "").strip(), (d.get("contact_social_profile") or "").strip(),
             (d.get("vehicle_description") or "").strip(), (d.get("license_plate") or "").strip(),
             d.get("expected_arrival"), d.get("expected_departure"),
             int(d.get("checkin_interval_minutes") or 30), d.get("next_checkin_due"),
             "scheduled", safe_pin_hash, duress_pin_hash,
             (d.get("user_notes") or "").strip())
        )
        return self._one("SELECT * FROM safemeet_sessions WHERE session_uuid=?", (session_uuid,))
    
    def get_safemeet_session(self, session_uuid):
        """Get a SafeMeet session by UUID."""
        return self._one("SELECT * FROM safemeet_sessions WHERE session_uuid=?", (session_uuid,))
    
    def get_safemeet_session_by_token(self, owner_token, limit=50):
        """Get all SafeMeet sessions for an owner."""
        return self._all(
            "SELECT * FROM safemeet_sessions WHERE owner_token=? ORDER BY id DESC LIMIT ?",
            (owner_token, int(limit))
        )

    def active_safemeets(self, limit=500):
        return self._all(
            "SELECT * FROM safemeet_sessions WHERE state NOT IN ('completed','cancelled','closed')"
            " ORDER BY id DESC LIMIT %d" % int(limit))
    
    def update_safemeet_session(self, session_uuid, updates):
        """Update a SafeMeet session (check-ins, state changes, anomalies)."""
        sets = []
        vals = []
        
        if "state" in updates:
            sets.append("state=?")
            vals.append(updates["state"])
        if "actual_arrival" in updates:
            sets.append("actual_arrival=?")
            vals.append(updates["actual_arrival"])
        if "actual_departure" in updates:
            sets.append("actual_departure=?")
            vals.append(updates["actual_departure"])
        if "last_checkin_at" in updates:
            sets.append("last_checkin_at=?")
            vals.append(updates["last_checkin_at"])
        if "next_checkin_due" in updates:
            sets.append("next_checkin_due=?")
            vals.append(updates["next_checkin_due"])
        if "missed_checkins" in updates:
            sets.append("missed_checkins=?")
            vals.append(updates["missed_checkins"])
        if "location_changed" in updates:
            sets.append("location_changed=?")
            vals.append(1 if updates["location_changed"] else 0)
        if "route_deviation" in updates:
            sets.append("route_deviation=?")
            vals.append(1 if updates["route_deviation"] else 0)
        if "phone_off_suddenly" in updates:
            sets.append("phone_off_suddenly=?")
            vals.append(1 if updates["phone_off_suddenly"] else 0)
        if "duress_triggered" in updates:
            sets.append("duress_triggered=?")
            sets.append("duress_trigger_time=?")
            vals.append(1 if updates["duress_triggered"] else 0)
            vals.append(now_iso() if updates["duress_triggered"] else None)
        if "escalated_at" in updates:
            sets.append("escalated_at=?")
            vals.append(updates["escalated_at"])
        if "escalation_reason" in updates:
            sets.append("escalation_reason=?")
            vals.append(updates["escalation_reason"])
        if "system_notes" in updates:
            sets.append("system_notes=?")
            vals.append(updates["system_notes"])
        
        if sets:
            sets.append("updated_at=?")
            vals.append(now_iso())
            vals.append(session_uuid)
            self._run(
                "UPDATE safemeet_sessions SET %s WHERE session_uuid=?" % ", ".join(sets),
                vals
            )
        return self._one("SELECT * FROM safemeet_sessions WHERE session_uuid=?", (session_uuid,))
    
    def insert_safemeet_checkin(self, d):
        """Record a SafeMeet check-in."""
        checkin_uuid = d.get("checkin_uuid") or self._uid()
        session_id = d.get("session_id")
        
        self._run(
            """INSERT INTO safemeet_checkins (
                session_id, checkin_uuid, ts, checkin_type,
                lat, lng, location_accuracy, battery_level, network_type,
                note, duress_flag, photo_url
            ) VALUES (?, ?,?, ?,?, ?,?,?, ?,?,?, ?)""",
            (session_id, checkin_uuid, now_iso(), (d.get("checkin_type") or "manual").strip(),
             d.get("lat"), d.get("lng"), d.get("location_accuracy"),
             d.get("battery_level"), (d.get("network_type") or "").strip(),
             (d.get("note") or "").strip(), 1 if d.get("duress_flag") else 0,
             (d.get("photo_url") or "").strip())
        )
        
        # Update session's last_checkin_at and next_checkin_due
        if session_id:
            session = self._one("SELECT * FROM safemeet_sessions WHERE id=?", (session_id,))
            if session and safety:
                interval = session.get("checkin_interval_minutes") or 30
                from datetime import datetime, timedelta
                next_due = datetime.now() + timedelta(minutes=interval)
                self.update_safemeet_session(
                    session.get("session_uuid"),
                    {
                        "last_checkin_at": now_iso(),
                        "next_checkin_due": next_due.isoformat(timespec="seconds")
                    }
                )
        
        return self._one("SELECT * FROM safemeet_checkins WHERE checkin_uuid=?", (checkin_uuid,))
    
    def get_safemeet_checkins(self, session_uuid, limit=100):
        """Get check-ins for a SafeMeet session."""
        return self._all(
            """SELECT c.* FROM safemeet_checkins c
               JOIN safemeet_sessions s ON c.session_id = s.id
               WHERE s.session_uuid=? ORDER BY c.id DESC LIMIT ?""",
            (session_uuid, int(limit))
        )
