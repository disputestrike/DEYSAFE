"""Product-safety layer for DeySafe / SHIELD.

This module is intentionally pure: DDL strings plus small scoring/projection
helpers. The API decides auth policy; db.py owns persistence.
"""
import datetime


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def as_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v or "").strip().lower() in ("1", "true", "yes", "on", "y")


JOURNEY_SESSION_SQLITE = """
CREATE TABLE IF NOT EXISTS journey_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  journey_uuid TEXT UNIQUE,
  owner_token TEXT,
  created_at TEXT, updated_at TEXT, started_at TEXT, expected_arrival TEXT,
  from_place TEXT, to_place TEXT,
  from_lat REAL, from_lng REAL, to_lat REAL, to_lng REAL,
  mode TEXT, state TEXT, risk_level TEXT,
  anomaly_level TEXT, anomaly_reason TEXT,
  last_checkin_at TEXT, last_packet_at TEXT,
  last_lat REAL, last_lng REAL, last_speed REAL, last_heading REAL,
  last_battery REAL, last_network TEXT,
  handoff_ref TEXT,
  share_consent INTEGER DEFAULT 0
);
"""
JOURNEY_SESSION_PG = """
CREATE TABLE IF NOT EXISTS journey_sessions (
  id SERIAL PRIMARY KEY,
  journey_uuid TEXT UNIQUE,
  owner_token TEXT,
  created_at TEXT, updated_at TEXT, started_at TEXT, expected_arrival TEXT,
  from_place TEXT, to_place TEXT,
  from_lat DOUBLE PRECISION, from_lng DOUBLE PRECISION,
  to_lat DOUBLE PRECISION, to_lng DOUBLE PRECISION,
  mode TEXT, state TEXT, risk_level TEXT,
  anomaly_level TEXT, anomaly_reason TEXT,
  last_checkin_at TEXT, last_packet_at TEXT,
  last_lat DOUBLE PRECISION, last_lng DOUBLE PRECISION,
  last_speed DOUBLE PRECISION, last_heading DOUBLE PRECISION,
  last_battery DOUBLE PRECISION, last_network TEXT,
  handoff_ref TEXT,
  share_consent INTEGER DEFAULT 0
);
"""

JOURNEY_EVENT_SQLITE = """
CREATE TABLE IF NOT EXISTS journey_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  journey_uuid TEXT,
  created_at TEXT,
  event_type TEXT, state TEXT,
  lat REAL, lng REAL, speed REAL, heading REAL, battery REAL, network TEXT,
  note TEXT,
  anomaly_level TEXT, anomaly_reason TEXT
);
"""
JOURNEY_EVENT_PG = """
CREATE TABLE IF NOT EXISTS journey_events (
  id SERIAL PRIMARY KEY,
  journey_uuid TEXT,
  created_at TEXT,
  event_type TEXT, state TEXT,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  speed DOUBLE PRECISION, heading DOUBLE PRECISION,
  battery DOUBLE PRECISION, network TEXT,
  note TEXT,
  anomaly_level TEXT, anomaly_reason TEXT
);
"""

READINESS_SQLITE = """
CREATE TABLE IF NOT EXISTS safety_readiness (
  owner_token TEXT PRIMARY KEY,
  created_at TEXT, updated_at TEXT,
  platform TEXT,
  findmy_enabled INTEGER DEFAULT 0,
  findhub_enabled INTEGER DEFAULT 0,
  trusted_contacts INTEGER DEFAULT 0,
  silent_sos INTEGER DEFAULT 0,
  sms_fallback INTEGER DEFAULT 0,
  wearable INTEGER DEFAULT 0,
  offline_pack INTEGER DEFAULT 0,
  readiness_score INTEGER DEFAULT 0,
  gaps TEXT,
  notes TEXT
);
"""
READINESS_PG = """
CREATE TABLE IF NOT EXISTS safety_readiness (
  owner_token TEXT PRIMARY KEY,
  created_at TEXT, updated_at TEXT,
  platform TEXT,
  findmy_enabled INTEGER DEFAULT 0,
  findhub_enabled INTEGER DEFAULT 0,
  trusted_contacts INTEGER DEFAULT 0,
  silent_sos INTEGER DEFAULT 0,
  sms_fallback INTEGER DEFAULT 0,
  wearable INTEGER DEFAULT 0,
  offline_pack INTEGER DEFAULT 0,
  readiness_score INTEGER DEFAULT 0,
  gaps TEXT,
  notes TEXT
);
"""

SHIELD_CASE_SQLITE = """
CREATE TABLE IF NOT EXISTS shield_cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT, last_update_at TEXT,
  case_type TEXT, subject_ref TEXT,
  status TEXT, visibility TEXT,
  family_liaison TEXT, incident_commander TEXT, analyst_owner TEXT,
  summary TEXT, public_note TEXT,
  requires_second_approval INTEGER DEFAULT 0
);
"""
SHIELD_CASE_PG = """
CREATE TABLE IF NOT EXISTS shield_cases (
  id SERIAL PRIMARY KEY,
  case_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT, last_update_at TEXT,
  case_type TEXT, subject_ref TEXT,
  status TEXT, visibility TEXT,
  family_liaison TEXT, incident_commander TEXT, analyst_owner TEXT,
  summary TEXT, public_note TEXT,
  requires_second_approval INTEGER DEFAULT 0
);
"""

CASE_UPDATE_SQLITE = """
CREATE TABLE IF NOT EXISTS case_updates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_uuid TEXT,
  created_at TEXT,
  actor TEXT, visibility TEXT,
  body TEXT,
  redacted INTEGER DEFAULT 0
);
"""
CASE_UPDATE_PG = """
CREATE TABLE IF NOT EXISTS case_updates (
  id SERIAL PRIMARY KEY,
  case_uuid TEXT,
  created_at TEXT,
  actor TEXT, visibility TEXT,
  body TEXT,
  redacted INTEGER DEFAULT 0
);
"""

EVIDENCE_SQLITE = """
CREATE TABLE IF NOT EXISTS evidence_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_uuid TEXT UNIQUE,
  case_uuid TEXT,
  created_at TEXT, updated_at TEXT,
  evidence_type TEXT, title TEXT, source_label TEXT,
  custody_hash TEXT, prev_hash TEXT,
  restricted_level TEXT, status TEXT,
  lat REAL, lng REAL, captured_at TEXT,
  notes TEXT, public_summary TEXT
);
"""
EVIDENCE_PG = """
CREATE TABLE IF NOT EXISTS evidence_items (
  id SERIAL PRIMARY KEY,
  evidence_uuid TEXT UNIQUE,
  case_uuid TEXT,
  created_at TEXT, updated_at TEXT,
  evidence_type TEXT, title TEXT, source_label TEXT,
  custody_hash TEXT, prev_hash TEXT,
  restricted_level TEXT, status TEXT,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION, captured_at TEXT,
  notes TEXT, public_summary TEXT
);
"""

GEOTRACE_SQLITE = """
CREATE TABLE IF NOT EXISTS geotrace_annotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trace_uuid TEXT UNIQUE,
  evidence_uuid TEXT,
  case_uuid TEXT,
  created_at TEXT,
  actor TEXT,
  confidence TEXT,
  method TEXT,
  area_label TEXT,
  lat REAL, lng REAL, radius_km REAL,
  notes TEXT,
  restricted INTEGER DEFAULT 1
);
"""
GEOTRACE_PG = """
CREATE TABLE IF NOT EXISTS geotrace_annotations (
  id SERIAL PRIMARY KEY,
  trace_uuid TEXT UNIQUE,
  evidence_uuid TEXT,
  case_uuid TEXT,
  created_at TEXT,
  actor TEXT,
  confidence TEXT,
  method TEXT,
  area_label TEXT,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION, radius_km DOUBLE PRECISION,
  notes TEXT,
  restricted INTEGER DEFAULT 1
);
"""

SAFETY_POINT_SQLITE = """
CREATE TABLE IF NOT EXISTS safety_points (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  point_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  name TEXT, point_type TEXT,
  state TEXT, lga TEXT, address TEXT,
  lat REAL, lng REAL,
  contact_channel TEXT, contact_address TEXT,
  vetted INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  verified_by TEXT, last_verified_at TEXT,
  notes TEXT
);
"""
SAFETY_POINT_PG = """
CREATE TABLE IF NOT EXISTS safety_points (
  id SERIAL PRIMARY KEY,
  point_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  name TEXT, point_type TEXT,
  state TEXT, lga TEXT, address TEXT,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  contact_channel TEXT, contact_address TEXT,
  vetted INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  verified_by TEXT, last_verified_at TEXT,
  notes TEXT
);
"""

SENTINEL_SQLITE = """
CREATE TABLE IF NOT EXISTS sentinels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sentinel_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  name TEXT, org TEXT, role TEXT,
  state TEXT, lga TEXT,
  trust_level TEXT,
  active INTEGER DEFAULT 1,
  consent_revoked_at TEXT,
  channel TEXT, address TEXT,
  last_checkin_at TEXT, notes TEXT
);
"""
SENTINEL_PG = """
CREATE TABLE IF NOT EXISTS sentinels (
  id SERIAL PRIMARY KEY,
  sentinel_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  name TEXT, org TEXT, role TEXT,
  state TEXT, lga TEXT,
  trust_level TEXT,
  active INTEGER DEFAULT 1,
  consent_revoked_at TEXT,
  channel TEXT, address TEXT,
  last_checkin_at TEXT, notes TEXT
);
"""

MESH_DEVICE_SQLITE = """
CREATE TABLE IF NOT EXISTS mesh_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_uuid TEXT UNIQUE,
  owner_token TEXT,
  created_at TEXT, updated_at TEXT,
  device_label TEXT,
  consent_scope TEXT,
  rotating_id TEXT,
  active INTEGER DEFAULT 1,
  revoked_at TEXT,
  last_seen_at TEXT,
  notes TEXT
);
"""
MESH_DEVICE_PG = """
CREATE TABLE IF NOT EXISTS mesh_devices (
  id SERIAL PRIMARY KEY,
  device_uuid TEXT UNIQUE,
  owner_token TEXT,
  created_at TEXT, updated_at TEXT,
  device_label TEXT,
  consent_scope TEXT,
  rotating_id TEXT,
  active INTEGER DEFAULT 1,
  revoked_at TEXT,
  last_seen_at TEXT,
  notes TEXT
);
"""

MESH_RELAY_SQLITE = """
CREATE TABLE IF NOT EXISTS mesh_relays (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  relay_uuid TEXT UNIQUE,
  created_at TEXT,
  device_uuid TEXT,
  relay_type TEXT,
  rotating_id TEXT,
  lat REAL, lng REAL,
  sig_status TEXT,
  accepted INTEGER DEFAULT 0,
  reason TEXT
);
"""
MESH_RELAY_PG = """
CREATE TABLE IF NOT EXISTS mesh_relays (
  id SERIAL PRIMARY KEY,
  relay_uuid TEXT UNIQUE,
  created_at TEXT,
  device_uuid TEXT,
  relay_type TEXT,
  rotating_id TEXT,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  sig_status TEXT,
  accepted INTEGER DEFAULT 0,
  reason TEXT
);
"""

TRACKER_SQLITE = """
CREATE TABLE IF NOT EXISTS tracker_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tracker_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  owner_ref TEXT,
  label TEXT,
  tracker_type TEXT,
  stable_id_hash TEXT,
  rotating_id TEXT,
  consent_status TEXT,
  anti_stalking_notice INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1,
  revoked_at TEXT,
  last_seen_at TEXT,
  last_lat REAL, last_lng REAL,
  notes TEXT
);
"""
TRACKER_PG = """
CREATE TABLE IF NOT EXISTS tracker_devices (
  id SERIAL PRIMARY KEY,
  tracker_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  owner_ref TEXT,
  label TEXT,
  tracker_type TEXT,
  stable_id_hash TEXT,
  rotating_id TEXT,
  consent_status TEXT,
  anti_stalking_notice INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1,
  revoked_at TEXT,
  last_seen_at TEXT,
  last_lat DOUBLE PRECISION, last_lng DOUBLE PRECISION,
  notes TEXT
);
"""

OPS_AGREEMENT_SQLITE = """
CREATE TABLE IF NOT EXISTS ops_agreements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agreement_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  partner_name TEXT, partner_type TEXT,
  state TEXT, lga TEXT,
  scope TEXT, escalation_channel TEXT,
  status TEXT,
  signed_at TEXT, expires_at TEXT,
  owner TEXT, notes TEXT
);
"""
OPS_AGREEMENT_PG = """
CREATE TABLE IF NOT EXISTS ops_agreements (
  id SERIAL PRIMARY KEY,
  agreement_uuid TEXT UNIQUE,
  created_at TEXT, updated_at TEXT,
  partner_name TEXT, partner_type TEXT,
  state TEXT, lga TEXT,
  scope TEXT, escalation_channel TEXT,
  status TEXT,
  signed_at TEXT, expires_at TEXT,
  owner TEXT, notes TEXT
);
"""

OPS_DRILL_SQLITE = """
CREATE TABLE IF NOT EXISTS ops_drills (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  drill_uuid TEXT UNIQUE,
  created_at TEXT,
  drill_type TEXT,
  state TEXT, lga TEXT,
  participants TEXT,
  outcome TEXT,
  gaps TEXT,
  next_due_at TEXT,
  owner TEXT
);
"""
OPS_DRILL_PG = """
CREATE TABLE IF NOT EXISTS ops_drills (
  id SERIAL PRIMARY KEY,
  drill_uuid TEXT UNIQUE,
  created_at TEXT,
  drill_type TEXT,
  state TEXT, lga TEXT,
  participants TEXT,
  outcome TEXT,
  gaps TEXT,
  next_due_at TEXT,
  owner TEXT
);
"""


SAFETY_TABLES = {
    "journey_sessions": (JOURNEY_SESSION_SQLITE, JOURNEY_SESSION_PG),
    "journey_events": (JOURNEY_EVENT_SQLITE, JOURNEY_EVENT_PG),
    "safety_readiness": (READINESS_SQLITE, READINESS_PG),
    "shield_cases": (SHIELD_CASE_SQLITE, SHIELD_CASE_PG),
    "case_updates": (CASE_UPDATE_SQLITE, CASE_UPDATE_PG),
    "evidence_items": (EVIDENCE_SQLITE, EVIDENCE_PG),
    "geotrace_annotations": (GEOTRACE_SQLITE, GEOTRACE_PG),
    "safety_points": (SAFETY_POINT_SQLITE, SAFETY_POINT_PG),
    "sentinels": (SENTINEL_SQLITE, SENTINEL_PG),
    "mesh_devices": (MESH_DEVICE_SQLITE, MESH_DEVICE_PG),
    "mesh_relays": (MESH_RELAY_SQLITE, MESH_RELAY_PG),
    "tracker_devices": (TRACKER_SQLITE, TRACKER_PG),
    "ops_agreements": (OPS_AGREEMENT_SQLITE, OPS_AGREEMENT_PG),
    "ops_drills": (OPS_DRILL_SQLITE, OPS_DRILL_PG),
}


def readiness_from(data, trusted_count=0):
    checks = {
        "findmy_enabled": as_bool(data.get("findmy_enabled")),
        "findhub_enabled": as_bool(data.get("findhub_enabled")),
        "trusted_contacts": int(data.get("trusted_contacts") or trusted_count or 0),
        "silent_sos": as_bool(data.get("silent_sos")),
        "sms_fallback": as_bool(data.get("sms_fallback")),
        "wearable": as_bool(data.get("wearable")),
        "offline_pack": as_bool(data.get("offline_pack")),
    }
    gaps = []
    score = 0
    if checks["findmy_enabled"] or checks["findhub_enabled"]:
        score += 20
    else:
        gaps.append("Enable Apple Find My or Google Find Hub before travel.")
    if checks["trusted_contacts"] >= 2:
        score += 20
    elif checks["trusted_contacts"] == 1:
        score += 10
        gaps.append("Add a second trusted contact.")
    else:
        gaps.append("Add trusted contacts for SOS notification.")
    for key, points, label in (
        ("silent_sos", 15, "Test silent SOS."),
        ("sms_fallback", 15, "Set an SMS fallback contact."),
        ("wearable", 10, "Pair a wearable or hardware tracker for high-risk trips."),
        ("offline_pack", 20, "Download offline route and emergency instructions."),
    ):
        if checks[key]:
            score += points
        else:
            gaps.append(label)
    return checks, max(0, min(100, score)), gaps


def assess_journey(row, event=None, now=None):
    event = event or {}
    now = now or datetime.datetime.now()
    level = "normal"
    reason = ""
    state = (row or {}).get("state") or "active"
    kind = (event.get("event_type") or event.get("type") or "").strip().lower()
    battery = event.get("battery")
    if kind in ("duress", "emergency", "sos"):
        return "critical", "duress event received", "escalated"
    if kind in ("checkin_failed", "missed_checkin"):
        level, reason = "warning", "missed check-in"
    try:
        if battery is not None and float(battery) <= 10:
            level, reason = "warning", "battery critically low"
    except Exception:
        pass
    try:
        expected = (row or {}).get("expected_arrival")
        if expected and state not in ("arrived", "closed"):
            eta = datetime.datetime.fromisoformat(expected)
            if now > eta + datetime.timedelta(minutes=15):
                level, reason = "warning", "journey overdue"
    except Exception:
        pass
    if event.get("deviation_km") is not None:
        try:
            if float(event.get("deviation_km")) > 5:
                level, reason = "warning", "reported route deviation"
        except Exception:
            pass
    if kind == "arrived":
        return "normal", "", "arrived"
    return level, reason, ("escalated" if level == "critical" else state)


def public_evidence_view(row):
    return {
        "evidence_uuid": row.get("evidence_uuid"),
        "case_uuid": row.get("case_uuid"),
        "evidence_type": row.get("evidence_type"),
        "title": row.get("title"),
        "status": row.get("status"),
        "public_summary": row.get("public_summary") or "",
        "restricted": True,
    }


def safety_point_public(row):
    return {
        "point_uuid": row.get("point_uuid"),
        "name": row.get("name"),
        "point_type": row.get("point_type"),
        "state": row.get("state"),
        "lga": row.get("lga"),
        "address": row.get("address"),
        "lat": row.get("lat"),
        "lng": row.get("lng"),
        "vetted": bool(row.get("vetted")),
        "last_verified_at": row.get("last_verified_at"),
    }
