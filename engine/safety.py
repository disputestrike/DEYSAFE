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


# =============================================================================
# PHASE 4: SafeMeet - High-Risk Meeting Protection
# =============================================================================
# Pre-incident workflow for dating, marketplace sales, job interviews,
# deliveries, ride-share pickups, and other high-risk encounters.
# =============================================================================

SAFEMEET_SQLITE = """
CREATE TABLE IF NOT EXISTS safemeet_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_uuid TEXT UNIQUE,
  owner_token TEXT,
  created_at TEXT, updated_at TEXT,
  
  -- Meeting details
  meeting_type TEXT,
  risk_level TEXT DEFAULT 'medium',
  
  -- Location
  meeting_place TEXT,
  meeting_address TEXT,
  meeting_lat REAL,
  meeting_lng REAL,
  
  -- Counterparty information
  contact_name TEXT,
  contact_phone TEXT,
  contact_photo_url TEXT,
  contact_social_profile TEXT,
  
  -- Vehicle info (for rides, deliveries, marketplace)
  vehicle_description TEXT,
  license_plate TEXT,
  
  -- Timing
  expected_arrival TEXT,
  expected_departure TEXT,
  actual_arrival TEXT,
  actual_departure TEXT,
  
  -- Check-in workflow
  checkin_interval_minutes INTEGER DEFAULT 30,
  last_checkin_at TEXT,
  next_checkin_due TEXT,
  missed_checkins INTEGER DEFAULT 0,
  
  -- Status tracking
  state TEXT DEFAULT 'scheduled',
  -- states: scheduled, in_progress, completed, escalated, cancelled
  
  -- Duress & safety
  duress_triggered INTEGER DEFAULT 0,
  duress_trigger_time TEXT,
  safe_pin_hash TEXT,
  duress_pin_hash TEXT,
  
  -- Anomaly detection
  location_changed INTEGER DEFAULT 0,
  route_deviation INTEGER DEFAULT 0,
  phone_off_suddenly INTEGER DEFAULT 0,
  
  -- Escalation
  escalated_at TEXT,
  escalation_reason TEXT,
  escalated_to_contacts INTEGER DEFAULT 0,
  
  -- Evidence preservation
  evidence_preserved INTEGER DEFAULT 0,
  evidence_snapshot_url TEXT,
  
  -- Notes
  user_notes TEXT,
  system_notes TEXT
);
"""

SAFEMEET_PG = """
CREATE TABLE IF NOT EXISTS safemeet_sessions (
  id SERIAL PRIMARY KEY,
  session_uuid TEXT UNIQUE,
  owner_token TEXT,
  created_at TEXT, updated_at TEXT,
  
  meeting_type TEXT,
  risk_level TEXT DEFAULT 'medium',
  
  meeting_place TEXT,
  meeting_address TEXT,
  meeting_lat DOUBLE PRECISION,
  meeting_lng DOUBLE PRECISION,
  
  contact_name TEXT,
  contact_phone TEXT,
  contact_photo_url TEXT,
  contact_social_profile TEXT,
  
  vehicle_description TEXT,
  license_plate TEXT,
  
  expected_arrival TEXT,
  expected_departure TEXT,
  actual_arrival TEXT,
  actual_departure TEXT,
  
  checkin_interval_minutes INTEGER DEFAULT 30,
  last_checkin_at TEXT,
  next_checkin_due TEXT,
  missed_checkins INTEGER DEFAULT 0,
  
  state TEXT DEFAULT 'scheduled',
  
  duress_triggered INTEGER DEFAULT 0,
  duress_trigger_time TEXT,
  safe_pin_hash TEXT,
  duress_pin_hash TEXT,
  
  location_changed INTEGER DEFAULT 0,
  route_deviation INTEGER DEFAULT 0,
  phone_off_suddenly INTEGER DEFAULT 0,
  
  escalated_at TEXT,
  escalation_reason TEXT,
  escalated_to_contacts INTEGER DEFAULT 0,
  
  evidence_preserved INTEGER DEFAULT 0,
  evidence_snapshot_url TEXT,
  
  user_notes TEXT,
  system_notes TEXT
);
"""

SAFEMEET_CHECKINS_SQLITE = """
CREATE TABLE IF NOT EXISTS safemeet_checkins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER,
  checkin_uuid TEXT UNIQUE,
  ts TEXT,
  checkin_type TEXT,
  -- types: scheduled, manual, auto_location, duress_safe, duress_covert
  lat REAL,
  lng REAL,
  location_accuracy REAL,
  battery_level REAL,
  network_type TEXT,
  note TEXT,
  duress_flag INTEGER DEFAULT 0,
  photo_url TEXT,
  audio_url TEXT
);
"""

SAFEMEET_CHECKINS_PG = """
CREATE TABLE IF NOT EXISTS safemeet_checkins (
  id SERIAL PRIMARY KEY,
  session_id INTEGER,
  checkin_uuid TEXT UNIQUE,
  ts TEXT,
  checkin_type TEXT,
  lat DOUBLE PRECISION,
  lng DOUBLE PRECISION,
  location_accuracy DOUBLE PRECISION,
  battery_level DOUBLE PRECISION,
  network_type TEXT,
  note TEXT,
  duress_flag INTEGER DEFAULT 0,
  photo_url TEXT,
  audio_url TEXT
);
"""


def safemeet_session_public(row):
    """Return public-safe view of a SafeMeet session (no tokens/hashes)."""
    return {
        "session_uuid": row.get("session_uuid"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "meeting_type": row.get("meeting_type"),
        "risk_level": row.get("risk_level"),
        "meeting_place": row.get("meeting_place"),
        "meeting_address": row.get("meeting_address"),
        "meeting_lat": row.get("meeting_lat"),
        "meeting_lng": row.get("meeting_lng"),
        "contact_name": row.get("contact_name"),
        "contact_phone": row.get("contact_phone"),
        "vehicle_description": row.get("vehicle_description"),
        "license_plate": row.get("license_plate"),
        "expected_arrival": row.get("expected_arrival"),
        "expected_departure": row.get("expected_departure"),
        "actual_arrival": row.get("actual_arrival"),
        "actual_departure": row.get("actual_departure"),
        "checkin_interval_minutes": row.get("checkin_interval_minutes"),
        "last_checkin_at": row.get("last_checkin_at"),
        "next_checkin_due": row.get("next_checkin_due"),
        "missed_checkins": row.get("missed_checkins"),
        "state": row.get("state"),
        "duress_triggered": bool(row.get("duress_triggered")),
        "location_changed": bool(row.get("location_changed")),
        "route_deviation": bool(row.get("route_deviation")),
        "escalated_at": row.get("escalated_at"),
        "escalation_reason": row.get("escalation_reason"),
        "user_notes": row.get("user_notes"),
    }


def safemeet_checkin_public(row):
    """Return public-safe view of a SafeMeet check-in."""
    return {
        "checkin_uuid": row.get("checkin_uuid"),
        "ts": row.get("ts"),
        "checkin_type": row.get("checkin_type"),
        "lat": row.get("lat"),
        "lng": row.get("lng"),
        "location_accuracy": row.get("location_accuracy"),
        "battery_level": row.get("battery_level"),
        "network_type": row.get("network_type"),
        "note": row.get("note"),
        "duress_flag": bool(row.get("duress_flag")),
        "photo_url": row.get("photo_url"),
    }


def calculate_meeting_risk(meeting_type, location_lat, location_lng, time_of_day, historical_data=None):
    """
    Calculate initial risk level for a meeting based on multiple factors.
    
    Returns: 'low', 'medium', 'high', 'critical'
    """
    risk_score = 50  # baseline medium
    
    # Meeting type adjustments
    type_risks = {
        'dating': 20,
        'marketplace_sale': 15,
        'job_interview': 10,
        'ride_share': 25,
        'delivery': 15,
        'house_call': 20,
        'business_meeting': 5,
        'informant_meeting': 40,
    }
    risk_score += type_risks.get(meeting_type, 10)
    
    # Time of day adjustments (simplified)
    if time_of_day:
        try:
            hour = int(time_of_day.split('T')[1].split(':')[0]) if 'T' in time_of_day else 12
            if hour < 6 or hour > 22:
                risk_score += 15  # night meetings higher risk
        except Exception:
            pass
    
    # Historical crime data for location (if available)
    if historical_data:
        # Would query incident history for this lat/lng
        pass
    
    # Convert score to level
    if risk_score >= 80:
        return 'critical'
    elif risk_score >= 60:
        return 'high'
    elif risk_score >= 40:
        return 'medium'
    else:
        return 'low'


def detect_meeting_anomalies(session_row, current_lat, current_lng, device_status):
    """
    Detect anomalies during an active SafeMeet session.
    
    Returns dict with anomaly flags and reasons.
    """
    anomalies = {
        'location_changed': False,
        'route_deviation': False,
        'phone_off_suddenly': False,
        'duration_exceeded': False,
        'checkin_missed': False,
        'reasons': []
    }
    
    # Check if location changed significantly from planned meeting place
    if session_row.get('meeting_lat') and current_lat:
        from math import radians, sin, cos, sqrt, atan2
        def haversine(lat1, lon1, lat2, lon2):
            R = 6371  # Earth radius in km
            dlat = radians(lat2 - lat1)
            dlon = radians(lon2 - lon1)
            a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
            c = 2 * atan2(sqrt(a), sqrt(1-a))
            return R * c
        
        distance = haversine(
            session_row['meeting_lat'], session_row['meeting_lng'],
            current_lat, current_lng
        )
        
        if distance > 5.0:  # More than 5km from meeting place
            anomalies['location_changed'] = True
            anomalies['reasons'].append(f'Moved {distance:.1f}km from meeting location')
    
    # Check if phone was turned off suddenly during active meeting
    if device_status == 'offline' and session_row.get('state') == 'in_progress':
        anomalies['phone_off_suddenly'] = True
        anomalies['reasons'].append('Device went offline during active meeting')
    
    # Check if meeting duration exceeded expected time
    if session_row.get('expected_departure') and session_row.get('actual_arrival'):
        from datetime import datetime
        try:
            expected_end = datetime.fromisoformat(session_row['expected_departure'])
            now = datetime.now()
            if now > expected_end:
                anomalies['duration_exceeded'] = True
                anomalies['reasons'].append('Meeting exceeded expected duration')
        except Exception:
            pass
    
    # Check for missed check-ins
    if session_row.get('next_checkin_due'):
        from datetime import datetime
        try:
            next_due = datetime.fromisoformat(session_row['next_checkin_due'])
            if datetime.now() > next_due:
                anomalies['checkin_missed'] = True
                anomalies['reasons'].append('Scheduled check-in missed')
        except Exception:
            pass
    
    return anomalies
