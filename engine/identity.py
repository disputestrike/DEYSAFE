"""Citizen identity, Safety Vault, PINs, MySafe, and push primitives.

Stdlib-only on purpose: DeySafe's current backend is a single Python HTTP server,
so these helpers keep account/session security auditable without adding a new
framework. The API layer owns request policy; this module owns deterministic
token, OTP, redaction, and table shape.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import time


SESSION_TTL_DAYS = int(os.environ.get("DEYSAFE_SESSION_TTL_DAYS", "30"))
OTP_TTL_MINUTES = int(os.environ.get("DEYSAFE_OTP_TTL_MINUTES", "10"))


IDENTITY_SQLITE = """
CREATE TABLE IF NOT EXISTS citizen_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_uuid TEXT UNIQUE,
  phone_hash TEXT UNIQUE,
  phone_display TEXT,
  first_name TEXT,
  language TEXT DEFAULT 'en',
  guardian_policy_id TEXT UNIQUE,
  created_at TEXT,
  verified_at TEXT,
  status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS otp_challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  otp_ref TEXT UNIQUE,
  phone_hash TEXT,
  phone_display TEXT,
  otp_hash TEXT,
  created_at TEXT,
  expires_at TEXT,
  consumed_at TEXT,
  attempts INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS personal_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_hash TEXT UNIQUE,
  user_uuid TEXT,
  device_id TEXT,
  created_at TEXT,
  expires_at TEXT,
  revoked_at TEXT,
  last_seen_at TEXT
);
CREATE TABLE IF NOT EXISTS user_pins (
  user_uuid TEXT PRIMARY KEY,
  app_pin_hash TEXT,
  safety_pin_hash TEXT,
  duress_pin_hash TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS guardian_contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guardian_uuid TEXT UNIQUE,
  user_uuid TEXT,
  policy_id TEXT,
  name TEXT,
  channel TEXT,
  address TEXT,
  address_hash TEXT,
  verified INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  created_at TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sub_uuid TEXT UNIQUE,
  user_uuid TEXT,
  device_id TEXT,
  endpoint_hash TEXT,
  subscription_json TEXT,
  created_at TEXT,
  last_test_at TEXT,
  last_confirmed_at TEXT,
  status TEXT DEFAULT 'registered'
);
CREATE TABLE IF NOT EXISTS mysafe_places (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  place_uuid TEXT UNIQUE,
  user_uuid TEXT,
  alias TEXT,
  place TEXT,
  lat REAL,
  lng REAL,
  created_at TEXT,
  active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS mysafe_routes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  route_uuid TEXT UNIQUE,
  user_uuid TEXT,
  origin_alias TEXT,
  destination_alias TEXT,
  days TEXT,
  departure_window TEXT,
  expected_arrival TEXT,
  escalation_policy TEXT,
  created_at TEXT,
  active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS beacon_nonces (
  nonce TEXT PRIMARY KEY,
  beacon_id TEXT,
  seen_at TEXT
);
"""


IDENTITY_PG = """
CREATE TABLE IF NOT EXISTS citizen_users (
  id SERIAL PRIMARY KEY,
  user_uuid TEXT UNIQUE,
  phone_hash TEXT UNIQUE,
  phone_display TEXT,
  first_name TEXT,
  language TEXT DEFAULT 'en',
  guardian_policy_id TEXT UNIQUE,
  created_at TEXT,
  verified_at TEXT,
  status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS otp_challenges (
  id SERIAL PRIMARY KEY,
  otp_ref TEXT UNIQUE,
  phone_hash TEXT,
  phone_display TEXT,
  otp_hash TEXT,
  created_at TEXT,
  expires_at TEXT,
  consumed_at TEXT,
  attempts INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS personal_sessions (
  id SERIAL PRIMARY KEY,
  session_hash TEXT UNIQUE,
  user_uuid TEXT,
  device_id TEXT,
  created_at TEXT,
  expires_at TEXT,
  revoked_at TEXT,
  last_seen_at TEXT
);
CREATE TABLE IF NOT EXISTS user_pins (
  user_uuid TEXT PRIMARY KEY,
  app_pin_hash TEXT,
  safety_pin_hash TEXT,
  duress_pin_hash TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS guardian_contacts (
  id SERIAL PRIMARY KEY,
  guardian_uuid TEXT UNIQUE,
  user_uuid TEXT,
  policy_id TEXT,
  name TEXT,
  channel TEXT,
  address TEXT,
  address_hash TEXT,
  verified INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  created_at TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id SERIAL PRIMARY KEY,
  sub_uuid TEXT UNIQUE,
  user_uuid TEXT,
  device_id TEXT,
  endpoint_hash TEXT,
  subscription_json TEXT,
  created_at TEXT,
  last_test_at TEXT,
  last_confirmed_at TEXT,
  status TEXT DEFAULT 'registered'
);
CREATE TABLE IF NOT EXISTS mysafe_places (
  id SERIAL PRIMARY KEY,
  place_uuid TEXT UNIQUE,
  user_uuid TEXT,
  alias TEXT,
  place TEXT,
  lat DOUBLE PRECISION,
  lng DOUBLE PRECISION,
  created_at TEXT,
  active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS mysafe_routes (
  id SERIAL PRIMARY KEY,
  route_uuid TEXT UNIQUE,
  user_uuid TEXT,
  origin_alias TEXT,
  destination_alias TEXT,
  days TEXT,
  departure_window TEXT,
  expected_arrival TEXT,
  escalation_policy TEXT,
  created_at TEXT,
  active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS beacon_nonces (
  nonce TEXT PRIMARY KEY,
  beacon_id TEXT,
  seen_at TEXT
);
"""


IDENTITY_TABLES = {
    "citizen_identity": (IDENTITY_SQLITE, IDENTITY_PG),
}


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def utc_epoch():
    return int(time.time())


def _b64(data):
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text):
    pad = "=" * (-len(text) % 4)
    return json.loads(base64.urlsafe_b64decode((text + pad).encode("ascii")).decode("utf-8"))


def secret():
    return (os.environ.get("DEYSAFE_SECRET") or os.environ.get("SECRET_KEY") or "").strip()


def effective_secret():
    s = secret()
    if s:
        return s
    # Dev/test fallback only. Production startup rejects this before serving.
    return "deysafe-dev-session-secret-change-me"


def hmac_hex(kind, value):
    key = effective_secret().encode("utf-8")
    msg = ("%s|%s" % (kind, value or "")).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def normalize_phone(phone):
    raw = re.sub(r"[^0-9+]", "", str(phone or "").strip())
    if raw.startswith("00"):
        raw = "+" + raw[2:]
    if raw.startswith("0") and len(raw) >= 10:
        raw = "+234" + raw[1:]
    return raw[:24]


def phone_hash(phone):
    return hmac_hex("phone", normalize_phone(phone))


def new_id(prefix):
    return prefix + "_" + secrets.token_hex(12)


def otp_code():
    return "%06d" % secrets.randbelow(1000000)


def otp_hash(ref, code):
    return hmac_hex("otp", "%s|%s" % (ref, str(code or "").strip()))


def pin_hash(user_uuid, pin, kind):
    return hmac_hex("pin:%s" % kind, "%s|%s" % (user_uuid, str(pin or "")))


def verify_pin(user_uuid, pin, expected_hash, kind):
    if not expected_hash:
        return False
    got = pin_hash(user_uuid, pin, kind)
    return hmac.compare_digest(got, expected_hash)


def session_token(user_uuid, device_id, exp=None):
    exp = int(exp or (utc_epoch() + SESSION_TTL_DAYS * 86400))
    payload = {"u": user_uuid, "d": device_id, "exp": exp, "iat": utc_epoch()}
    body = _b64(payload)
    sig = hmac_hex("session", body)
    return "dsu.%s.%s" % (body, sig)


def parse_session_token(token):
    parts = str(token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != "dsu":
        return None
    body, sig = parts[1], parts[2]
    if not hmac.compare_digest(hmac_hex("session", body), sig):
        return None
    try:
        payload = _unb64(body)
    except Exception:
        return None
    if int(payload.get("exp") or 0) < utc_epoch():
        return None
    return payload


def session_hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def redact_phone(phone):
    p = normalize_phone(phone)
    if len(p) <= 6:
        return "***"
    return p[:4] + "..." + p[-3:]


def redact_address(addr):
    s = str(addr or "").strip()
    if "@" in s:
        name, dom = s.split("@", 1)
        return (name[:1] + "***@" + dom[:12])[:32]
    if len(s) <= 6:
        return "***"
    return s[:4] + "..." + s[-3:]


def public_user(row):
    if not row:
        return None
    return {
        "user_uuid": row.get("user_uuid"),
        "first_name": row.get("first_name") or "",
        "language": row.get("language") or "en",
        "phone": redact_phone(row.get("phone_display") or ""),
        "guardian_policy_id": row.get("guardian_policy_id"),
        "status": row.get("status") or "active",
    }


def public_guardian(row):
    return {
        "guardian_uuid": row.get("guardian_uuid"),
        "name": row.get("name") or "Guardian",
        "channel": row.get("channel") or "sms",
        "address_redacted": redact_address(row.get("address") or ""),
        "verified": bool(row.get("verified")),
        "active": bool(row.get("active")),
    }


def public_place(row):
    return {
        "place_uuid": row.get("place_uuid"),
        "alias": row.get("alias") or "",
        "place": row.get("place") or "",
        "lat": row.get("lat"),
        "lng": row.get("lng"),
        "active": bool(row.get("active")),
    }


def public_route(row):
    return {
        "route_uuid": row.get("route_uuid"),
        "origin_alias": row.get("origin_alias") or "",
        "destination_alias": row.get("destination_alias") or "",
        "days": row.get("days") or "",
        "departure_window": row.get("departure_window") or "",
        "expected_arrival": row.get("expected_arrival") or "",
        "escalation_policy": row.get("escalation_policy") or "",
        "active": bool(row.get("active")),
    }
