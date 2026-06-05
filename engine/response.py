"""Response-loop pure helpers + schema for DeySafe / SHIELD (Phase 1).

This module is the single, auditable home for the *response loop* state model —
the half of the system that turns a verified warning into an acknowledged human
response (SOS -> trusted circle -> operator -> 112/responder), plus the alert
lifecycle and the delivery/responder records the broadcast layer writes to.

Design rules (mirror security.py):
  - STDLIB ONLY. No DB handle, no env reads, no network, no I/O. Every public
    function is pure/deterministic given its inputs (except new_id()). That makes
    the whole state model trivially unit-testable and safe to call from any
    request thread, and lets api.py / db.py import it without side effects.
  - The DDL lives here as plain strings (one SQLite variant, one Postgres
    variant per object) so db.py can splice them into its dual-mode schema +
    _migrate path. Nothing here executes SQL; it only *describes* it.

Bright lines encoded in the state machines (FEEDBACK §L / RESP-06):
  - Nothing here auto-dispatches anything. The SOS and responder machines only
    ever move between *human* acknowledgement states; "armed dispatch" is not a
    representable transition.
  - HANDOFF_112_REQUESTED is a *requested* state — a governed manual handoff, not
    an automatic call-out (RESP-02).

Three state models are provided:
  1. SOS event lifecycle      — event-driven FSM, next_state(cur, event).
  2. Responder task lifecycle — linear ack ladder, valid_task_transition(a, b).
  3. Alert lifecycle          — PUBLISHED/UPDATED/CANCELLED/EXPIRED + TTL helper.
"""
import uuid
import datetime


# ---------------------------------------------------------------------------
# 0. Identity
# ---------------------------------------------------------------------------
def new_id():
    """A fresh immutable id (uuid4 hex, 32 chars) for an sos_event / task / etc.

    Kept here (rather than importing security.new_uuid) so response.py has zero
    intra-package dependencies and stays importable on its own.
    """
    return uuid.uuid4().hex


def _now():
    return datetime.datetime.now()


def _parse_iso(ts):
    """Best-effort parse of an ISO-8601 timestamp string to a naive datetime.

    Returns None when ts is falsy or unparseable (callers treat None as "no
    creation time known" -> cannot be considered expired on age alone)."""
    if not ts:
        return None
    if isinstance(ts, datetime.datetime):
        return ts
    s = str(ts).strip()
    # Tolerate a trailing 'Z' and space-separated date/time.
    if s.endswith("Z"):
        s = s[:-1]
    s = s.replace(" ", "T", 1) if ("T" not in s and " " in s) else s
    try:
        return datetime.datetime.fromisoformat(s)
    except Exception:
        # Last resort: try just the seconds-precision prefix "YYYY-MM-DDTHH:MM:SS".
        try:
            return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None


# ===========================================================================
# 1. SOS EVENT STATE MACHINE  (SOS-01 / SOS-02)
# ===========================================================================
# The durable SOS event walks an escalation ladder from the moment the field
# user triggers it through to an acknowledged, coordinated, resolved outcome.
# It is EVENT-DRIVEN: next_state(current, event) returns the state the event
# moves to when `event` is applied, or None if that event is not allowed from
# the current state.
#
# States:
#   TRIGGERED             user hit SOS; durable event created (no delivery yet)
#   LOCATION_CAPTURED     on-device location attached (user-shared; never harvested)
#   CIRCLE_NOTIFIED       trusted-circle notification dispatched (SIM or real)
#   DELIVERED             at least one notification confirmed delivered (receipt)
#   OPERATOR_ACK          a human operator has acknowledged / picked up the event
#   HANDOFF_112_REQUESTED governed manual handoff to 112/ECC requested (RESP-02)
#   COORDINATED           response is being coordinated with responders/112
#   SAFE                  subject confirmed safe (good terminal outcome)
#   ESCALATED            timer/operator escalation (reachable from most live states)
#   CLOSED                event closed out (terminal; after-action done)
#
# Terminal states: SAFE, CLOSED. (SAFE may still be CLOSED for bookkeeping.)
SOS_TRIGGERED = "TRIGGERED"
SOS_LOCATION_CAPTURED = "LOCATION_CAPTURED"
SOS_CIRCLE_NOTIFIED = "CIRCLE_NOTIFIED"
SOS_DELIVERED = "DELIVERED"
SOS_OPERATOR_ACK = "OPERATOR_ACK"
SOS_HANDOFF_112_REQUESTED = "HANDOFF_112_REQUESTED"
SOS_COORDINATED = "COORDINATED"
SOS_SAFE = "SAFE"
SOS_ESCALATED = "ESCALATED"
SOS_CLOSED = "CLOSED"

SOS_STATES = (
    SOS_TRIGGERED,
    SOS_LOCATION_CAPTURED,
    SOS_CIRCLE_NOTIFIED,
    SOS_DELIVERED,
    SOS_OPERATOR_ACK,
    SOS_HANDOFF_112_REQUESTED,
    SOS_COORDINATED,
    SOS_SAFE,
    SOS_ESCALATED,
    SOS_CLOSED,
)

SOS_TERMINAL = frozenset({SOS_SAFE, SOS_CLOSED})

# The starting state for a brand-new SOS event.
SOS_INITIAL = SOS_TRIGGERED

# Event vocabulary applied to the SOS machine. Each maps (state -> next state).
SOS_EVENTS = (
    "capture_location",   # attach on-device location
    "notify_circle",      # dispatch trusted-circle notifications
    "delivery_confirmed", # a delivery receipt came back
    "operator_ack",       # operator picks up the event
    "request_112",        # request governed 112/ECC handoff (manual, RESP-02)
    "coordinate",         # response coordination underway
    "mark_safe",          # subject confirmed safe
    "escalate",           # escalation timer fired / operator escalated
    "close",              # close the event out
)

# Allowed transitions as an event-keyed adjacency map:
#   SOS_TRANSITIONS[current_state][event] = next_state
# Anything not present is rejected by next_state(). 'escalate' and 'close' are
# attached to every live (non-terminal) state because escalation/closure can be
# forced from wherever the event currently sits. 'mark_safe' is likewise broadly
# available — a subject can turn out safe at any live stage.
SOS_TRANSITIONS = {
    SOS_TRIGGERED: {
        "capture_location": SOS_LOCATION_CAPTURED,
        "notify_circle": SOS_CIRCLE_NOTIFIED,   # location is optional (covert/no-GPS)
        "operator_ack": SOS_OPERATOR_ACK,
        "escalate": SOS_ESCALATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    SOS_LOCATION_CAPTURED: {
        "notify_circle": SOS_CIRCLE_NOTIFIED,
        "operator_ack": SOS_OPERATOR_ACK,
        "escalate": SOS_ESCALATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    SOS_CIRCLE_NOTIFIED: {
        "delivery_confirmed": SOS_DELIVERED,
        "operator_ack": SOS_OPERATOR_ACK,
        "escalate": SOS_ESCALATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    SOS_DELIVERED: {
        "operator_ack": SOS_OPERATOR_ACK,
        "escalate": SOS_ESCALATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    SOS_OPERATOR_ACK: {
        "request_112": SOS_HANDOFF_112_REQUESTED,
        "coordinate": SOS_COORDINATED,
        "escalate": SOS_ESCALATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    SOS_HANDOFF_112_REQUESTED: {
        "coordinate": SOS_COORDINATED,
        "escalate": SOS_ESCALATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    SOS_COORDINATED: {
        "request_112": SOS_HANDOFF_112_REQUESTED,  # may still pull in 112 mid-coordination
        "escalate": SOS_ESCALATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    SOS_ESCALATED: {
        # Escalation is a holding state: an operator can pick it up, push it to
        # 112, coordinate, resolve, or close it.
        "operator_ack": SOS_OPERATOR_ACK,
        "request_112": SOS_HANDOFF_112_REQUESTED,
        "coordinate": SOS_COORDINATED,
        "mark_safe": SOS_SAFE,
        "close": SOS_CLOSED,
    },
    # Terminal states: SAFE can still be CLOSED for bookkeeping; CLOSED is final.
    SOS_SAFE: {
        "close": SOS_CLOSED,
    },
    SOS_CLOSED: {},
}


def sos_is_terminal(state):
    """True if the SOS event is in a terminal state (SAFE or CLOSED)."""
    return state in SOS_TERMINAL


def sos_allowed_events(state):
    """Tuple of events that are valid from `state` (empty for unknown/terminal)."""
    return tuple(SOS_TRANSITIONS.get(state, {}).keys())


def next_state(current, event):
    """Return the SOS state reached by applying `event` to `current`.

    Returns the next state string on a valid transition, or None if `event` is
    not allowed from `current` (including unknown states/events). Pure function —
    it does not mutate anything; the caller persists the returned state.
    """
    return SOS_TRANSITIONS.get(current, {}).get(event)


# Backwards-/forwards-compatible aliases (explicit names some callers prefer).
def sos_next_state(current, event):
    """Alias of next_state() scoped to the SOS machine name."""
    return next_state(current, event)


# ===========================================================================
# 2. RESPONDER TASK STATE MACHINE  (RESP-01 / RESP-06)
# ===========================================================================
# A verified incident (or an SOS event) hands off to a responder as a TASK with
# an explicit human acknowledgement ladder. RESP-06 bright line: these are the
# ONLY states — there is no "dispatch"/"armed" state, by design.
#
#   received   -> the task landed with the responder (not yet looked at)
#   reviewing  -> responder is assessing it
#   responding -> responder is acting on it
#   closed     -> task complete / stood down (terminal)
TASK_RECEIVED = "received"
TASK_REVIEWING = "reviewing"
TASK_RESPONDING = "responding"
TASK_CLOSED = "closed"

TASK_STATES = (TASK_RECEIVED, TASK_REVIEWING, TASK_RESPONDING, TASK_CLOSED)
TASK_INITIAL = TASK_RECEIVED
TASK_TERMINAL = frozenset({TASK_CLOSED})

# Forward ack ladder. A task may also be closed from any live state (stand-down),
# and an operator may send a task back a step (e.g. responding -> reviewing) if
# new information arrives. We DO allow same-state "no-op" transitions so an
# idempotent re-post of the current state is not treated as illegal.
TASK_TRANSITIONS = {
    TASK_RECEIVED: {TASK_RECEIVED, TASK_REVIEWING, TASK_RESPONDING, TASK_CLOSED},
    TASK_REVIEWING: {TASK_REVIEWING, TASK_RESPONDING, TASK_RECEIVED, TASK_CLOSED},
    TASK_RESPONDING: {TASK_RESPONDING, TASK_REVIEWING, TASK_CLOSED},
    TASK_CLOSED: {TASK_CLOSED},  # terminal (idempotent close only)
}


def task_is_terminal(state):
    """True if the responder task is in a terminal state (closed)."""
    return state in TASK_TERMINAL


def valid_task_transition(a, b):
    """True if a responder task may move from state `a` to state `b`.

    Encodes the RESP-01 ack ladder (received->reviewing->responding->closed),
    plus stand-down-to-closed from any live state, an operator step-back, and
    idempotent same-state moves. Unknown states are rejected.
    """
    if a not in TASK_STATES or b not in TASK_STATES:
        return False
    return b in TASK_TRANSITIONS.get(a, set())


def task_allowed_next(state):
    """Sorted tuple of states a task may move to from `state` (incl. itself)."""
    return tuple(sorted(TASK_TRANSITIONS.get(state, set())))


# ===========================================================================
# 3. ALERT LIFECYCLE  (INT-02 / INT-03)
# ===========================================================================
# Public alerts get a CAP-style lifecycle on top of the existing active/resolved
# storage. PUBLISHED is the live state; UPDATED is a re-published revision;
# CANCELLED is an operator kill-switch (ABU-07); EXPIRED is the TTL outcome.
#
# Only PUBLISHED and UPDATED are "live" (a citizen should still act on them);
# CANCELLED and EXPIRED are dead. alert_is_active() combines the lifecycle state
# with a read-time TTL so a stale PUBLISHED alert auto-expires with no cron —
# mirroring the incident decay model already in the codebase.
ALERT_PUBLISHED = "PUBLISHED"
ALERT_UPDATED = "UPDATED"
ALERT_CANCELLED = "CANCELLED"
ALERT_EXPIRED = "EXPIRED"

ALERT_STATES = (ALERT_PUBLISHED, ALERT_UPDATED, ALERT_CANCELLED, ALERT_EXPIRED)
ALERT_INITIAL = ALERT_PUBLISHED
ALERT_LIVE = frozenset({ALERT_PUBLISHED, ALERT_UPDATED})
ALERT_DEAD = frozenset({ALERT_CANCELLED, ALERT_EXPIRED})

# Allowed lifecycle moves. An alert is published, may be updated repeatedly, and
# ends either cancelled (operator) or expired (TTL). Dead states are terminal.
ALERT_TRANSITIONS = {
    ALERT_PUBLISHED: {ALERT_UPDATED, ALERT_CANCELLED, ALERT_EXPIRED},
    ALERT_UPDATED: {ALERT_UPDATED, ALERT_CANCELLED, ALERT_EXPIRED},
    ALERT_CANCELLED: set(),
    ALERT_EXPIRED: set(),
}

# Default TTL by alert level label (hours). Higher-severity alerts live longer;
# callers may override per-alert. Kept here so the lifecycle module owns the TTL
# policy in one place. Unknown labels fall back to DEFAULT_ALERT_TTL_H.
DEFAULT_ALERT_TTL_H = 24
ALERT_TTL_H = {
    "RED": 24,
    "ORANGE": 12,
    "YELLOW": 6,
    "GREEN": 3,
}


def valid_alert_transition(a, b):
    """True if an alert may move from lifecycle state `a` to `b`."""
    if a not in ALERT_STATES or b not in ALERT_STATES:
        return False
    return b in ALERT_TRANSITIONS.get(a, set())


def alert_expired_by_ttl(created_at, ttl_h, now=None):
    """True if an alert created at `created_at` is older than `ttl_h` hours.

    `created_at` is an ISO string (or datetime). Unparseable/None creation time
    -> False (cannot expire on age we can't measure). `ttl_h` <= 0 -> never
    expires by TTL (treat as no-TTL). `now` is injectable for testing.
    """
    try:
        ttl = float(ttl_h)
    except Exception:
        ttl = 0
    if ttl <= 0:
        return False
    created = _parse_iso(created_at)
    if created is None:
        return False
    now = now or _now()
    age_h = (now - created).total_seconds() / 3600.0
    return age_h > ttl


def alert_is_active(state, created_at, ttl_h, now=None):
    """True if an alert is still LIVE: a live lifecycle state AND within its TTL.

    Combines INT-03 lifecycle (PUBLISHED/UPDATED are live; CANCELLED/EXPIRED are
    dead) with a read-time TTL check so a stale PUBLISHED alert is treated as
    inactive even before a writer flips it to EXPIRED. Unknown state -> False.
    """
    if state not in ALERT_LIVE:
        return False
    return not alert_expired_by_ttl(created_at, ttl_h, now=now)


def ttl_for_level(level_label):
    """Default TTL (hours) for an alert level label (RED/ORANGE/YELLOW/GREEN)."""
    return ALERT_TTL_H.get((level_label or "").upper(), DEFAULT_ALERT_TTL_H)


# ===========================================================================
# 4. DDL  (db.py splices these into SCHEMA_SQLITE / SCHEMA_PG + _migrate)
# ===========================================================================
# Two flavours per object:
#   *_SQLITE  -> INTEGER PRIMARY KEY AUTOINCREMENT, REAL coords
#   *_PG      -> SERIAL PRIMARY KEY, DOUBLE PRECISION coords
# All CREATE statements use IF NOT EXISTS so they are safe to run on every boot
# (matching db.py's existing schema-execute-on-connect pattern). Timestamps are
# stored as TEXT ISO strings to match the rest of the schema. No PII column is
# special-cased here — redaction happens at the API boundary (security.py).
#
# PRIVACY NOTE (PRIV-01): trusted_contacts.address / responders.address /
# deliveries.address hold sensitive handles (phone/WhatsApp). They live server-
# side only and must NEVER be projected onto a public GET. This module only
# *defines* the columns; the api.py layer is responsible for never leaking them.

# --- sos_events: durable SOS state machine (SOS-01) -------------------------
SOS_EVENTS_SQLITE = """
CREATE TABLE IF NOT EXISTS sos_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sos_uuid TEXT,
  created_at TEXT, updated_at TEXT,
  lat REAL, lng REAL,
  message TEXT, mode TEXT,
  state TEXT,
  contact_state TEXT,
  operator TEXT, acked_at TEXT,
  handoff_ref TEXT,
  reporter_hint TEXT,
  closed_at TEXT
);
"""

SOS_EVENTS_PG = """
CREATE TABLE IF NOT EXISTS sos_events (
  id SERIAL PRIMARY KEY,
  sos_uuid TEXT,
  created_at TEXT, updated_at TEXT,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION,
  message TEXT, mode TEXT,
  state TEXT,
  contact_state TEXT,
  operator TEXT, acked_at TEXT,
  handoff_ref TEXT,
  reporter_hint TEXT,
  closed_at TEXT
);
"""

# --- trusted_contacts: a field user's opted-in circle (SOS-03) --------------
TRUSTED_CONTACTS_SQLITE = """
CREATE TABLE IF NOT EXISTS trusted_contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_token TEXT,
  name TEXT, channel TEXT,
  address TEXT,
  created_at TEXT, verified INTEGER DEFAULT 0
);
"""

TRUSTED_CONTACTS_PG = """
CREATE TABLE IF NOT EXISTS trusted_contacts (
  id SERIAL PRIMARY KEY,
  owner_token TEXT,
  name TEXT, channel TEXT,
  address TEXT,
  created_at TEXT, verified INTEGER DEFAULT 0
);
"""

# --- responders: verified responder directory (RESP-01) --------------------
RESPONDERS_SQLITE = """
CREATE TABLE IF NOT EXISTS responders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT, org TEXT,
  role TEXT, state TEXT, lga TEXT,
  channel TEXT, address TEXT,
  active INTEGER DEFAULT 1, created_at TEXT
);
"""

RESPONDERS_PG = """
CREATE TABLE IF NOT EXISTS responders (
  id SERIAL PRIMARY KEY,
  name TEXT, org TEXT,
  role TEXT, state TEXT, lga TEXT,
  channel TEXT, address TEXT,
  active INTEGER DEFAULT 1, created_at TEXT
);
"""

# --- responder_tasks: handoff + ack lifecycle (RESP-01 / RESP-06) ----------
RESPONDER_TASKS_SQLITE = """
CREATE TABLE IF NOT EXISTS responder_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_uuid TEXT, created_at TEXT, updated_at TEXT,
  incident_uuid TEXT,
  alert_key TEXT,
  sos_uuid TEXT,
  responder_id INTEGER,
  state TEXT,
  ack_at TEXT, closed_at TEXT,
  escalate_after TEXT,
  note TEXT, after_action TEXT
);
"""

RESPONDER_TASKS_PG = """
CREATE TABLE IF NOT EXISTS responder_tasks (
  id SERIAL PRIMARY KEY,
  task_uuid TEXT, created_at TEXT, updated_at TEXT,
  incident_uuid TEXT,
  alert_key TEXT,
  sos_uuid TEXT,
  responder_id INTEGER,
  state TEXT,
  ack_at TEXT, closed_at TEXT,
  escalate_after TEXT,
  note TEXT, after_action TEXT
);
"""

# --- deliveries: broadcast/SOS-notify receipts + SIM-mode log (BC-03) ------
# `sim` flags a SIM-mode record so a simulated send is NEVER mistaken for a real
# one (status='sim_delivered'); real sends record provider_ref.
DELIVERIES_SQLITE = """
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT,
  alert_key TEXT,
  sos_uuid TEXT,
  channel TEXT,
  address TEXT,
  status TEXT,
  provider_ref TEXT, sim INTEGER DEFAULT 0
);
"""

DELIVERIES_PG = """
CREATE TABLE IF NOT EXISTS deliveries (
  id SERIAL PRIMARY KEY,
  created_at TEXT,
  alert_key TEXT,
  sos_uuid TEXT,
  channel TEXT,
  address TEXT,
  status TEXT,
  provider_ref TEXT, sim INTEGER DEFAULT 0
);
"""

# --- alert lifecycle columns (INT-03) --------------------------------------
# These are ADD COLUMN statements (not full tables): db.py already owns the
# `alerts` table; _migrate splices these onto it (legacy SQLite + PG). Each is a
# (column_name, sqlite_decl, pg_decl) triple so db.py can loop them exactly like
# its existing structured-signal / incident_uuid migrations. Postgres uses
# ADD COLUMN IF NOT EXISTS; legacy SQLite swallows the duplicate-column error.
ALERT_LIFECYCLE_COLUMNS = (
    ("alert_uuid", "TEXT", "TEXT"),
    ("state", "TEXT", "TEXT"),
    ("version", "INTEGER", "INTEGER"),
    ("expires_at", "TEXT", "TEXT"),
    ("updated_at", "TEXT", "TEXT"),
    ("cancelled_at", "TEXT", "TEXT"),
    ("cancel_reason", "TEXT", "TEXT"),
    ("superseded_by", "TEXT", "TEXT"),
)

# Convenience bundles so db.py can iterate fresh-DB tables in one place.
DDL_SQLITE = (
    SOS_EVENTS_SQLITE,
    TRUSTED_CONTACTS_SQLITE,
    RESPONDERS_SQLITE,
    RESPONDER_TASKS_SQLITE,
    DELIVERIES_SQLITE,
)
DDL_PG = (
    SOS_EVENTS_PG,
    TRUSTED_CONTACTS_PG,
    RESPONDERS_PG,
    RESPONDER_TASKS_PG,
    DELIVERIES_PG,
)

# (table_name -> (sqlite_ddl, pg_ddl)) for targeted _migrate CREATE-IF-NOT-EXISTS.
RESPONSE_TABLES = {
    "sos_events": (SOS_EVENTS_SQLITE, SOS_EVENTS_PG),
    "trusted_contacts": (TRUSTED_CONTACTS_SQLITE, TRUSTED_CONTACTS_PG),
    "responders": (RESPONDERS_SQLITE, RESPONDERS_PG),
    "responder_tasks": (RESPONDER_TASKS_SQLITE, RESPONDER_TASKS_PG),
    "deliveries": (DELIVERIES_SQLITE, DELIVERIES_PG),
}


# ===========================================================================
# 5. SELF-TEST  (python engine/response.py)
# ===========================================================================
if __name__ == "__main__":
    # --- identity ----------------------------------------------------------
    a, b = new_id(), new_id()
    assert len(a) == 32 and a != b, "new_id must be a unique 32-char hex"

    # --- SOS machine: the happy escalation path ----------------------------
    st = SOS_INITIAL
    assert st == SOS_TRIGGERED
    st = next_state(st, "capture_location"); assert st == SOS_LOCATION_CAPTURED
    st = next_state(st, "notify_circle"); assert st == SOS_CIRCLE_NOTIFIED
    st = next_state(st, "delivery_confirmed"); assert st == SOS_DELIVERED
    st = next_state(st, "operator_ack"); assert st == SOS_OPERATOR_ACK
    st = next_state(st, "request_112"); assert st == SOS_HANDOFF_112_REQUESTED
    st = next_state(st, "coordinate"); assert st == SOS_COORDINATED
    st = next_state(st, "mark_safe"); assert st == SOS_SAFE
    st = next_state(st, "close"); assert st == SOS_CLOSED

    # covert/no-GPS path: trigger -> notify circle directly (location optional)
    assert next_state(SOS_TRIGGERED, "notify_circle") == SOS_CIRCLE_NOTIFIED

    # escalation is reachable from every live state and lands in ESCALATED
    for s in (SOS_TRIGGERED, SOS_LOCATION_CAPTURED, SOS_CIRCLE_NOTIFIED,
              SOS_DELIVERED, SOS_OPERATOR_ACK, SOS_HANDOFF_112_REQUESTED,
              SOS_COORDINATED):
        assert next_state(s, "escalate") == SOS_ESCALATED, s
    # an escalated event can be picked back up by an operator
    assert next_state(SOS_ESCALATED, "operator_ack") == SOS_OPERATOR_ACK

    # invalid transitions return None (not an exception)
    assert next_state(SOS_TRIGGERED, "coordinate") is None       # can't coordinate pre-ack
    assert next_state(SOS_CLOSED, "operator_ack") is None        # terminal
    assert next_state(SOS_SAFE, "escalate") is None              # terminal-ish: only close
    assert next_state("NOT_A_STATE", "escalate") is None
    assert next_state(SOS_TRIGGERED, "not_an_event") is None

    # terminal predicate + allowed-events helper
    assert sos_is_terminal(SOS_CLOSED) and sos_is_terminal(SOS_SAFE)
    assert not sos_is_terminal(SOS_TRIGGERED)
    assert set(sos_allowed_events(SOS_CLOSED)) == set()
    assert "operator_ack" in sos_allowed_events(SOS_TRIGGERED)
    # every transition target is itself a known state (no dangling edges)
    for s, evmap in SOS_TRANSITIONS.items():
        assert s in SOS_STATES, s
        for ev, nxt in evmap.items():
            assert ev in SOS_EVENTS, ev
            assert nxt in SOS_STATES, nxt
    # bright line: there is no transition that names dispatch/armed action
    assert all("dispatch" not in ev and "armed" not in ev for ev in SOS_EVENTS)

    # --- responder task machine -------------------------------------------
    assert TASK_INITIAL == TASK_RECEIVED
    assert valid_task_transition("received", "reviewing")
    assert valid_task_transition("reviewing", "responding")
    assert valid_task_transition("responding", "closed")
    assert valid_task_transition("received", "closed")      # stand-down from start
    assert valid_task_transition("responding", "reviewing")  # operator step-back
    assert valid_task_transition("received", "received")     # idempotent no-op
    # illegal / terminal / unknown
    assert not valid_task_transition("closed", "responding")  # terminal
    assert not valid_task_transition("received", "bogus")
    assert not valid_task_transition("bogus", "closed")
    assert not valid_task_transition("responding", "received")  # can't skip back two
    assert task_is_terminal("closed") and not task_is_terminal("received")
    assert valid_task_transition.__doc__  # documented
    # RESP-06: the only states are the four ack states (no dispatch state exists)
    assert set(TASK_STATES) == {"received", "reviewing", "responding", "closed"}

    # --- alert lifecycle ---------------------------------------------------
    assert ALERT_INITIAL == ALERT_PUBLISHED
    assert valid_alert_transition(ALERT_PUBLISHED, ALERT_UPDATED)
    assert valid_alert_transition(ALERT_PUBLISHED, ALERT_CANCELLED)
    assert valid_alert_transition(ALERT_UPDATED, ALERT_EXPIRED)
    assert not valid_alert_transition(ALERT_CANCELLED, ALERT_PUBLISHED)  # terminal
    assert not valid_alert_transition(ALERT_EXPIRED, ALERT_UPDATED)      # terminal
    assert not valid_alert_transition("bogus", ALERT_UPDATED)

    # TTL helper: build timestamps relative to a fixed "now" to stay deterministic.
    now = datetime.datetime(2026, 6, 4, 12, 0, 0)
    fresh = (now - datetime.timedelta(hours=1)).isoformat(timespec="seconds")
    stale = (now - datetime.timedelta(hours=30)).isoformat(timespec="seconds")
    assert alert_expired_by_ttl(stale, 24, now=now) is True
    assert alert_expired_by_ttl(fresh, 24, now=now) is False
    assert alert_expired_by_ttl(stale, 0, now=now) is False     # ttl<=0 -> never
    assert alert_expired_by_ttl(None, 24, now=now) is False     # unknown age -> never
    assert alert_expired_by_ttl("not-a-date", 24, now=now) is False

    # alert_is_active = live lifecycle state AND within TTL
    assert alert_is_active(ALERT_PUBLISHED, fresh, 24, now=now) is True
    assert alert_is_active(ALERT_UPDATED, fresh, 24, now=now) is True
    assert alert_is_active(ALERT_PUBLISHED, stale, 24, now=now) is False   # TTL kill
    assert alert_is_active(ALERT_CANCELLED, fresh, 24, now=now) is False   # dead state
    assert alert_is_active(ALERT_EXPIRED, fresh, 24, now=now) is False
    assert alert_is_active("bogus", fresh, 24, now=now) is False

    # TTL-by-level policy
    assert ttl_for_level("RED") == 24 and ttl_for_level("green") == 3
    assert ttl_for_level("unknown") == DEFAULT_ALERT_TTL_H
    assert ttl_for_level(None) == DEFAULT_ALERT_TTL_H

    # --- DDL sanity: strings are well-formed-ish and dual-mode -------------
    for ddl in DDL_SQLITE:
        assert "CREATE TABLE IF NOT EXISTS" in ddl and "AUTOINCREMENT" in ddl
    for ddl in DDL_PG:
        assert "CREATE TABLE IF NOT EXISTS" in ddl and "SERIAL PRIMARY KEY" in ddl
    # coords use the right column type per backend
    assert "lat REAL" in SOS_EVENTS_SQLITE and "lat DOUBLE PRECISION" in SOS_EVENTS_PG
    assert set(RESPONSE_TABLES) == {
        "sos_events", "trusted_contacts", "responders", "responder_tasks", "deliveries"}
    assert len(DDL_SQLITE) == len(DDL_PG) == 5
    # alert lifecycle columns are (name, sqlite_decl, pg_decl) triples
    names = {c[0] for c in ALERT_LIFECYCLE_COLUMNS}
    assert {"state", "expires_at", "alert_uuid", "cancel_reason"}.issubset(names)
    for c in ALERT_LIFECYCLE_COLUMNS:
        assert len(c) == 3

    # --- DDL actually executes on a real SQLite connection -----------------
    import sqlite3 as _sqlite3
    _c = _sqlite3.connect(":memory:")
    for ddl in DDL_SQLITE:
        _c.executescript(ddl)
    _c.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_key TEXT)")
    for col, sdecl, _p in ALERT_LIFECYCLE_COLUMNS:
        _c.execute("ALTER TABLE alerts ADD COLUMN " + col + " " + sdecl)
    # round-trip an sos_event row through the live schema
    _c.execute(
        "INSERT INTO sos_events (sos_uuid, created_at, state, mode) VALUES (?,?,?,?)",
        (new_id(), now.isoformat(timespec="seconds"), SOS_INITIAL, "covert"))
    _row = _c.execute("SELECT state, mode FROM sos_events").fetchone()
    assert _row[0] == SOS_TRIGGERED and _row[1] == "covert"
    _c.close()

    print("response.py self-test OK")
