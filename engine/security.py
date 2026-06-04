"""Pure security helpers for DeySafe / SHIELD — stdlib only, no side effects.

Bundles the small, well-tested primitives the Phase 0 fixes need so they live in
one auditable place:

  - new_uuid()              immutable incident identity (INT-01)
  - INCIDENT_TYPES / valid_type()   controlled vocabulary (ABU-09)
  - redact_missing()        public flyer vs. operator view (PRIV-01 / BLE-02)
  - audit_hash()            tamper-evident decision chain (PRIV-05)

Everything here is a pure function: deterministic given its inputs (except
new_uuid), no DB, no env, no I/O. That makes it trivial to unit-test and safe to
call from any request thread.
"""
import json
import uuid
import hashlib

# --- immutable identity (INT-01) --------------------------------------------
def new_uuid():
    """A fresh immutable id for an incident/event lineage (uuid4 hex, 32 chars)."""
    return uuid.uuid4().hex


# --- controlled incident vocabulary (ABU-09) --------------------------------
# Arbitrary client-supplied "type" strings must never become real incident types.
# Anything outside this whitelist is coerced to OTHER so it still gets captured
# but is clearly flagged for an operator instead of minting a fake category.
OTHER = "other_needs_review"
INCIDENT_TYPES = (
    "kidnapping",
    "banditry_attack",
    "armed_robbery",
    "missing_person",
    "police_misconduct",
    OTHER,
)
_TYPE_SET = set(INCIDENT_TYPES)

# Common alias spellings mapped onto the canonical vocabulary.
_TYPE_ALIASES = {
    "abduction": "kidnapping",
    "kidnap": "kidnapping",
    "banditry": "banditry_attack",
    "bandit_attack": "banditry_attack",
    "robbery": "armed_robbery",
    "missing": "missing_person",
    "missing_persons": "missing_person",
    "police_brutality": "police_misconduct",
}


def valid_type(t):
    """Normalize a client-supplied incident type to the controlled vocabulary.

    Returns a canonical type from INCIDENT_TYPES; unknown / empty / junk input
    becomes OTHER ('other_needs_review') so it is captured but never silently
    promoted to a fabricated category.
    """
    key = (t or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not key:
        return OTHER
    if key in _TYPE_SET:
        return key
    return _TYPE_ALIASES.get(key, OTHER)


# --- PII redaction (PRIV-01 / BLE-02) ---------------------------------------
# Fields that may appear on the PUBLIC flyer. Anything not in this set is dropped
# for unauthenticated callers. Note the deliberate absence of exact_place, lat,
# lng, last_seen, vehicle, clothing, direction, beacon_id, and raw sightings.
PUBLIC_FIELDS = (
    "id", "age", "count", "status", "created_at",
)
# Sensitive fields that must NEVER leave the server for a public/anon caller.
SENSITIVE_FIELDS = (
    "exact_place", "lat", "lng", "last_seen", "description",
    "vehicle", "clothing", "direction", "beacon_id",
)


def _first_name_initial(name):
    """'Aisha Bello' -> 'Aisha B.'  — keeps a human-recognisable label on the
    public flyer without publishing the full legal name."""
    parts = [p for p in (name or "").strip().split() if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return "%s %s." % (parts[0], parts[1][0].upper())


def _fuzz_area(case):
    """Public locality label: the town/area ('place'), never the exact place.
    Exact coordinates are not emitted; the search radius is the only locating
    signal the public flyer carries (set by the caller from radius logic)."""
    return (case.get("place") or "").strip()


def redact_missing(case, restricted=False):
    """Project a missing-person row to the appropriate audience.

    restricted=False (PUBLIC FLYER): redacted dict — first-name + initial, fuzzed
      area (town only), age/count/status. NO exact_place, NO beacon_id, NO
      vehicle/clothing/direction, NO exact coordinates, NO private sightings.
    restricted=True (OPERATOR / RESPONDER): the full case is returned unchanged
      (caller is already authenticated and authorised for exact detail).

    `case` is a dict (e.g. a row from the `missing` table). The input is never
    mutated.
    """
    if restricted:
        # Operator view: hand back a *copy* of everything as-is.
        return dict(case)

    out = {}
    for f in PUBLIC_FIELDS:
        if f in case and case[f] is not None:
            out[f] = case[f]
    out["name"] = _first_name_initial(case.get("name"))
    out["area"] = _fuzz_area(case)          # town-level locality only
    out["redacted"] = True                  # explicit marker for the client/UI
    # Belt-and-braces: guarantee no sensitive key ever survives the projection.
    for f in SENSITIVE_FIELDS:
        out.pop(f, None)
    return out


# --- tamper-evident audit chain (PRIV-05) -----------------------------------
def audit_hash(prev_hash, row_dict):
    """SHA-256 hex linking this audit/decision row to the previous one.

    hash = sha256(prev_hash + canonical_json(row_dict)). Using sorted-key,
    separator-tight JSON makes the canonical form stable regardless of dict
    ordering, so the chain is reproducible on export and any retroactive edit to
    an earlier row breaks every subsequent hash (tamper-evident, append-only).
    The genesis row uses prev_hash="" (or None).
    """
    prev = prev_hash or ""
    canon = json.dumps(row_dict, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()


# --- self-test ---------------------------------------------------------------
if __name__ == "__main__":
    # uuid
    u1, u2 = new_uuid(), new_uuid()
    assert len(u1) == 32 and u1 != u2

    # controlled vocabulary
    assert valid_type("kidnapping") == "kidnapping"
    assert valid_type("  Abduction ") == "kidnapping"
    assert valid_type("armed-robbery") == "armed_robbery"
    assert valid_type("made_up_type") == OTHER
    assert valid_type("") == OTHER
    assert valid_type(None) == OTHER

    # redaction — public flyer hides everything sensitive
    case = {
        "id": 7, "name": "Aisha Bello", "age": "12", "count": 3, "status": "active",
        "place": "Kankara", "exact_place": "GSS Kankara, Block C", "created_at": "2026-06-01",
        "lat": 11.62, "lng": 7.95, "last_seen": "yesterday 6pm",
        "vehicle": "white Hilux", "clothing": "blue uniform", "direction": "north",
        "beacon_id": "BX-9f2a", "description": "tall",
    }
    pub = redact_missing(case, restricted=False)
    assert pub["name"] == "Aisha B." and pub["area"] == "Kankara"
    assert pub["age"] == "12" and pub["status"] == "active" and pub["redacted"] is True
    for leak in ("exact_place", "lat", "lng", "last_seen", "vehicle", "clothing",
                 "direction", "beacon_id", "description"):
        assert leak not in pub, ("leaked %s" % leak)
    # operator view keeps everything and does not mutate the source
    full = redact_missing(case, restricted=True)
    assert full["beacon_id"] == "BX-9f2a" and full["exact_place"].startswith("GSS")
    assert "beacon_id" in case  # original untouched

    # single-name + empty-name edge cases
    assert redact_missing({"name": "Musa", "place": "Zaria"})["name"] == "Musa"
    assert redact_missing({"name": "", "place": ""})["name"] == ""

    # audit hash chain — deterministic, order-independent, tamper-evident
    g = audit_hash("", {"actor": "amina", "decision": "verified", "uuid": u1})
    g2 = audit_hash(None, {"uuid": u1, "decision": "verified", "actor": "amina"})
    assert g == g2 and len(g) == 64
    nxt = audit_hash(g, {"actor": "bola", "decision": "dismissed", "uuid": u2})
    assert nxt != g
    # changing the genesis row changes the next link
    g_tampered = audit_hash("", {"actor": "mallory", "decision": "verified", "uuid": u1})
    assert audit_hash(g_tampered, {"actor": "bola", "decision": "dismissed", "uuid": u2}) != nxt

    print("security.py self-test OK")
