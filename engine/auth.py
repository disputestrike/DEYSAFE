"""Operator authentication & RBAC for the DeySafe / SHIELD stdlib server.

Pure standard library (hashlib, hmac, base64, json, time, os, secrets). No
external dependencies, so it drops straight into the http.server backend.

Design (Phase 0, AUTH-01/02/05):
  - Operators are declared in the environment variable DEYSAFE_OPERATORS as a
    comma-separated list of  user:role:sha256pwhex  records, e.g.

        DEYSAFE_OPERATORS="amina:admin:<sha256>,bola:reviewer:<sha256>"

    The password hash is the lowercase hex SHA-256 of the operator's password.
    (Use sha256_hex() below to mint one for the env file.)
  - Login returns a *stateless signed session token* (no server-side session
    store): base64url(payload_json) + "." + base64url(hmac_sha256(payload)).
    The signing key is env DEYSAFE_SECRET; if unset we fall back to a random
    per-boot key (tokens then survive only until the next restart, which is the
    safe default for a single-process demo box).
  - Roles are a strict ladder  viewer < reviewer < verifier < admin. has_role()
    answers "does <held> meet the bar for <needed>?".

FAIL-OPEN CONTRACT (keeps validate.py at 56/56):
  This module *answers questions*; it never decides policy on its own. When the
  operator set is empty (DEYSAFE_OPERATORS unset), check_login() returns None and
  identity() returns None, but the api.py gate is responsible for treating an
  empty roster / empty OPERATOR_TOKEN as "auth disabled -> allow". Nothing here
  blocks; the caller chooses to enforce only when operators are configured.
  auth_enabled() is provided so the caller can make that decision in one place.
"""
import os
import json
import time
import hmac
import base64
import hashlib
import secrets

# --- role ladder -------------------------------------------------------------
ROLES = ("viewer", "reviewer", "verifier", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}

# Default session lifetime (seconds). Operators re-login after this.
TOKEN_TTL = int(os.environ.get("DEYSAFE_TOKEN_TTL", "43200"))  # 12h

_ENV_OPERATORS = "DEYSAFE_OPERATORS"
_ENV_SECRET = "DEYSAFE_SECRET"

# Per-boot random fallback secret — only used when DEYSAFE_SECRET is unset.
_FALLBACK_SECRET = secrets.token_hex(32)


# --- small helpers -----------------------------------------------------------
def sha256_hex(text):
    """Lowercase hex SHA-256 of a string — used to mint password hashes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _secret():
    return os.environ.get(_ENV_SECRET) or _FALLBACK_SECRET


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(payload_b64):
    mac = hmac.new(_secret().encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64u(mac)


def load_operators():
    """Parse DEYSAFE_OPERATORS into {user: {"role":..., "pw":<sha256hex>}}.

    Malformed records (wrong field count, unknown role) are skipped silently so
    one bad entry can't lock everyone out. Returns {} when the env var is unset.
    """
    raw = os.environ.get(_ENV_OPERATORS, "").strip()
    out = {}
    if not raw:
        return out
    for rec in raw.split(","):
        rec = rec.strip()
        if not rec:
            continue
        parts = rec.split(":")
        if len(parts) != 3:
            continue
        user, role, pwhex = parts[0].strip(), parts[1].strip().lower(), parts[2].strip().lower()
        if not user or role not in _RANK or not pwhex:
            continue
        out[user] = {"role": role, "pw": pwhex}
    return out


def auth_enabled():
    """True when at least one operator is configured. The api.py gate uses this
    to stay fail-open (auth disabled) on a fresh box so validate.py stays green."""
    return bool(load_operators())


def has_role(held, needed):
    """Does role `held` satisfy the bar `needed` in the viewer<...<admin ladder?"""
    if held not in _RANK or needed not in _RANK:
        return False
    return _RANK[held] >= _RANK[needed]


def issue_token(user, role, ttl=None):
    """Mint a stateless signed session token for an authenticated operator."""
    now = int(time.time())
    payload = {"u": user, "r": role, "iat": now, "exp": now + int(ttl if ttl is not None else TOKEN_TTL)}
    payload_b64 = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return payload_b64 + "." + _sign(payload_b64)


def check_login(user, pw):
    """Verify user+password against the roster. Returns a session token or None.

    Constant-time password comparison; unknown users still do a compare against a
    dummy hash so timing doesn't reveal whether the username exists.
    """
    ops = load_operators()
    rec = ops.get(user)
    candidate = sha256_hex(pw or "")
    expected = rec["pw"] if rec else ("0" * 64)
    ok = hmac.compare_digest(candidate, expected)
    if rec and ok:
        return issue_token(user, rec["role"])
    return None


def identity(token):
    """Validate a session token's signature + expiry. Returns {"user","role"} or None.

    A token is rejected if: malformed, signature mismatch (constant-time), expired,
    or its user/role is no longer present in the current roster (revocation by env
    edit + restart). Role is taken from the *live* roster, so a demotion takes
    effect immediately even on an unexpired token.
    """
    if not token or not isinstance(token, str) or token.count(".") != 1:
        return None
    payload_b64, sig = token.split(".", 1)
    if not hmac.compare_digest(sig, _sign(payload_b64)):
        return None
    try:
        payload = json.loads(_b64u_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    user = payload.get("u")
    ops = load_operators()
    rec = ops.get(user)
    if not rec:
        return None  # user removed from roster -> token no longer valid
    return {"user": user, "role": rec["role"]}


# --- self-test ---------------------------------------------------------------
if __name__ == "__main__":
    pw = "correct horse battery staple"
    os.environ[_ENV_SECRET] = "test-secret-not-for-prod"
    os.environ[_ENV_OPERATORS] = "amina:admin:%s,bola:reviewer:%s" % (sha256_hex(pw), sha256_hex("hunter2"))

    assert auth_enabled() is True
    ops = load_operators()
    assert set(ops) == {"amina", "bola"} and ops["amina"]["role"] == "admin"

    # ladder
    assert has_role("admin", "verifier") and has_role("verifier", "reviewer")
    assert not has_role("reviewer", "verifier")
    assert not has_role("viewer", "admin")
    assert not has_role("bogus", "viewer")

    # login + identity round-trip
    tok = check_login("amina", pw)
    assert tok and identity(tok) == {"user": "amina", "role": "admin"}
    assert check_login("amina", "wrong") is None
    assert check_login("ghost", "x") is None

    # tamper / expiry / revocation
    assert identity("garbage") is None
    assert identity(tok[:-1] + ("A" if tok[-1] != "A" else "B")) is None
    expired = issue_token("amina", "admin", ttl=-1)
    assert identity(expired) is None
    bola_tok = check_login("bola", "hunter2")
    del os.environ[_ENV_OPERATORS]  # roster now empty
    assert auth_enabled() is False
    assert identity(bola_tok) is None  # revoked once roster is gone

    # malformed roster entries are skipped, good ones survive
    os.environ[_ENV_OPERATORS] = "bad,worse:two,ok:viewer:%s" % sha256_hex("p")
    o2 = load_operators()
    assert set(o2) == {"ok"} and o2["ok"]["role"] == "viewer"

    print("auth.py self-test OK")
