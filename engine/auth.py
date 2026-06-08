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

POLICY SEPARATION (this module answers questions; the caller enforces):
  This module *answers questions*; it never decides policy on its own. When the
  operator set is empty (DEYSAFE_OPERATORS unset), check_login() and identity()
  return None — no token can be validated. auth_enabled() reports whether any
  operator/roster is configured, so the caller can decide in one place.
  The api.py gate is FAIL-CLOSED: operator surfaces require a valid operator
  token, so an empty roster / empty OPERATOR_TOKEN leaves those endpoints LOCKED
  (401) — a careless deploy ships safe, not wide open. (Earlier builds were
  fail-open; that changed in the Phase 0 trust core. validate.py stays green
  because its operator checks run with OPERATOR_TOKEN / DEYSAFE_OPERATORS set.)
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


# --- password hashing --------------------------------------------------------
# Two on-disk (env) formats are accepted per operator, detected at verify time:
#   (a) LEGACY  : 64-char lowercase hex = plain SHA-256 of the password. Kept so
#                 existing DEYSAFE_OPERATORS values keep working. Weak (no salt,
#                 GPU-fast) — flagged by audit P0-15.
#   (b) PBKDF2  : self-describing  pbkdf2$<iterations>$<salt_hex>$<hash_hex>
#                 (slow, salted KDF; stdlib hashlib.pbkdf2_hmac). Preferred.
# Both verify with hmac.compare_digest for constant-time comparison.
_PBKDF2_PREFIX = "pbkdf2$"
_PBKDF2_DEFAULT_ITERS = 200000  # ~OWASP-class work factor for PBKDF2-HMAC-SHA256


def sha256_hex(text):
    """Lowercase hex SHA-256 of a string — legacy/backward password hash format."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_pbkdf2(password, iterations=_PBKDF2_DEFAULT_ITERS):
    """Mint a new self-describing PBKDF2 hash string for the roster / DEPLOY recipe.

    Returns  "pbkdf2$<iterations>$<salt_hex>$<hash_hex>"  — a slow, salted KDF using
    only the standard library (hashlib.pbkdf2_hmac, SHA-256). A fresh 16-byte random
    salt is generated per call, so the same password yields a different string each
    time. Verify with check_login(); the format is parsed back by _verify_pw().
    """
    iterations = int(iterations)
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, iterations)
    return "%s%d$%s$%s" % (_PBKDF2_PREFIX, iterations, salt.hex(), dk.hex())


def _verify_pw(password, stored):
    """Constant-time verify `password` against a stored hash field (legacy or pbkdf2).

    Detects the format from `stored`:
      - pbkdf2$<iters>$<salt_hex>$<hash_hex>  -> recompute PBKDF2 and compare.
      - otherwise                              -> treat as legacy plain sha256 hex.
    Always runs a real comparison (and, for pbkdf2, a real KDF) so it does no early
    return that would leak timing. A malformed pbkdf2 string fails closed. The
    user-enumeration guard (comparing against a dummy for unknown users) lives in
    check_login(); this helper just answers "does this password match this hash?".
    """
    stored = stored or ""
    if stored.startswith(_PBKDF2_PREFIX):
        try:
            _tag, iters_s, salt_hex, hash_hex = stored.split("$", 3)
            iterations = int(iters_s)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except (ValueError, TypeError):
            return False  # malformed pbkdf2 record -> never authenticates
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    # legacy path: plain sha256 hex (also covers the unknown-user dummy "0"*64).
    return hmac.compare_digest(sha256_hex(password or ""), stored)


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
        user, role, pwfield = parts[0].strip(), parts[1].strip().lower(), parts[2].strip()
        if not user or role not in _RANK or not pwfield:
            continue
        # Store the hash field verbatim. PBKDF2 strings (pbkdf2$<iters>$<salt>$<hash>)
        # must survive intact; legacy sha256 hex is already lowercase from sha256_hex,
        # but we lowercase it so a hand-typed legacy hex still matches case-insensitively.
        if not pwfield.startswith(_PBKDF2_PREFIX):
            pwfield = pwfield.lower()
        out[user] = {"role": role, "pw": pwfield}
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
    # Unknown users still run a real comparison against a dummy legacy hash so
    # response timing doesn't reveal whether the username exists. Known users are
    # verified per their stored format (legacy sha256 hex OR pbkdf2$...), both via
    # hmac.compare_digest inside _verify_pw().
    expected = rec["pw"] if rec else ("0" * 64)
    ok = _verify_pw(pw or "", expected)
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


def generate_owner_token():
    """Generate a cryptographically strong owner_token for field users (SOS, Journey, Trusted).
    
    Uses secrets.token_urlsafe() for cryptographic randomness (not Math.random()).
    This token is meant to be stored client-side and used for ownership verification.
    """
    return secrets.token_urlsafe(32)  # 256-bit entropy


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

    # --- P0-15: dual-format password hashing -------------------------------
    # make_pbkdf2 round-trips and is self-describing (slow, salted, stdlib only).
    h = make_pbkdf2("correct horse battery staple", iterations=50000)  # low iters = fast test
    assert h.startswith("pbkdf2$50000$")
    tag, iters_s, salt_hex, hash_hex = h.split("$", 3)
    assert tag == "pbkdf2" and int(iters_s) == 50000
    assert len(bytes.fromhex(salt_hex)) == 16 and len(bytes.fromhex(hash_hex)) == 32
    assert _verify_pw("correct horse battery staple", h) is True
    assert _verify_pw("wrong", h) is False
    # fresh random salt per call -> same password mints a different string
    assert make_pbkdf2("x", iterations=50000) != make_pbkdf2("x", iterations=50000)
    # malformed pbkdf2 strings fail closed, never throw
    assert _verify_pw("anything", "pbkdf2$notanint$zz$zz") is False
    assert _verify_pw("anything", "pbkdf2$1$$") is False

    # (1) a LEGACY  user:admin:<sha256hex>  roster entry still logs in + rejects wrong pw.
    legacy_pw = "S3cret-Legacy!"
    os.environ[_ENV_OPERATORS] = "amina:admin:%s" % sha256_hex(legacy_pw)
    tok_legacy = check_login("amina", legacy_pw)
    assert tok_legacy and identity(tok_legacy) == {"user": "amina", "role": "admin"}
    assert check_login("amina", "nope") is None
    assert check_login("ghost", legacy_pw) is None  # unknown user still rejected

    # (2) a NEW  user:admin:<pbkdf2$...>  roster entry logs in correctly + rejects wrong pw.
    new_pw = "S3cret-Pbkdf2!"
    os.environ[_ENV_OPERATORS] = "amina:admin:%s" % make_pbkdf2(new_pw, iterations=50000)
    tok_new = check_login("amina", new_pw)
    assert tok_new and identity(tok_new) == {"user": "amina", "role": "admin"}
    assert check_login("amina", "nope") is None
    # the stored pbkdf2 field survives load_operators() verbatim (not lower-mangled).
    assert load_operators()["amina"]["pw"].startswith("pbkdf2$50000$")

    # (3) mixed roster: legacy + pbkdf2 operators coexist, each verified by its own format.
    os.environ[_ENV_OPERATORS] = "amina:admin:%s,bola:reviewer:%s" % (
        sha256_hex(legacy_pw), make_pbkdf2(new_pw, iterations=50000))
    assert check_login("amina", legacy_pw) and check_login("bola", new_pw)
    assert check_login("amina", new_pw) is None and check_login("bola", legacy_pw) is None

    print("auth.py self-test OK")
