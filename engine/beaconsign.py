"""Signed rotating beacon envelope — anti-spoof for the BLE crowd-relay (BLE-01).

Today `/api/beacon-relay` trusts an arbitrary `{beacon_id, lat, lng}` body: anyone
can POST a registered beacon id with a fake location and re-anchor a missing-person
search (FEEDBACK §D / BLE-01). This module is the pure crypto core of the fix — a
signed, time-boxed, replay-resistant envelope the relay endpoint can require when a
shared secret is configured.

Design rules (mirror security.py / response.py):
  - STDLIB ONLY (hmac, hashlib, time, threading). No DB handle, no env reads, no
    network, no I/O at import. Every public function is pure/deterministic given
    its inputs, EXCEPT the optional in-process replay cache (seen()/verify(mark_seen=
    True)) which is the one tiny piece of state, guarded by a lock. That keeps the
    whole thing trivially unit-testable and safe to import from any request thread.
  - The api.py layer owns policy: it reads DEYSAFE_BEACON_SECRET, decides WHEN to
    require a signature (set -> required; unset -> current permissive behavior), and
    persists the durable nonce/replay store. This module only describes the maths.

What it provides:
  - sign(beacon_id, lat, lng, ts, secret[, nonce])  -> hex HMAC-SHA256 signature
  - verify(payload, secret, max_age_s, ...)          -> (ok, reason); bool-friendly
  - rotate(beacon_id, epoch, secret)                 -> ephemeral rotating id (BLE-02)
  - canonical(beacon_id, lat, lng, ts[, nonce])      -> the exact signed string
  - replay cache: seen(nonce) / remember(nonce) / clear_seen()

Bright lines (FEEDBACK §D):
  - BLE-02: the real beacon_id never has to travel on the wire — rotate() lets a
    device advertise an ephemeral id that the server maps back server-side. This
    module never logs, prints, or persists a beacon_id or secret.
  - A bad signature, a stale/future timestamp, or a replayed nonce all make
    verify() fail CLOSED (the relay rejects with 400); nothing is trusted on the
    strength of the client's word alone.
"""
import hmac
import time
import hashlib
import threading

# Algorithm + signature shape. SHA-256 HMAC -> 64 hex chars. Kept as constants so
# the api/db layer and any client SDK agree on one wire format.
ALGO = "sha256"
SIG_HEX_LEN = 64  # len(hexdigest of sha256)

# Default freshness window (seconds) a signed envelope is accepted within. The api
# layer may pass its own max_age_s; this is the fallback. 120s tolerates clock skew
# and slow store-and-forward relays without leaving a wide replay window.
DEFAULT_MAX_AGE_S = 120

# Allowance (seconds) for a timestamp that is slightly in the FUTURE relative to the
# verifier (client clock running fast). Beyond this we reject as skew/forgery.
DEFAULT_FUTURE_SKEW_S = 60

# Coordinate quantization. Floats are formatted to a fixed number of decimals before
# signing so that a client and server that hold the "same" coordinate but render it
# with different float precision still produce an identical signed string. 5 dp ~=
# 1.1 m at the equator — far finer than any BLE/relay positioning, and a sighting is
# logged at this precision anyway.
COORD_DP = 5

# Reasons verify() can return (stable strings for audit/log without leaking secrets).
OK = "ok"
R_MISSING = "missing_fields"
R_BAD_TS = "bad_timestamp"
R_STALE = "stale"
R_FUTURE = "future_skew"
R_BAD_SIG = "bad_signature"
R_REPLAY = "replayed_nonce"

# --- in-process replay cache (nonce -> first-seen epoch) ----------------------
# This is the ONE piece of module state. It is a best-effort, single-process guard
# so a self-test / single instance rejects an immediate replay without a DB. The
# DURABLE replay store (across restarts / multiple workers) is the api/db layer's
# `beacon_nonces` table; this cache is the in-memory mirror, capped + lockable.
_SEEN = {}
_SEEN_LOCK = threading.Lock()
_SEEN_MAX = 50000  # cap so a long-running process can't grow unbounded


def _enabled_secret(secret):
    """Normalize a secret to bytes, or return None when there is effectively none.

    Accepts str or bytes. Empty/whitespace-only/None -> None so callers can use
    `if beaconsign._enabled_secret(s) is None` to mean "no signing configured".
    """
    if secret is None:
        return None
    if isinstance(secret, bytes):
        return secret if secret.strip() else None
    s = str(secret).strip()
    return s.encode("utf-8") if s else None


def _fmt_coord(v):
    """Format a coordinate to a fixed-precision string for stable signing.

    Quantizes to COORD_DP decimals and normalizes -0.0 to 0.0 so the signed string
    is identical for equivalent inputs regardless of float repr. Raises ValueError
    on a non-numeric/NaN/inf coordinate so a malformed envelope fails loudly at
    sign-time and fails CLOSED (bad_timestamp/missing handled separately) at verify.
    """
    f = float(v)  # may raise ValueError/TypeError -> caller treats as invalid
    if f != f or f in (float("inf"), float("-inf")):  # NaN / inf
        raise ValueError("non-finite coordinate")
    s = "%.*f" % (COORD_DP, f)
    if s in ("-0." + "0" * COORD_DP,):  # normalize negative zero
        s = "0." + "0" * COORD_DP
    return s


def _coerce_ts(ts):
    """Coerce a timestamp to an int epoch-seconds, or None if not coercible.

    Accepts int/float/numeric-string. We sign the *integer* second so sub-second
    float jitter between client and server can't change the signed string.
    """
    try:
        return int(float(ts))
    except (TypeError, ValueError):
        return None


def canonical(beacon_id, lat, lng, ts, nonce=""):
    """Build the exact string that gets HMAC'd.

    Format (pipe-delimited, fixed field order, no JSON so there is zero ambiguity):
        v1|<beacon_id>|<lat 5dp>|<lng 5dp>|<ts int>|<nonce>

    `nonce` is optional ("" when unused). Versioned with a leading "v1" so the wire
    format can evolve without silently accepting an old-format signature. Raises
    ValueError if beacon_id is empty or coords/ts are not finite/numeric.
    """
    bid = (str(beacon_id) if beacon_id is not None else "").strip()
    if not bid:
        raise ValueError("beacon_id required")
    its = _coerce_ts(ts)
    if its is None:
        raise ValueError("ts must be numeric epoch seconds")
    lat_s = _fmt_coord(lat)
    lng_s = _fmt_coord(lng)
    nstr = "" if nonce is None else str(nonce).strip()
    return "v1|%s|%s|%s|%d|%s" % (bid, lat_s, lng_s, its, nstr)


def sign(beacon_id, lat, lng, ts, secret, nonce=""):
    """Return the hex HMAC-SHA256 signature for a beacon envelope.

    Deterministic: identical inputs (and the same secret) always yield the same
    64-char hex string. Raises ValueError when the secret is empty (you cannot sign
    without a key) or when beacon_id/coords/ts are invalid (via canonical()).
    """
    key = _enabled_secret(secret)
    if key is None:
        raise ValueError("secret required to sign")
    msg = canonical(beacon_id, lat, lng, ts, nonce=nonce).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify(payload, secret, max_age_s=DEFAULT_MAX_AGE_S, now=None,
           future_skew_s=DEFAULT_FUTURE_SKEW_S, mark_seen=True, replay_seen=None):
    """Verify a signed beacon envelope. Returns (ok: bool, reason: str).

    `payload` is a dict carrying at least {beacon_id, lat, lng, ts, sig} and
    optionally {nonce}. Checks, in order (all FAIL CLOSED):
      1. required fields present + coords/ts well-formed                -> R_MISSING/R_BAD_TS
      2. timestamp within [now - max_age_s, now + future_skew_s]        -> R_STALE / R_FUTURE
      3. HMAC signature matches (constant-time compare)                 -> R_BAD_SIG
      4. nonce (if present) not already seen (replay protection)        -> R_REPLAY

    Ordering note: freshness + signature are checked BEFORE the replay cache is
    touched, so a forged/garbage payload can never poison the nonce store. The
    nonce is only remembered after the signature has been proven authentic.

    Args:
      max_age_s     : how old (seconds) a ts may be. <=0 disables the staleness
                      check (signature + replay still enforced).
      future_skew_s : how far in the future a ts may be before rejection.
      now           : injectable epoch seconds for deterministic tests.
      mark_seen     : when True (default) and a nonce is present and everything
                      else passed, record the nonce in the in-process replay cache.
                      Set False for a pure read-only check.
      replay_seen   : optional callable(nonce)->bool to consult an EXTERNAL replay
                      store (e.g. the db `beacon_nonces` table). When provided it is
                      consulted IN ADDITION to the in-process cache; either reporting
                      the nonce as seen -> R_REPLAY. The api layer passes db-backed
                      durability here; the in-process cache covers a single process.

    Use `ok, reason = verify(...)`. The tuple is truthy-friendly: callers that want
    a plain bool can do `verify(...)[0]`.
    """
    if not isinstance(payload, dict):
        return (False, R_MISSING)
    key = _enabled_secret(secret)
    if key is None:
        # No secret configured at this layer -> we cannot assert authenticity.
        # Policy (require-or-permit) belongs to the caller; here, no key == cannot
        # verify == fail closed.
        return (False, R_MISSING)

    beacon_id = payload.get("beacon_id")
    sig = payload.get("sig") or payload.get("signature")
    if not beacon_id or not sig:
        return (False, R_MISSING)

    # Build the canonical string; any malformed coord/ts surfaces here.
    nonce = payload.get("nonce") or ""
    try:
        msg = canonical(beacon_id, payload.get("lat"), payload.get("lng"),
                        payload.get("ts"), nonce=nonce)
    except ValueError:
        # Distinguish a bad timestamp (common, benign clock issue) from other
        # malformed input for clearer audit, but both fail closed.
        if _coerce_ts(payload.get("ts")) is None:
            return (False, R_BAD_TS)
        return (False, R_MISSING)

    # --- freshness window -----------------------------------------------------
    its = _coerce_ts(payload.get("ts"))  # canonical() guarantees this is not None here
    now = int(now if now is not None else time.time())
    try:
        max_age = float(max_age_s)
    except (TypeError, ValueError):
        max_age = DEFAULT_MAX_AGE_S
    try:
        fskew = float(future_skew_s)
    except (TypeError, ValueError):
        fskew = DEFAULT_FUTURE_SKEW_S
    if fskew > 0 and its - now > fskew:
        return (False, R_FUTURE)
    if max_age > 0 and now - its > max_age:
        return (False, R_STALE)

    # --- signature (constant-time) -------------------------------------------
    expected = hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(sig).strip().lower()):
        return (False, R_BAD_SIG)

    # --- replay (only after the envelope is proven authentic) ----------------
    if nonce:
        if seen(nonce):
            return (False, R_REPLAY)
        if callable(replay_seen):
            try:
                if replay_seen(nonce):
                    return (False, R_REPLAY)
            except Exception:
                # An external store error must not silently allow a replay.
                return (False, R_REPLAY)
        if mark_seen:
            remember(nonce, first_seen=now)

    return (True, OK)


def is_valid(payload, secret, **kw):
    """Convenience bool wrapper around verify() -> True/False only."""
    return verify(payload, secret, **kw)[0]


# --- rotating ephemeral ids (BLE-02) -----------------------------------------
def rotate(beacon_id, epoch, secret, length=12):
    """Derive a rotating ephemeral id for `beacon_id` at a given time `epoch`.

    So the real, stable beacon_id need never be advertised over the air or sent on
    the wire (BLE-02): the device emits rotate(real_id, current_epoch, secret) and
    the server, knowing the secret, recomputes the same value to map it back.

    Deterministic: same (beacon_id, epoch, secret) -> same id. Different epoch ->
    different id (unlinkable to an observer without the secret). Returns a lowercase
    hex string of `length` chars (truncated HMAC; default 12 -> 48 bits, plenty for
    a per-epoch namespace while staying short enough to advertise).
    """
    key = _enabled_secret(secret)
    if key is None:
        raise ValueError("secret required to rotate")
    bid = (str(beacon_id) if beacon_id is not None else "").strip()
    if not bid:
        raise ValueError("beacon_id required")
    try:
        ep = int(epoch)
    except (TypeError, ValueError):
        raise ValueError("epoch must be an integer")
    msg = ("rot1|%s|%d" % (bid, ep)).encode("utf-8")
    full = hmac.new(key, msg, hashlib.sha256).hexdigest()
    n = max(4, min(int(length), SIG_HEX_LEN))
    return full[:n]


def epoch_for(ts, window_s=900):
    """Bucket an epoch-seconds timestamp into a rotation window index.

    Pairs with rotate(): both device and server compute epoch_for(now) so an id
    stays stable for `window_s` (default 15 min) then rotates. Returns an int.
    """
    its = _coerce_ts(ts)
    if its is None:
        its = int(time.time())
    w = int(window_s) if window_s else 900
    if w <= 0:
        w = 900
    return its // w


# --- replay cache helpers -----------------------------------------------------
def seen(nonce):
    """True if `nonce` is already in the in-process replay cache."""
    if not nonce:
        return False
    with _SEEN_LOCK:
        return str(nonce) in _SEEN


def remember(nonce, first_seen=None):
    """Record `nonce` as seen (idempotent). Returns False if it was already
    present (i.e. this is a replay), True if newly recorded."""
    if not nonce:
        return False
    n = str(nonce)
    ts = int(first_seen if first_seen is not None else time.time())
    with _SEEN_LOCK:
        if n in _SEEN:
            return False
        # Opportunistic cap: drop the oldest entries if we hit the ceiling. This is
        # a coarse trim (the durable store is the db); it just bounds memory.
        if len(_SEEN) >= _SEEN_MAX:
            for old in sorted(_SEEN, key=_SEEN.get)[: _SEEN_MAX // 10 or 1]:
                _SEEN.pop(old, None)
        _SEEN[n] = ts
        return True


def clear_seen():
    """Empty the in-process replay cache (test hygiene / single-process reset)."""
    with _SEEN_LOCK:
        _SEEN.clear()


# --- self-test ---------------------------------------------------------------
if __name__ == "__main__":
    SECRET = "case-secret-9f2a"
    bid = "BX-9f2a"
    t = 1_750_000_000  # fixed epoch for deterministic assertions

    # canonical() is stable, versioned, fixed-precision, order-fixed
    c1 = canonical(bid, 11.6200000, 7.95, t)
    c2 = canonical(bid, 11.62, 7.9500001, t)  # same to 5dp -> same string
    assert c1 == c2 == "v1|BX-9f2a|11.62000|7.95000|1750000000|", c1
    # negative-zero normalization + nonce field
    assert canonical(bid, -0.0, 0.0, t, nonce="abc").endswith("|abc")
    assert "|0.00000|" in canonical(bid, -0.0, 0.0, t)

    # sign() is deterministic, 64 hex chars, key-sensitive
    s = sign(bid, 11.62, 7.95, t, SECRET)
    assert len(s) == SIG_HEX_LEN and all(ch in "0123456789abcdef" for ch in s), s
    assert sign(bid, 11.62, 7.95, t, SECRET) == s              # deterministic
    assert sign(bid, 11.62, 7.95, t, "other-secret") != s      # key-sensitive
    assert sign(bid, 11.62, 7.96, t, SECRET) != s              # coord-sensitive

    # you cannot sign without a secret
    try:
        sign(bid, 11.62, 7.95, t, "")
        assert False, "empty secret must raise"
    except ValueError:
        pass

    # --- happy path: a fresh, correctly-signed envelope verifies ------------
    clear_seen()
    env = {"beacon_id": bid, "lat": 11.62, "lng": 7.95, "ts": t, "sig": s}
    ok, why = verify(env, SECRET, max_age_s=300, now=t)
    assert ok and why == OK, (ok, why)
    assert verify(env, SECRET, max_age_s=300, now=t + 10)[0] is True  # within window

    # uppercase-hex signature is accepted (we lower() before compare)
    env_upper = dict(env, sig=s.upper())
    assert verify(env_upper, SECRET, max_age_s=300, now=t)[0] is True

    # --- tamper: any change to a signed field fails closed (R_BAD_SIG) ------
    assert verify(dict(env, lat=11.63), SECRET, max_age_s=300, now=t) == (False, R_BAD_SIG)
    assert verify(dict(env, beacon_id="BX-evil"), SECRET, max_age_s=300, now=t) == (False, R_BAD_SIG)
    assert verify(env, "wrong-secret", max_age_s=300, now=t) == (False, R_BAD_SIG)

    # --- freshness window: stale + future both rejected ---------------------
    assert verify(env, SECRET, max_age_s=120, now=t + 600) == (False, R_STALE)
    assert verify(env, SECRET, max_age_s=120, now=t - 600) == (False, R_FUTURE)
    # max_age_s <= 0 disables the staleness check (signature still required)
    assert verify(env, SECRET, max_age_s=0, now=t + 10 ** 6)[0] is True

    # --- missing / malformed -------------------------------------------------
    assert verify({"beacon_id": bid, "lat": 1, "lng": 2, "ts": t}, SECRET)[0] is False  # no sig
    assert verify({"sig": s, "lat": 1, "lng": 2, "ts": t}, SECRET)[0] is False           # no beacon_id
    assert verify(dict(env, ts="not-a-number"), SECRET, now=t) == (False, R_BAD_TS)
    assert verify("not-a-dict", SECRET)[0] is False
    # no secret at this layer -> cannot verify -> fail closed
    assert verify(env, "", now=t)[0] is False
    assert verify(env, None, now=t)[0] is False

    # --- replay protection ---------------------------------------------------
    clear_seen()
    nonce = "nonce-0001"
    s_n = sign(bid, 11.62, 7.95, t, SECRET, nonce=nonce)
    env_n = {"beacon_id": bid, "lat": 11.62, "lng": 7.95, "ts": t, "sig": s_n, "nonce": nonce}
    first = verify(env_n, SECRET, max_age_s=300, now=t)        # records the nonce
    assert first == (True, OK), first
    second = verify(env_n, SECRET, max_age_s=300, now=t)       # same nonce again -> replay
    assert second == (False, R_REPLAY), second
    # a read-only check (mark_seen=False) does not consume the nonce
    clear_seen()
    assert verify(env_n, SECRET, max_age_s=300, now=t, mark_seen=False)[0] is True
    assert verify(env_n, SECRET, max_age_s=300, now=t, mark_seen=False)[0] is True  # still fine
    # an external replay store is consulted too
    clear_seen()
    assert verify(env_n, SECRET, max_age_s=300, now=t,
                  replay_seen=lambda n: True) == (False, R_REPLAY)
    # a forged envelope NEVER poisons the replay cache (sig checked before nonce)
    clear_seen()
    forged = dict(env_n, sig="0" * 64)
    assert verify(forged, SECRET, max_age_s=300, now=t) == (False, R_BAD_SIG)
    assert seen(nonce) is False, "forged envelope must not record the nonce"

    # replay cache helpers
    clear_seen()
    assert remember("n1") is True and remember("n1") is False  # idempotent
    assert seen("n1") is True and seen("missing") is False
    clear_seen()
    assert seen("n1") is False

    # --- rotating ephemeral ids (BLE-02) ------------------------------------
    e0 = epoch_for(t)
    r0 = rotate(bid, e0, SECRET)
    assert len(r0) == 12 and all(ch in "0123456789abcdef" for ch in r0), r0
    assert rotate(bid, e0, SECRET) == r0                       # deterministic
    assert rotate(bid, e0 + 1, SECRET) != r0                   # rotates per epoch
    assert rotate("BX-other", e0, SECRET) != r0                # per-beacon
    assert rotate(bid, e0, "other-secret") != r0               # secret-bound
    assert rotate(bid, e0, SECRET, length=8) == r0[:8]         # length honored
    # epoch bucketing: stable within window, advances across it
    assert epoch_for(t) == epoch_for(t + 1)
    assert epoch_for(t + 1000, window_s=900) == epoch_for(t, window_s=900) + 1
    try:
        rotate("", e0, SECRET)
        assert False, "empty beacon_id must raise"
    except ValueError:
        pass

    # the real beacon_id is recoverable to a server that knows the secret +
    # candidate set: recompute rotate() for each known beacon and match.
    known = {"BX-9f2a", "BX-1111", "BX-2222"}
    advertised = rotate("BX-9f2a", e0, SECRET)
    matched = [k for k in known if rotate(k, e0, SECRET) == advertised]
    assert matched == ["BX-9f2a"], matched

    print("beaconsign.py self-test OK")
