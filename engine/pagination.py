"""Pagination primitive for DeySafe / SHIELD list endpoints (PERF-02).

The audit (FEEDBACK §J / PERF-02) flags that *every* list endpoint returns its
full dataset: megabyte JSON bodies that freeze the DOM on a low-end phone over a
2G link. This module is the one small, auditable place that turns a query string
into a clamped (limit, offset) window and slices a list into a page envelope the
api.py GET handlers can return verbatim.

Design rules (mirror security.py / response.py / broadcast.py):
  - STDLIB ONLY. No DB handle, no env reads, no network, no I/O. Both public
    functions are pure/deterministic given their inputs, so they are trivially
    unit-testable and safe to call from any request thread, and api.py can import
    this without side effects.
  - FAIL-SOFT, NEVER RAISE on caller input. A field phone on a flaky link sends
    garbage query strings; parse() must coerce anything ("abc", "-5", "999999",
    None, a list) into a sane window rather than 500-ing. Bad input clamps to the
    defaults/caps; it does not throw.

GATE-SAFETY (the hard rule): validate.py (56/56) and validate_security.py (17/17)
read FULL lists. The default page size must therefore EXCEED the gate fixtures'
row counts so an un-paginated gate call still receives every row on page 1. With
DEFAULT_LIMIT=100 (and MAX_LIMIT=500) the gates' small datasets fit on one page
untouched, so wiring page() behind a list endpoint cannot regress them.

CONTRACT (the shape api.py depends on):
  parse(qs) -> {"limit": int, "offset": int}
      qs may be a raw query string ("limit=20&offset=40", with or without a
      leading "?"), an already-parsed dict ({"limit": "20"} or
      {"limit": ["20"]} as urllib.parse.parse_qs yields), or None. limit is
      clamped to [1, MAX_LIMIT] defaulting to DEFAULT_LIMIT; offset is clamped to
      >= 0 defaulting to 0. "cursor" is accepted as an offset alias (the audit
      says "limit/cursor") so a forward-only cursor == the next_offset we hand
      back works without a second code path.

  page(items, limit, offset) -> {
      "items":       the offset:offset+limit slice (a NEW list, never the input),
      "total":       len(items) BEFORE slicing,
      "limit":       the effective limit applied,
      "offset":      the effective offset applied,
      "next_offset": offset+limit if more rows remain after this page, else None,
  }
      limit/offset are themselves re-clamped here so page() is safe to call with
      raw ints too (callers that already have a window, or pass parse()'s output
      straight through). next_offset is None on the last page so a client can
      loop `while r["next_offset"] is not None` and stop cleanly.

Typical api.py usage (illustrative — not wired here; api.py owns that):
    win = pagination.parse(self.parsed_qs)        # {"limit", "offset"}
    rows = db.all_incidents(...)                   # full list from the DB layer
    return self._json(pagination.page(rows, **win))
"""

# --- Tunables (kept module-level so api.py / tests can read the same source) ---
# DEFAULT_LIMIT MUST stay >= the largest list the validate.py / validate_security.py
# fixtures produce, or an un-paginated gate read would lose rows and regress.
DEFAULT_LIMIT = 100   # generous default: gate fixtures fit on page 1 untouched
MAX_LIMIT = 500       # hard ceiling so one request can't pull a megabyte payload
MIN_LIMIT = 1         # a page always returns at least one row's worth of window

# Query-string keys we accept. "cursor" aliases "offset" so the forward-only
# cursor we emit as next_offset round-trips through the same parser (the audit
# wording is "limit/cursor"); an explicit "offset" wins if both are present.
_LIMIT_KEYS = ("limit", "per_page", "count")
_OFFSET_KEYS = ("offset", "cursor", "start")


def _as_scalar(v):
    """Reduce a parse_qs-style value to a single scalar.

    urllib.parse.parse_qs yields {key: [v1, v2, ...]}; a hand-built dict may pass
    a bare scalar. Take the FIRST element of a list/tuple (last-wins would let a
    later blank override a good value), pass scalars through, map empty -> None.
    """
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _coerce_int(v, default):
    """Best-effort int from a scalar/parse_qs value; `default` on anything bad.

    Tolerates surrounding whitespace and a clean integer string. Floats like
    "10.0" or junk like "abc" fall back to `default` rather than raising — field
    input is never trusted to be well-formed.
    """
    s = _as_scalar(v)
    if s is None:
        return default
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def clamp_limit(n):
    """Clamp an arbitrary value to a valid page size in [MIN_LIMIT, MAX_LIMIT].

    None/garbage -> DEFAULT_LIMIT; too-small -> MIN_LIMIT; too-large -> MAX_LIMIT.
    Pure and total: always returns a usable int.
    """
    n = _coerce_int(n, DEFAULT_LIMIT)
    if n < MIN_LIMIT:
        return MIN_LIMIT
    if n > MAX_LIMIT:
        return MAX_LIMIT
    return n


def clamp_offset(n):
    """Clamp an arbitrary value to a valid offset (>= 0).

    None/garbage/negative -> 0. Pure and total: always returns a usable int.
    """
    n = _coerce_int(n, 0)
    return n if n > 0 else 0


def _qs_to_dict(qs):
    """Normalize parse()'s `qs` argument into a flat {key: scalar} dict.

    Accepts:
      - None / ""              -> {}
      - a mapping              -> used as-is (values may be scalars or lists)
      - a raw query string     -> parsed via urllib.parse.parse_qs (leading "?"
                                  and "#fragment" tolerated)
    Never raises; an unparpseable type degrades to {} so parse() returns defaults.
    """
    if qs is None:
        return {}
    if isinstance(qs, dict):
        return qs
    # A urllib SplitResult / ParseResult carries a .query attribute.
    q = getattr(qs, "query", None)
    if q is not None and not isinstance(qs, (str, bytes)):
        qs = q
    if isinstance(qs, bytes):
        try:
            qs = qs.decode("utf-8", "replace")
        except Exception:
            return {}
    if isinstance(qs, str):
        s = qs.strip()
        if s.startswith("?"):
            s = s[1:]
        # Drop a fragment if a full path/URL tail slipped in.
        s = s.split("#", 1)[0]
        if not s:
            return {}
        try:
            from urllib.parse import parse_qs
            return parse_qs(s, keep_blank_values=True)
        except Exception:
            return {}
    # Unknown type -> no params -> defaults.
    return {}


def _first_present(d, keys):
    """Return d[k] for the first k in `keys` actually present in `d`, else None."""
    for k in keys:
        if k in d:
            return d[k]
    return None


def parse(qs):
    """Parse a query string (or dict) into a clamped {"limit", "offset"} window.

    See module docstring for the accepted `qs` forms and the clamping rules.
    Pure, total, never raises: any malformed input yields the defaults. The
    returned dict is exactly the kwargs page() expects, so callers can splat it:
        page(rows, **parse(qs)).
    """
    d = _qs_to_dict(qs)
    limit = clamp_limit(_first_present(d, _LIMIT_KEYS))
    offset = clamp_offset(_first_present(d, _OFFSET_KEYS))
    return {"limit": limit, "offset": offset}


def page(items, limit=DEFAULT_LIMIT, offset=0):
    """Slice `items` into a page envelope (see module docstring for the shape).

    `limit`/`offset` are re-clamped here, so page() is safe to call with raw ints
    or with parse()'s output. `items` may be any sequence (list/tuple); the
    returned "items" is always a NEW list (never an alias of or view into the
    input), so a caller mutating the page can't corrupt the source list. A
    non-sequence (e.g. None) is treated as empty rather than raising.
    """
    limit = clamp_limit(limit)
    offset = clamp_offset(offset)
    try:
        total = len(items)
    except TypeError:
        items, total = [], 0
    # list() copies the slice -> the returned page never aliases the source.
    window = list(items[offset:offset + limit])
    end = offset + limit
    next_offset = end if end < total else None
    return {
        "items": window,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }


def paginate(items, qs):
    """Convenience: parse(qs) then page(items, **window) in one call.

    api.py can use either the two-step form (parse() once, reuse the window) or
    this single call when it just needs the envelope for one list.
    """
    return page(items, **parse(qs))


# ===========================================================================
# SELF-TEST  (python engine/pagination.py)
# ===========================================================================
if __name__ == "__main__":
    # --- parse(): raw query strings ----------------------------------------
    assert parse("limit=20&offset=40") == {"limit": 20, "offset": 40}
    assert parse("?limit=20&offset=40") == {"limit": 20, "offset": 40}  # leading ?
    assert parse("limit=20&offset=40#frag") == {"limit": 20, "offset": 40}  # fragment

    # defaults when absent / empty / None
    assert parse(None) == {"limit": DEFAULT_LIMIT, "offset": 0}
    assert parse("") == {"limit": DEFAULT_LIMIT, "offset": 0}
    assert parse("?") == {"limit": DEFAULT_LIMIT, "offset": 0}
    assert parse("foo=bar") == {"limit": DEFAULT_LIMIT, "offset": 0}

    # --- parse(): clamping & coercion (never raises on junk) ---------------
    assert parse("limit=99999")["limit"] == MAX_LIMIT          # over cap -> MAX
    assert parse("limit=0")["limit"] == MIN_LIMIT              # under floor -> MIN
    assert parse("limit=-5")["limit"] == MIN_LIMIT             # negative -> MIN
    assert parse("limit=abc")["limit"] == DEFAULT_LIMIT        # junk -> default
    assert parse("limit=10.5")["limit"] == DEFAULT_LIMIT       # float str -> default
    assert parse("offset=-9")["offset"] == 0                   # negative -> 0
    assert parse("offset=xyz")["offset"] == 0                  # junk -> 0
    assert parse("limit=50&offset=200") == {"limit": 50, "offset": 200}

    # --- parse(): dict input (incl. parse_qs's list-valued form) -----------
    assert parse({"limit": "25", "offset": "5"}) == {"limit": 25, "offset": 5}
    assert parse({"limit": ["30"], "offset": ["10"]}) == {"limit": 30, "offset": 10}
    assert parse({"limit": 7}) == {"limit": 7, "offset": 0}      # bare int value
    assert parse({"limit": []}) == {"limit": DEFAULT_LIMIT, "offset": 0}  # empty list
    assert parse({}) == {"limit": DEFAULT_LIMIT, "offset": 0}

    # --- parse(): cursor aliases offset; explicit offset wins --------------
    assert parse("cursor=80")["offset"] == 80
    assert parse("limit=20&cursor=60") == {"limit": 20, "offset": 60}
    assert parse("offset=10&cursor=99")["offset"] == 10         # offset preferred
    assert parse("start=15")["offset"] == 15                    # start alias
    assert parse("per_page=40")["limit"] == 40                  # per_page alias

    # --- parse(): tolerate a SplitResult-like object -----------------------
    from urllib.parse import urlsplit
    assert parse(urlsplit("http://x/api/incidents?limit=12&offset=3")) == {
        "limit": 12, "offset": 3}
    # bytes query string
    assert parse(b"limit=8&offset=2") == {"limit": 8, "offset": 2}
    # wholly unexpected type -> defaults, no raise
    assert parse(12345) == {"limit": DEFAULT_LIMIT, "offset": 0}

    # --- page(): basic slicing + envelope shape ----------------------------
    data = list(range(250))  # 0..249

    p0 = page(data, limit=100, offset=0)
    assert p0["items"] == list(range(0, 100))
    assert p0["total"] == 250
    assert p0["limit"] == 100 and p0["offset"] == 0
    assert p0["next_offset"] == 100        # more remain
    assert set(p0) == {"items", "total", "limit", "offset", "next_offset"}

    p1 = page(data, limit=100, offset=100)
    assert p1["items"] == list(range(100, 200))
    assert p1["next_offset"] == 200

    p2 = page(data, limit=100, offset=200)
    assert p2["items"] == list(range(200, 250))   # short last page (50 rows)
    assert p2["total"] == 250
    assert p2["next_offset"] is None              # last page -> None

    # walking the cursor visits every row exactly once and terminates
    seen, win = [], parse("limit=100")
    off = win["offset"]
    while True:
        r = page(data, limit=win["limit"], offset=off)
        seen.extend(r["items"])
        if r["next_offset"] is None:
            break
        off = r["next_offset"]
    assert seen == data, "cursor walk must cover the whole list once"

    # --- page(): edge cases ------------------------------------------------
    assert page([], limit=10, offset=0) == {
        "items": [], "total": 0, "limit": 10, "offset": 0, "next_offset": None}
    # offset past the end -> empty page, no next, total still reported
    beyond = page(data, limit=10, offset=9999)
    assert beyond["items"] == [] and beyond["total"] == 250
    assert beyond["next_offset"] is None
    # exact fit: offset+limit == total -> no next page
    exact = page(list(range(10)), limit=10, offset=0)
    assert exact["items"] == list(range(10)) and exact["next_offset"] is None

    # page() re-clamps raw/garbage limit & offset (safe with un-parsed ints)
    assert page(data, limit=99999, offset=0)["limit"] == MAX_LIMIT
    assert page(data, limit=0, offset=0)["limit"] == MIN_LIMIT
    assert page(data, limit=10, offset=-3)["offset"] == 0
    assert page(data, limit="abc", offset="xyz")["limit"] == DEFAULT_LIMIT

    # default limit applies when omitted (matches the gate-safety contract)
    assert page(list(range(5)))["limit"] == DEFAULT_LIMIT

    # returned items is a COPY: mutating the page must not touch the source
    src = [{"id": 1}, {"id": 2}]
    pg = page(src, limit=10, offset=0)
    pg["items"].append({"id": 3})
    assert len(src) == 2, "page() must not alias the source list"

    # non-sequence input degrades to an empty page rather than raising
    assert page(None, limit=10, offset=0)["total"] == 0

    # --- GATE-SAFETY INVARIANT: a small full-list read survives untouched --
    # Any gate fixture with <= DEFAULT_LIMIT rows comes back complete on page 1
    # with no truncation and no next page (so validate.py / validate_security.py,
    # which read full lists, cannot regress).
    for n in (0, 1, 17, 56, DEFAULT_LIMIT):
        full = list(range(n))
        pg = page(full, **parse(None))     # parse(None) -> default window
        assert pg["items"] == full, ("default page dropped rows at n=%d" % n)
        assert pg["next_offset"] is None, ("unexpected 2nd page at n=%d" % n)
        assert pg["total"] == n

    # --- paginate(): one-shot convenience equals the two-step form ---------
    assert paginate(data, "limit=20&offset=20") == page(data, limit=20, offset=20)
    assert paginate(data, None)["items"] == page(data, **parse(None))["items"]

    # --- clamp helpers are documented & total -----------------------------
    assert clamp_limit(None) == DEFAULT_LIMIT and clamp_limit(10**9) == MAX_LIMIT
    assert clamp_offset(None) == 0 and clamp_offset(-1) == 0 and clamp_offset(7) == 7
    assert parse.__doc__ and page.__doc__ and paginate.__doc__

    print("pagination.py self-test OK")
