"""Corridor-scan helpers for WakaSafe (WAKA-01) — pure, stdlib-only.

WHAT THIS IS (and is NOT)
  WakaSafe answers "is the road between A and B dangerous right now?". The honest
  version of that question needs a real road graph (OSRM/GraphHopper) so we can
  follow the actual route and catch danger *between* the endpoints. We do not ship
  one here: "no new pip deps" (and no guaranteed network) rules out an embedded
  router, and the existing frontend only samples the two endpoints, missing
  on-path danger in the middle.

  This module is the stdlib stand-in the audit asked for: it densifies the
  great-circle line from A to B into N ordered waypoints and scores the risk along
  that line, segment by segment, against the live incident set. It is a CORRIDOR
  APPROXIMATION, not road routing — a straight-line tube between the endpoints,
  not the road. Every label and the public copy must keep saying "corridor scan
  (not road routing)" (see app/index.html and FEEDBACK WAKA-01). When a real
  routing engine is wired, only corridor() changes (swap great-circle waypoints
  for road-snapped ones); segment_risk() keeps working unchanged.

DESIGN RULES (mirror response.py / security.py)
  - STDLIB ONLY. No DB handle, no env reads, no network, no I/O. Pure functions,
    deterministic given inputs. Safe to import from api.py with zero side effects
    and to call from any request thread.
  - The risk model is kept BYTE-FOR-BYTE consistent with engine/api.py so the
    backend corridor scan and the client agree:
        status score  -> _RISK  (verified=4 … dismissed=0)  == api.RISK
        score -> level -> _public_level()                    == api.public_level
        distance       -> great-circle haversine, km          == api._hav
    These three are duplicated here (not imported) precisely so routing.py has no
    intra-package dependency and stays independently testable — but the numbers
    must match api.py. If api.RISK / api.public_level change, change them here too.

PUBLIC API
  corridor(a, b, n)                         -> [ (lat, lng), ... ]  (n>=2 waypoints)
  segment_risk(waypoints, incidents, r_km)  -> {segments[], worst_level,
                                                incidents (deduped union),
                                                radius_km, segment_count}
  scan(a, b, incidents, n, radius_km)       -> convenience: corridor + segment_risk
                                               merged into one route-scan result.

BRIGHT LINES
  Read-only analytics. Nothing here dispatches, escalates, verifies, or moves any
  state machine; it only *reads* incidents and *describes* corridor risk. RED here
  is a public severity label, identical to the rest of the app — it never asserts a
  human-verified emergency on its own (that still comes from incident `status`).
"""

# ---------------------------------------------------------------------------
# Risk model — kept identical to engine/api.py (see module docstring).
# ---------------------------------------------------------------------------
# status -> severity score. MUST match api.RISK.
_RISK = {
    "verified": 4,
    "needs_human_review": 3,
    "corroborated": 2,
    "candidate_unverified": 1,
    "dismissed": 0,
}

# Public severity ladder. Highest first so worst_of() can short-circuit and so a
# missing/unknown level sorts below GREEN.
LEVELS = ("RED", "ORANGE", "YELLOW", "GREEN")
_LEVEL_ORDER = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}

# Default corridor half-width (km). 55 km matches the frontend's `distToSeg(...) <
# 55` corridor membership in app/index.html so backend and client agree on which
# incidents count as "on the corridor".
DEFAULT_RADIUS_KM = 55

# Default number of waypoints to densify a corridor into. Enough to catch a
# mid-route hotspot a two-endpoint scan would miss, cheap enough to run per
# request. Callers may override.
DEFAULT_WAYPOINTS = 24


def _risk_score(status):
    """Severity score (0..4) for an incident `status`. Unknown -> 1 (treated as a
    low/unconfirmed signal, exactly like api.risk_at's `RISK.get(status, 1)`)."""
    return _RISK.get(status, 1)


def _public_level(top):
    """Score -> public level label. IDENTICAL thresholds to api.public_level:
    >=4 RED, >=2 ORANGE, >=1 YELLOW, else GREEN."""
    return "RED" if top >= 4 else (
        "ORANGE" if top >= 2 else ("YELLOW" if top >= 1 else "GREEN"))


def worst_of(*levels):
    """Return the most severe of the given level labels (GREEN if none/empty).

    Unknown labels are treated as GREEN. Lets callers fold the two endpoints'
    /api/risk levels into the corridor's per-segment levels with one helper, the
    same way the frontend does `worst = max(endpointA, endpointB, …incidents)`.
    """
    best = "GREEN"
    for lv in levels:
        if _LEVEL_ORDER.get(lv, 0) > _LEVEL_ORDER.get(best, 0):
            best = lv
    return best


# ---------------------------------------------------------------------------
# Geometry — great-circle, stdlib math only (mirrors api._hav).
# ---------------------------------------------------------------------------
def _as_latlng(p):
    """Coerce a point to a (lat, lng) float tuple.

    Accepts a (lat, lng) sequence or a dict with lat/lng (or lon/long) keys —
    so callers can pass raw geocoder/api shapes. Raises ValueError on anything
    unusable so a bad route fails loudly rather than silently scanning (0,0)."""
    if isinstance(p, dict):
        lat = p.get("lat")
        lng = p.get("lng", p.get("lon", p.get("long")))
    else:
        try:
            lat, lng = p[0], p[1]
        except (TypeError, IndexError, KeyError):
            raise ValueError("point must be (lat,lng) or {lat,lng}: %r" % (p,))
    if lat is None or lng is None:
        raise ValueError("point missing lat/lng: %r" % (p,))
    return (float(lat), float(lng))


def haversine_km(a, b):
    """Great-circle distance in km between two points (each (lat,lng) or dict).

    Same formula/earth radius (6371 km) as engine/api.py `_hav`, so distances are
    consistent across the codebase.
    """
    import math
    la1, lo1 = _as_latlng(a)
    la2, lo2 = _as_latlng(b)
    R = 6371.0
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = math.radians(la2 - la1), math.radians(lo2 - lo1)
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(x))


def _point_to_segment_km(p, a, b):
    """Shortest distance (km) from point `p` to the great-circle segment a->b.

    Backend equivalent of the frontend's `distToSeg`: project `p` onto the A->B
    line in a small local planar approximation (good enough at country scale for a
    tens-of-km corridor), clamp the projection to the segment, then measure the
    real haversine distance to that nearest on-segment point. Used so an incident
    sitting *beside the line between two waypoints* is still counted as on-segment,
    not just incidents near a waypoint.
    """
    import math
    pla, plo = _as_latlng(p)
    ala, alo = _as_latlng(a)
    bla, blo = _as_latlng(b)
    # Local equirectangular projection (km) about segment start. cos(lat) corrects
    # longitude convergence; fine for the short corridors WakaSafe scans.
    kx = 111.320 * math.cos(math.radians(ala))
    ky = 110.574
    ax, ay = 0.0, 0.0
    bx, by = (blo - alo) * kx, (bla - ala) * ky
    px, py = (plo - alo) * kx, (pla - ala) * ky
    dx, dy = bx - ax, by - ay
    seg2 = dx * dx + dy * dy
    if seg2 <= 1e-12:
        # Degenerate segment (a == b): fall back to point distance.
        return haversine_km(p, a)
    t = ((px - ax) * dx + (py - ay) * dy) / seg2
    t = 0.0 if t < 0.0 else (1.0 if t > 1.0 else t)   # clamp to the segment
    # Nearest on-segment point, back in lat/lng, measured with the real haversine.
    nx, ny = ax + t * dx, ay + t * dy
    nlat = ala + ny / ky
    nlng = alo + (nx / kx if kx else 0.0)
    return haversine_km(p, (nlat, nlng))


# ---------------------------------------------------------------------------
# 1. corridor(a, b, n) — densify the great-circle A->B into n waypoints
# ---------------------------------------------------------------------------
def corridor(a, b, n=DEFAULT_WAYPOINTS):
    """Return `n` ordered waypoints along the great-circle path from A to B.

    `a`, `b` are the route endpoints (each (lat,lng) or {lat,lng}). The first
    waypoint is exactly A, the last exactly B; the rest are spaced evenly along the
    great circle by spherical (slerp) interpolation, so the corridor follows the
    true shortest path on the globe rather than a naive lat/lng lerp. `n` is
    clamped to >= 2 (you always get at least the two endpoints).

    NOT road routing — this is a straight (great-circle) tube between the
    endpoints; see the module docstring. Returns a list of (lat, lng) float tuples.
    """
    import math
    pa = _as_latlng(a)
    pb = _as_latlng(b)
    n = max(2, int(n))

    # Convert endpoints to unit vectors on the sphere for slerp.
    def _vec(lat, lng):
        rla, rlo = math.radians(lat), math.radians(lng)
        cl = math.cos(rla)
        return (cl * math.cos(rlo), cl * math.sin(rlo), math.sin(rla))

    def _latlng(v):
        x, y, z = v
        hyp = math.sqrt(x * x + y * y)
        return (math.degrees(math.atan2(z, hyp)), math.degrees(math.atan2(y, x)))

    v0 = _vec(*pa)
    v1 = _vec(*pb)
    dot = max(-1.0, min(1.0, sum(c0 * c1 for c0, c1 in zip(v0, v1))))
    omega = math.acos(dot)   # angular distance between endpoints

    pts = []
    for i in range(n):
        f = i / (n - 1)        # 0 .. 1 inclusive
        if i == 0:
            pts.append(pa)         # exact endpoint A (no float drift)
            continue
        if i == n - 1:
            pts.append(pb)         # exact endpoint B
            continue
        if omega < 1e-9:
            # Coincident/near-coincident endpoints: every waypoint is A.
            pts.append(pa)
            continue
        s0 = math.sin((1.0 - f) * omega) / math.sin(omega)
        s1 = math.sin(f * omega) / math.sin(omega)
        v = (s0 * v0[0] + s1 * v1[0],
             s0 * v0[1] + s1 * v1[1],
             s0 * v0[2] + s1 * v1[2])
        pts.append(_latlng(v))
    return pts


# ---------------------------------------------------------------------------
# 2. segment_risk(waypoints, incidents, radius_km)
# ---------------------------------------------------------------------------
def _incident_ll(inc):
    """(lat, lng) for an incident dict, or None if it has no usable coordinates.

    GEO-01 friendliness: an incident with null/missing coords is skipped, never
    silently pinned to (0,0)/centroid."""
    lat = inc.get("lat")
    lng = inc.get("lng", inc.get("lon"))
    if lat is None or lng is None:
        return None
    try:
        return (float(lat), float(lng))
    except (TypeError, ValueError):
        return None


def _incident_id(inc, fallback):
    """Stable-ish identity for dedup across segments. Prefer the immutable
    incident_uuid (INT-01), then common id keys, else a positional fallback."""
    for k in ("incident_uuid", "id", "uuid", "incident_key", "key"):
        v = inc.get(k)
        if v not in (None, ""):
            return ("k", v)
    return ("idx", fallback)


def segment_risk(waypoints, incidents, radius_km=DEFAULT_RADIUS_KM):
    """Score corridor risk segment-by-segment.

    A *segment* is the great-circle leg between consecutive `waypoints`
    (n waypoints -> n-1 segments). For each segment we find every incident whose
    point-to-segment distance is within `radius_km` (the corridor half-width),
    take the worst severity among them as that segment's level (api.public_level
    semantics), and list those incidents nearest-first.

    Args:
      waypoints: ordered list of (lat,lng)/dicts from corridor() (>= 2 points).
      incidents: iterable of incident dicts, each with lat/lng + a `status`
                 (and ideally an id/incident_uuid). Coord-less incidents are
                 skipped, not centroid-guessed.
      radius_km: corridor half-width. Defaults to 55 km to match the frontend.

    Returns a dict:
      {
        "radius_km": float,
        "segment_count": int,
        "worst_level": "GREEN|YELLOW|ORANGE|RED",   # worst across all segments
        "worst_score": int,                          # 0..4 raw score
        "segments": [
           {"index", "from":(lat,lng), "to":(lat,lng), "length_km",
            "level", "score", "count",
            "incidents":[ {<incident fields>, "distance_km":..}, ... ]}, ...
        ],
        "incidents": [ ...deduped union of on-corridor incidents, worst-first... ],
      }

    Pure/read-only: incident dicts are shallow-copied before a per-segment
    `distance_km` is stamped on, so callers' originals are never mutated.
    """
    wps = [_as_latlng(w) for w in (waypoints or [])]
    try:
        r = float(radius_km)
    except (TypeError, ValueError):
        r = DEFAULT_RADIUS_KM
    if r <= 0:
        r = DEFAULT_RADIUS_KM

    # Pre-extract usable incidents once (skip coord-less rows).
    pool = []
    for idx, inc in enumerate(incidents or []):
        ll = _incident_ll(inc)
        if ll is None:
            continue
        pool.append((idx, inc, ll))

    segments = []
    union = {}            # incident-id -> (best/nearest record) for the union list
    worst_score = 0

    # n waypoints => n-1 segments. With a single waypoint there are no segments
    # (degenerate route); we still return a well-formed empty-corridor result.
    for si in range(len(wps) - 1):
        a, b = wps[si], wps[si + 1]
        seg_inc = []
        seg_score = 0
        for idx, inc, ll in pool:
            d = _point_to_segment_km(ll, a, b)
            if d <= r:
                rec = dict(inc)                      # shallow copy — never mutate caller's
                rec["distance_km"] = round(d, 1)
                seg_inc.append(rec)
                sc = _risk_score(inc.get("status"))
                if sc > seg_score:
                    seg_score = sc
                # Maintain the corridor-wide union, keeping the nearest sighting of
                # each distinct incident.
                key = _incident_id(inc, idx)
                prev = union.get(key)
                if prev is None or rec["distance_km"] < prev["distance_km"]:
                    union[key] = rec
        # worst severity first, then nearest — same ordering as api.risk_at.
        seg_inc.sort(key=lambda i: (-_risk_score(i.get("status")), i["distance_km"]))
        if seg_score > worst_score:
            worst_score = seg_score
        segments.append({
            "index": si,
            "from": a,
            "to": b,
            "length_km": round(haversine_km(a, b), 1),
            "level": _public_level(seg_score),
            "score": seg_score,
            "count": len(seg_inc),
            "incidents": seg_inc,
        })

    union_list = sorted(
        union.values(),
        key=lambda i: (-_risk_score(i.get("status")), i["distance_km"]))

    return {
        "radius_km": r,
        "segment_count": len(segments),
        "worst_level": _public_level(worst_score),
        "worst_score": worst_score,
        "segments": segments,
        "incidents": union_list,
    }


# ---------------------------------------------------------------------------
# 3. scan(a, b, incidents, ...) — convenience one-shot for POST /api/route-scan
# ---------------------------------------------------------------------------
def scan(a, b, incidents, n=DEFAULT_WAYPOINTS, radius_km=DEFAULT_RADIUS_KM):
    """Build the corridor and score it in one call (the shape /api/route-scan wants).

    Returns segment_risk()'s dict plus the route framing:
      {"from", "to", "waypoints", "approximation":"great-circle corridor (not road
       routing)", ...segment_risk fields...}

    `from`/`to` echo the resolved endpoints so the caller can render the corridor
    and label it honestly. The `approximation` string is deliberately present in
    the payload so any UI consuming this can't quietly imply true road routing.
    """
    pa = _as_latlng(a)
    pb = _as_latlng(b)
    wps = corridor(pa, pb, n)
    out = segment_risk(wps, incidents, radius_km=radius_km)
    out["from"] = pa
    out["to"] = pb
    out["waypoints"] = wps
    out["total_km"] = round(haversine_km(pa, pb), 1)
    out["approximation"] = "great-circle corridor (not road routing)"
    return out


# ===========================================================================
# SELF-TEST  (python engine/routing.py)
# ===========================================================================
if __name__ == "__main__":
    import math

    # --- risk model parity with api.py (guard against drift) ---------------
    # These literals MUST equal api.RISK / api.public_level. If api.py changes,
    # this self-test is where the mismatch should surface first.
    assert _RISK == {"verified": 4, "needs_human_review": 3, "corroborated": 2,
                     "candidate_unverified": 1, "dismissed": 0}
    assert _public_level(4) == "RED" and _public_level(3) == "ORANGE"
    assert _public_level(2) == "ORANGE" and _public_level(1) == "YELLOW"
    assert _public_level(0) == "GREEN"
    assert _risk_score("verified") == 4 and _risk_score("totally_unknown") == 1
    assert worst_of("GREEN", "RED", "YELLOW") == "RED"
    assert worst_of("GREEN", "YELLOW") == "YELLOW"
    assert worst_of() == "GREEN" and worst_of("bogus") == "GREEN"

    # --- point coercion ----------------------------------------------------
    assert _as_latlng((9.0, 7.0)) == (9.0, 7.0)
    assert _as_latlng({"lat": 9.0, "lng": 7.0}) == (9.0, 7.0)
    assert _as_latlng({"lat": 9.0, "lon": 7.0}) == (9.0, 7.0)   # lon alias
    for bad in (None, (1,), {"lat": 1}, "x"):
        try:
            _as_latlng(bad)
            assert False, "expected ValueError for %r" % (bad,)
        except ValueError:
            pass

    # --- haversine sanity (Abuja ~ Kaduna ~ 160-200 km) --------------------
    abuja = (9.0765, 7.3986)
    kaduna = (10.5105, 7.4165)
    d = haversine_km(abuja, kaduna)
    assert 150 < d < 210, d
    assert haversine_km(abuja, abuja) == 0.0
    # dict + lon-alias path gives the same distance as the tuple path
    assert abs(haversine_km({"lat": 9.0765, "lon": 7.3986}, kaduna) - d) < 1e-9

    # --- corridor(): endpoints exact, count honored, monotone along path ---
    wps = corridor(abuja, kaduna, 24)
    assert len(wps) == 24
    assert wps[0] == abuja and wps[-1] == kaduna     # endpoints are exact
    assert all(isinstance(p, tuple) and len(p) == 2 for p in wps)
    # cumulative distance from A increases monotonically toward B
    dprev = -1.0
    for p in wps:
        dd = haversine_km(abuja, p)
        assert dd >= dprev - 1e-6, (dprev, dd)
        dprev = dd
    # sum of segment legs ~= straight A->B distance (great circle, no detour)
    legs = sum(haversine_km(wps[i], wps[i + 1]) for i in range(len(wps) - 1))
    assert abs(legs - d) < 1.0, (legs, d)
    # a midpoint waypoint really is ~halfway (slerp, not endpoint-biased)
    mid = corridor(abuja, kaduna, 3)[1]
    assert abs(haversine_km(abuja, mid) - haversine_km(mid, kaduna)) < 1.0
    # n clamps to >= 2
    assert corridor(abuja, kaduna, 1) == [abuja, kaduna]
    assert corridor(abuja, kaduna, 0) == [abuja, kaduna]
    # coincident endpoints: every waypoint is that point (no NaN from slerp)
    same = corridor(abuja, abuja, 5)
    assert len(same) == 5 and all(p == abuja for p in same)

    # --- segment_risk(): a MID-CORRIDOR hotspot the 2-endpoint scan misses --
    # Place a verified incident near the geometric middle, far (>55km) from both
    # endpoints, so only a densified corridor scan can catch it.
    midpoint = corridor(abuja, kaduna, 3)[1]
    assert haversine_km(abuja, midpoint) > 55 and haversine_km(kaduna, midpoint) > 55
    incidents = [
        {"incident_uuid": "u-mid", "lat": midpoint[0], "lng": midpoint[1],
         "status": "verified", "type": "kidnapping"},
        # an off-corridor incident ~2 degrees east (~220 km away) -> excluded
        {"incident_uuid": "u-far", "lat": 9.5, "lng": 9.6,
         "status": "verified", "type": "banditry_attack"},
        # a low-severity one right on the A end
        {"incident_uuid": "u-near-a", "lat": abuja[0], "lng": abuja[1],
         "status": "candidate_unverified", "type": "armed_robbery"},
    ]
    res = segment_risk(wps, incidents, radius_km=55)
    assert res["segment_count"] == 23                 # 24 waypoints -> 23 segments
    assert res["worst_level"] == "RED"                # the mid verified incident
    # union contains the mid + the near-A one, but NOT the far-off one
    ids = {i["incident_uuid"] for i in res["incidents"]}
    assert ids == {"u-mid", "u-near-a"}, ids
    # union is worst-first, and each carries a distance_km
    assert res["incidents"][0]["incident_uuid"] == "u-mid"
    assert all("distance_km" in i for i in res["incidents"])
    # at least one segment actually flags RED, and segment levels never exceed worst
    assert any(s["level"] == "RED" for s in res["segments"])
    assert all(_LEVEL_ORDER[s["level"]] <= _LEVEL_ORDER[res["worst_level"]]
               for s in res["segments"])
    # the mid incident sits in a roughly-central segment, not the first/last
    red_idxs = [s["index"] for s in res["segments"] if s["level"] == "RED"]
    assert red_idxs and min(red_idxs) > 0 and max(red_idxs) < 22, red_idxs

    # purity: caller's incident dicts were not mutated (no distance_km leaked in)
    assert all("distance_km" not in inc for inc in incidents)

    # coord-less incidents are skipped, not centroid-pinned
    res2 = segment_risk(wps, [{"status": "verified", "type": "x"},
                              {"lat": None, "lng": None, "status": "verified"}],
                        radius_km=55)
    assert res2["worst_level"] == "GREEN" and res2["incidents"] == []

    # empty / degenerate inputs return well-formed results (no crash)
    assert segment_risk([], incidents)["segments"] == []
    assert segment_risk([abuja], incidents)["segment_count"] == 0   # 1 wp -> 0 segs
    assert segment_risk(wps, [])["worst_level"] == "GREEN"
    # radius<=0 / bad radius falls back to the default, doesn't divide-by-zero
    assert segment_risk(wps, incidents, radius_km=0)["radius_km"] == DEFAULT_RADIUS_KM
    assert segment_risk(wps, incidents, radius_km="oops")["radius_km"] == DEFAULT_RADIUS_KM

    # --- scan() one-shot: shape + honest approximation label ---------------
    s = scan(abuja, kaduna, incidents, n=24, radius_km=55)
    assert s["from"] == abuja and s["to"] == kaduna
    assert len(s["waypoints"]) == 24 and s["segment_count"] == 23
    assert s["worst_level"] == "RED"
    assert s["approximation"] == "great-circle corridor (not road routing)"
    assert abs(s["total_km"] - d) < 1.0
    # accepts dict endpoints (raw geocoder shapes) too
    s2 = scan({"lat": abuja[0], "lng": abuja[1]},
              {"lat": kaduna[0], "lon": kaduna[1]}, incidents)
    assert s2["worst_level"] == "RED"

    # dedup: the SAME incident hit by several adjacent segments appears once in
    # the union (keyed on incident_uuid), at its nearest distance.
    dup = [{"incident_uuid": "dup", "lat": midpoint[0], "lng": midpoint[1],
            "status": "corroborated", "type": "kidnapping"}]
    rd = segment_risk(wps, dup, radius_km=200)   # huge radius => many segments hit
    assert sum(s["count"] for s in rd["segments"]) > 1   # counted in many segments
    assert len(rd["incidents"]) == 1                      # but deduped to one in union

    print("routing.py self-test OK")
