"""Reachability-ring / Venn triangulation engine for DeySafe FindMe (FIND-03).

WHAT THIS IS (and is NOT)
  When a person goes missing we have a set of credible POINTS in space-time: the
  last-seen location and any subsequent sightings, each stamped with WHEN it was
  observed. From each point the subject can only have travelled so far by now:
  draw a circle (a REACHABILITY RING) whose radius is elapsed-time x plausible
  ground speed. The subject must lie inside EVERY ring at once, so the densest
  OVERLAP of the rings — where the most independent observations agree — is the
  most-likely PRIORITY SEARCH ZONE. A fresher sighting means a smaller, tighter
  ring, which pulls the priority zone in and sharpens it.

  This is the server-side, testable version of the client-only Venn math in
  app/index.html (the `triangulate(cid)` map overlay). It produces a richer,
  JSON-serializable result (ranked candidate zones + a forward movement cone +
  confidence + plain-words explanation) that /api/triangulate can return and the
  frontend can render, instead of every client recomputing it inconsistently.

  BRIGHT LINE (non-negotiable for this product): the output is a PROBABILITY — a
  "likely search zone", NEVER a pinpoint or confirmed location. `confidence` is a
  probability in [0,1] and is never presented as certainty; every result carries a
  `disclaimer` saying so. Nothing here claims to pinpoint a person. More agreeing
  rings raises confidence; it never reaches "found".

DESIGN RULES (mirror routing.py / terrain.py)
  - STDLIB ONLY. No DB handle, no env reads, no NETWORK, no FILE I/O. Pure /
    deterministic given its inputs — safe to import from api.py with zero side
    effects and to call from any request thread. In particular it does NOT read the
    clock: `now_iso` is passed IN as an ISO string (the caller stamps it), so the
    engine is reproducible and unit-testable. (Client `Date.now()` is the thing we
    are deliberately replacing.)
  - The terrain -> speed -> reach RADIUS model is kept consistent with
    engine/terrain.py (the single home of that policy): forest/mountain on foot are
    far slower than a highway, so an off-road ring is correctly tighter. If
    `terrain` (the engine.terrain TERRAINS module) is passed in we reuse its
    reach_radius(); otherwise we fall back to an explicit `speed_kmh` (or the same
    coarse defaults terrain.py uses) so this module also stands alone in a test.
  - Read-only analytics. Nothing here dispatches, escalates, verifies, fuzzes, or
    moves any state machine; it only DESCRIBES a probable area from points given.

PUBLIC API
  haversine_km(a, b)                                   -> great-circle km
  reach_radius_km(hours, speed_kmh=None, terrain=None) -> ring radius km (capped)
  search_zones(last_seen, sightings, now_iso,
               speed_kmh=None, terrain=None)           -> the full result dict
"""

import math
import datetime

# ---------------------------------------------------------------------------
# Movement / reach model — kept consistent with engine/terrain.py.
# ---------------------------------------------------------------------------
# Fallback ground speed (km/h) used ONLY when neither an engine.terrain module
# nor an explicit speed_kmh is supplied. Equal to terrain.TERRAIN_SPEED_KMH[MIXED]
# (the conservative DEFAULT_TERRAIN), so a no-terrain call behaves like terrain.py's
# default rather than the old dangerously-large flat 50 km/h highway assumption.
DEFAULT_SPEED_KMH = 25.0

# Hard cap on any ring radius (km). Matches terrain.MAX_RADIUS_KM / the client's
# reach() clamp: even a long-elapsed highway ring stops being a useful "likely
# zone" past this, and an uncapped ring would swamp the whole map.
MAX_RADIUS_KM = 250.0

# Floor on elapsed time (h) so a just-reported case still yields a non-zero,
# searchable ring (mirrors terrain.MIN_HOURS and the client's Math.max(0.1,...)).
MIN_HOURS = 0.25

# Grid resolution for the overlap scan. The bounding box of all rings is sampled
# on an (N+1)x(N+1) lattice; the densest cells (most rings covering them) are the
# priority zone. 48 trades a finer zone estimate for a still-cheap per-request
# scan (matches the spirit of the client's N=40 grid, a touch finer).
GRID_N = 48

# Half-angle (deg) of the forward movement cone drawn from the sighting trail, and
# the cap on how far ahead it is projected. Mirrors the client cone (half=34deg,
# reach capped ~120 km) so backend and map agree on the "likely heading" wedge.
CONE_HALF_DEG = 34.0
CONE_MAX_KM = 120.0

# The one disclaimer string every result carries. Kept here so the wording is
# auditable in one place and can never silently drift toward implying certainty.
DISCLAIMER = (
    "This is a PROBABILITY-BASED likely search zone, not a pinpoint or confirmed "
    "location. It is a planning aid only: the person may be outside it. More "
    "credible sightings tighten the estimate. Always rely on trained responders "
    "and human judgement."
)


# ---------------------------------------------------------------------------
# Geometry — great-circle, stdlib math only (mirrors routing.haversine_km).
# ---------------------------------------------------------------------------
def _as_latlng(p):
    """Coerce a point to a (lat, lng) float tuple, or return None if unusable.

    Accepts a (lat, lng) sequence or a dict with lat/lng (or lon/long) keys, so
    callers can pass raw case / sighting shapes. Unlike routing._as_latlng this is
    forgiving — a coord-less point returns None (so the caller SKIPS it) rather than
    raising, because a missing-person feed legitimately contains rows with no
    coordinates and one bad sighting must not crash the whole search."""
    if isinstance(p, dict):
        lat = p.get("lat")
        lng = p.get("lng", p.get("lon", p.get("long")))
    else:
        try:
            lat, lng = p[0], p[1]
        except (TypeError, IndexError, KeyError):
            return None
    if lat is None or lng is None:
        return None
    try:
        lat, lng = float(lat), float(lng)
    except (TypeError, ValueError):
        return None
    if lat != lat or lng != lng:          # NaN guard
        return None
    return (lat, lng)


def haversine_km(a, b):
    """Great-circle distance in km between two points (each (lat,lng) or dict).

    Same formula and earth radius (6371 km) as engine/routing.py `haversine_km` and
    engine/api.py `_hav`, so distances are consistent across the codebase. Returns
    0.0 if either point is coord-less (caller is expected to have filtered those)."""
    pa = _as_latlng(a)
    pb = _as_latlng(b)
    if pa is None or pb is None:
        return 0.0
    R = 6371.0
    p1, p2 = math.radians(pa[0]), math.radians(pb[0])
    dp, dl = math.radians(pb[0] - pa[0]), math.radians(pb[1] - pa[1])
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(x))


def _bearing_deg(a, b):
    """Initial great-circle bearing (deg, 0=N, clockwise) from point a to point b.

    Backend equivalent of the client `bearing(...)`. Used to read the subject's
    direction of travel off the sighting trail for the forward movement cone."""
    pa = _as_latlng(a)
    pb = _as_latlng(b)
    if pa is None or pb is None:
        return None
    la1, lo1 = math.radians(pa[0]), math.radians(pa[1])
    la2, lo2 = math.radians(pb[0]), math.radians(pb[1])
    dlo = lo2 - lo1
    y = math.sin(dlo) * math.cos(la2)
    x = math.cos(la1) * math.sin(la2) - math.sin(la1) * math.cos(la2) * math.cos(dlo)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def _destination(a, bearing_deg, km):
    """Point reached travelling `km` from `a` along `bearing_deg` (great circle).

    Backend equivalent of the client `dest(...)`. Used to lay out the forward cone
    polygon and the predicted-ahead marker."""
    pa = _as_latlng(a)
    if pa is None:
        return None
    R = 6371.0
    d = km / R
    b = math.radians(bearing_deg)
    la1, lo1 = math.radians(pa[0]), math.radians(pa[1])
    la2 = math.asin(math.sin(la1) * math.cos(d) + math.cos(la1) * math.sin(d) * math.cos(b))
    lo2 = lo1 + math.atan2(math.sin(b) * math.sin(d) * math.cos(la1),
                           math.cos(d) - math.sin(la1) * math.sin(la2))
    return (math.degrees(la2), math.degrees(lo2))


_COMPASS = ("north", "north-east", "east", "south-east",
            "south", "south-west", "west", "north-west")


def _compass(bearing_deg):
    """Bearing (deg) -> 8-point compass word. Mirrors the client `compass(...)`."""
    return _COMPASS[int(round((bearing_deg % 360) / 45.0)) % 8]


# ---------------------------------------------------------------------------
# Time + reach helpers
# ---------------------------------------------------------------------------
def _parse_iso(s):
    """Parse an ISO-8601 timestamp to a datetime, or None if unparseable.

    Uses datetime.fromisoformat — the same parser engine/api.py uses on
    last_seen / seen_at — so this engine accepts exactly the timestamps the rest of
    DeySafe produces (db.now_iso() / isoformat(timespec='seconds')). Never raises:
    a bad/empty timestamp returns None and the caller degrades to the MIN_HOURS
    floor rather than crashing the search."""
    if not s:
        return None
    if isinstance(s, datetime.datetime):
        return s
    try:
        return datetime.datetime.fromisoformat(str(s))
    except (TypeError, ValueError):
        return None


def _elapsed_hours(seen_at, now_iso):
    """Hours between a point's `seen_at` and `now_iso`, floored at MIN_HOURS.

    Both are ISO strings (or datetimes). A bad/missing `seen_at`, a bad `now_iso`,
    or a future `seen_at` all degrade to the MIN_HOURS floor — never negative, never
    raising — so a malformed timestamp yields the smallest sensible ring instead of
    an error or an absurd radius."""
    t_seen = _parse_iso(seen_at)
    t_now = _parse_iso(now_iso)
    if t_seen is None or t_now is None:
        return MIN_HOURS
    try:
        hrs = (t_now - t_seen).total_seconds() / 3600.0
    except (TypeError, OverflowError):
        return MIN_HOURS
    if hrs != hrs or hrs < MIN_HOURS:     # NaN or below floor (incl. future) -> floor
        return MIN_HOURS
    return hrs


def _speed_kmh(speed_kmh, terrain):
    """Resolve the ground speed (km/h) to use for a ring.

    Priority: an explicit positive `speed_kmh` wins; else, if a `terrain` value is
    given AND a terrain-policy module was injected, use that module's speed; else
    the conservative DEFAULT_SPEED_KMH. (`terrain` here may be either a terrain-class
    string with the module bound at import, or — in standalone tests — left as the
    default.) Always returns a positive float; never raises."""
    try:
        s = float(speed_kmh)
        if s > 0:
            return s
    except (TypeError, ValueError):
        pass
    # Try the sibling terrain policy module if it is importable AND a class is named.
    if terrain is not None:
        try:
            import terrain as _terrain_mod  # sibling engine module (stdlib import path)
            return float(_terrain_mod.speed_for(terrain))
        except Exception:
            pass
    return DEFAULT_SPEED_KMH


def reach_radius_km(hours, speed_kmh=None, terrain=None):
    """Reachable ring radius (km) for `hours` elapsed, capped to [0, MAX_RADIUS_KM].

    radius = speed * max(hours, MIN_HOURS). The speed comes from `speed_kmh` /
    `terrain` via _speed_kmh (see terrain.py for the policy). The result GROWS with
    elapsed time (older point -> larger, looser ring) and SHRINKS off-road, exactly
    like the FIND-02 terrain model and the client `reach()`. Returns a float km so
    the zone math keeps sub-km precision; callers may round for display. Bad `hours`
    degrades to the MIN_HOURS floor (never raises, never negative)."""
    try:
        h = float(hours)
    except (TypeError, ValueError):
        h = MIN_HOURS
    if h != h or h < MIN_HOURS:
        h = MIN_HOURS
    km = _speed_kmh(speed_kmh, terrain) * h
    if km < 0:
        km = 0.0
    return min(km, MAX_RADIUS_KM)


# ---------------------------------------------------------------------------
# Ring assembly
# ---------------------------------------------------------------------------
def _build_rings(last_seen, sightings, now_iso, speed_kmh, terrain):
    """Build the reachability ring for every usable known point.

    The last-seen point (source 'last_seen') plus each sighting (source = that
    sighting's `source`, default 'sighting'). Points with no usable coordinates are
    SKIPPED (never pinned to 0,0 / a centroid — GEO-01). Each ring is a dict:
        {center:(lat,lng), radius_km, from_source, age_hours, seen_at}
    Returns (rings_internal, skipped_count). Internal rings keep tuple centers and
    full-precision radii for the math; _ring_public() renders the API shape."""
    rings = []
    skipped = 0

    def _add(point, default_source):
        nonlocal skipped
        ll = _as_latlng(point)
        if ll is None:
            skipped += 1
            return
        seen_at = point.get("seen_at") if isinstance(point, dict) else None
        src = (point.get("source") if isinstance(point, dict) else None) or default_source
        age = _elapsed_hours(seen_at, now_iso)
        rings.append({
            "center": ll,
            "radius_km": reach_radius_km(age, speed_kmh=speed_kmh, terrain=terrain),
            "from_source": src,
            "age_hours": round(age, 2),
            "seen_at": seen_at,
        })

    if last_seen:
        _add(last_seen, "last_seen")
    for s in (sightings or []):
        _add(s, "sighting")
    return rings, skipped


def _ring_public(r):
    """API-facing shape of a ring: center as a [lat,lng] list, radii rounded."""
    return {
        "center": [round(r["center"][0], 6), round(r["center"][1], 6)],
        "radius_km": round(r["radius_km"], 2),
        "from_source": r["from_source"],
        "age_hours": r["age_hours"],
    }


# ---------------------------------------------------------------------------
# Overlap / Venn scan
# ---------------------------------------------------------------------------
def _bbox(rings):
    """Lat/lng bounding box covering every ring (center +/- its radius).

    Each ring's radius is converted to a degree pad (lat: ~111 km/deg; lng scaled
    by cos(lat) for meridian convergence) so the scan box fully contains all rings.
    Returns (min_lat, max_lat, min_lng, max_lng)."""
    min_la, max_la = 90.0, -90.0
    min_lo, max_lo = 180.0, -180.0
    for r in rings:
        la, lo = r["center"]
        d_la = r["radius_km"] / 111.0
        cos_la = math.cos(math.radians(la))
        d_lo = r["radius_km"] / (111.0 * cos_la) if abs(cos_la) > 1e-9 else 180.0
        min_la, max_la = min(min_la, la - d_la), max(max_la, la + d_la)
        min_lo, max_lo = min(min_lo, lo - d_lo), max(max_lo, lo + d_lo)
    return min_la, max_la, min_lo, max_lo


def _coverage(point, rings):
    """How many rings cover `point` (point within ring.radius of ring.center)."""
    c = 0
    for r in rings:
        if haversine_km(point, r["center"]) <= r["radius_km"]:
            c += 1
    return c


def _zone_from_cells(cells):
    """Collapse a set of (lat,lng) overlap cells to a {center, radius_km} zone.

    Center is the centroid of the cells; radius is the max distance from that
    centroid to any cell (the spread of the overlap), floored at a small value so a
    pinpoint cluster still draws a visible, honestly-fuzzy ring (we never claim a
    razor-sharp point)."""
    s_la = sum(c[0] for c in cells) / len(cells)
    s_lo = sum(c[1] for c in cells) / len(cells)
    spread = 0.0
    for c in cells:
        spread = max(spread, haversine_km((s_la, s_lo), c))
    return {"center": (s_la, s_lo), "radius_km": max(2.0, spread)}


def _scan_overlap(rings):
    """Grid-scan the rings' bounding box for the densest overlap.

    Samples a (GRID_N+1)^2 lattice over the bbox; for each cell counts how many
    rings cover it. Returns (zones_by_count, max_count) where zones_by_count maps an
    overlap count k -> a {center, radius_km} zone built from all cells with that
    exact count. The k == max_count zone is the priority zone; lower-k zones become
    ranked fall-back candidates. Returns ({}, 0) for <1 ring."""
    if not rings:
        return {}, 0
    min_la, max_la, min_lo, max_lo = _bbox(rings)
    # Degenerate (all centers coincident, zero-ish radius): box has no area. Fall
    # back to scoring the shared center alone so we still return a zone.
    if max_la - min_la < 1e-9 and max_lo - min_lo < 1e-9:
        ctr = rings[0]["center"]
        return {len(rings): {"center": ctr, "radius_km": max(2.0, rings[0]["radius_km"])}}, len(rings)

    by_count = {}        # overlap count -> list of cells
    max_count = 0
    for i in range(GRID_N + 1):
        la = min_la + (max_la - min_la) * i / GRID_N
        for j in range(GRID_N + 1):
            lo = min_lo + (max_lo - min_lo) * j / GRID_N
            c = _coverage((la, lo), rings)
            if c <= 0:
                continue
            by_count.setdefault(c, []).append((la, lo))
            if c > max_count:
                max_count = c

    zones = {k: _zone_from_cells(cells) for k, cells in by_count.items()}
    return zones, max_count


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------
def _confidence(ring_count, total_rings, zone_radius_km):
    """Probability-style confidence in [0,1] that the subject is in a zone.

    Two intuitions, deliberately conservative (this must never read as certainty):
      * AGREEMENT — the fraction of all rings that overlap this zone. One ring
        alone caps low (a single observation cannot triangulate); more agreeing
        rings raise it. Even total agreement is capped below 1.0 — we never claim
        a confirmed location.
      * TIGHTNESS — a smaller overlap is more informative than a sprawling one, so a
        large zone radius gently discounts confidence.
    Result is clamped to [0.0, 0.95]. Tunable, not a calibrated probability — the
    `disclaimer` makes that explicit to anyone consuming the number."""
    if total_rings <= 0 or ring_count <= 0:
        return 0.0
    agreement = ring_count / float(total_rings)
    # A single source can locate only a broad ring, not triangulate -> hard low cap.
    if total_rings == 1 or ring_count == 1:
        base = 0.30 * agreement
    else:
        base = agreement
    # Tightness factor: ~1.0 for a <=5 km zone, decaying toward ~0.5 for a 100 km one.
    tightness = 1.0 / (1.0 + max(0.0, zone_radius_km - 5.0) / 95.0)
    conf = base * (0.6 + 0.4 * tightness)
    return round(max(0.0, min(0.95, conf)), 3)


def _zone_public(zone, ring_count, total_rings):
    """API shape for a candidate / priority zone (center list, rounded, +confidence)."""
    return {
        "center": [round(zone["center"][0], 6), round(zone["center"][1], 6)],
        "radius_km": round(zone["radius_km"], 1),
        "confidence": _confidence(ring_count, total_rings, zone["radius_km"]),
        "ring_count": ring_count,
    }


# ---------------------------------------------------------------------------
# Movement cone (forward prediction from the sighting trail)
# ---------------------------------------------------------------------------
def _movement_cone(rings, last_seen, sightings, now_iso, speed_kmh, terrain):
    """Forward direction wedge inferred from the trail of credible points.

    Mirrors the client's heading logic: with >=2 usable sightings, the bearing is
    from the second-newest to the newest sighting; with exactly one, from last-seen
    to that sighting. (With zero sightings there is no movement evidence -> no cone;
    we deliberately do NOT invent a direction from a free-text 'direction' note
    here — that stays a client/operator hint.) The cone is anchored at the newest
    point, projected up to its reach (capped at CONE_MAX_KM). Returns None when
    there is no directional evidence. Shape:
        {anchor:[lat,lng], bearing_deg, heading, half_angle_deg, length_km,
         polygon:[[lat,lng],...], predicted_ahead:[lat,lng]}
    """
    pts = []
    if last_seen is not None and _as_latlng(last_seen) is not None:
        pts.append(last_seen)
    for s in (sightings or []):
        if _as_latlng(s) is not None:
            pts.append(s)
    # Need at least the last-seen + 1 sighting (2 points) to infer a direction.
    if len(pts) < 2:
        return None

    newest = pts[-1]
    prev = pts[-2]
    brg = _bearing_deg(prev, newest)
    if brg is None:
        return None
    anchor = _as_latlng(newest)

    # Reach of the newest point (how far ahead it could be) drives the cone length.
    age = _elapsed_hours(newest.get("seen_at") if isinstance(newest, dict) else None, now_iso)
    length = min(reach_radius_km(age, speed_kmh=speed_kmh, terrain=terrain), CONE_MAX_KM)
    if length < 1.0:
        length = 1.0

    # Build the wedge polygon: anchor -> arc of destinations across +/- half-angle.
    poly = [[round(anchor[0], 6), round(anchor[1], 6)]]
    a = -CONE_HALF_DEG
    while a <= CONE_HALF_DEG + 1e-9:
        d = _destination(anchor, brg + a, length)
        if d is not None:
            poly.append([round(d[0], 6), round(d[1], 6)])
        a += 8.0
    poly.append([round(anchor[0], 6), round(anchor[1], 6)])

    ahead = _destination(anchor, brg, length * 0.5)
    return {
        "anchor": [round(anchor[0], 6), round(anchor[1], 6)],
        "bearing_deg": round(brg, 1),
        "heading": _compass(brg),
        "half_angle_deg": CONE_HALF_DEG,
        "length_km": round(length, 1),
        "polygon": poly,
        "predicted_ahead": [round(ahead[0], 6), round(ahead[1], 6)] if ahead else None,
    }


# ---------------------------------------------------------------------------
# Empty / well-formed-fallback result
# ---------------------------------------------------------------------------
def _empty_result(reason):
    """A fully-formed, JSON-serializable empty result (no usable points).

    Every field the normal result carries is present (so callers never KeyError),
    the priority zone is None, confidence is absent because there is no zone, and
    the BRIGHT-LINE disclaimer is still attached. `explanation` says, in plain
    words, why there is nothing to show."""
    return {
        "rings": [],
        "priority_zone": None,
        "candidate_zones": [],
        "movement_cone": None,
        "ring_count": 0,
        "skipped_points": 0,
        "disclaimer": DISCLAIMER,
        "explanation": (
            "No usable location points were provided (%s), so no search zone could "
            "be estimated. Add a last-seen location or a sighting with coordinates."
            % reason
        ),
    }


# ---------------------------------------------------------------------------
# PUBLIC: search_zones(...) — the one call /api/triangulate makes
# ---------------------------------------------------------------------------
def search_zones(last_seen, sightings, now_iso, speed_kmh=None, terrain=None):
    """Compute reachability rings + the priority Venn search zone for a case.

    Args:
      last_seen: the last-seen point — {"lat","lng","seen_at"(iso)} (or None / a
                 coord-less dict, which is tolerated).
      sightings: list of sighting points — each {"lat","lng","seen_at"(iso),
                 "source"} (may be empty/None). Coord-less entries are skipped.
                 ORDER MATTERS: oldest-first, newest-last, so the movement cone reads
                 direction off the freshest leg of the trail (api.py stores sightings
                 in this order).
      now_iso:   the reference "now" as an ISO string — passed in (NOT read from the
                 clock) so the engine is deterministic/testable.
      speed_kmh: optional explicit ground speed (km/h) for every ring. Overrides
                 terrain.
      terrain:   optional terrain class (one of engine.terrain.TERRAINS, e.g.
                 "forest") — used with the sibling terrain module's speed policy so
                 off-road rings are correctly tighter. Ignored if speed_kmh is given.

    Returns a JSON-serializable dict:
      {
        "rings": [ {center:[lat,lng], radius_km, from_source, age_hours}, ... ],
        "priority_zone": {center:[lat,lng], radius_km, confidence(0..1), ring_count}
                          | None,                # the densest overlap (most agree)
        "candidate_zones": [ ...the same shape, ranked by confidence desc... ],
        "movement_cone": { ...forward wedge... } | None,
        "ring_count": int,                       # number of usable rings
        "skipped_points": int,                   # coord-less points dropped
        "disclaimer": "<bright-line probability text>",   # ALWAYS present
        "explanation": "<plain-words summary>",
      }

    BRIGHT LINE: `confidence` is a probability in [0,1] (never 1.0), the result is a
    likely zone NOT a pinpoint location, and `disclaimer` says so. Pure/read-only:
    inputs are never mutated. Degenerate inputs (no points, one point, coincident
    points, bad coords, bad timestamps) all return a well-formed result, never raise.
    """
    rings, skipped = _build_rings(last_seen, sightings, now_iso, speed_kmh, terrain)

    if not rings:
        out = _empty_result("all points were missing or had no coordinates")
        out["skipped_points"] = skipped
        return out

    total = len(rings)
    public_rings = [_ring_public(r) for r in rings]

    # Overlap scan -> zones keyed by how many rings agree.
    zones_by_count, max_count = _scan_overlap(rings)

    # Rank every distinct-overlap zone by confidence (then by tighter radius). The
    # densest (max_count) zone is the priority zone; the rest are fall-backs.
    ranked = []
    for k in sorted(zones_by_count.keys(), reverse=True):
        ranked.append(_zone_public(zones_by_count[k], k, total))
    ranked.sort(key=lambda z: (-z["confidence"], z["radius_km"]))

    priority = None
    for z in ranked:
        if z["ring_count"] == max_count:
            priority = z
            break
    if priority is None and ranked:
        priority = ranked[0]

    cone = _movement_cone(rings, last_seen, sightings, now_iso, speed_kmh, terrain)

    # Plain-words explanation — honest, never asserting a pinpoint.
    if total == 1:
        explanation = (
            "Only one credible point is known, so the likely area is a single "
            "reachability ring (~%d km) around it — too little to triangulate. "
            "A second sighting would tighten the estimate."
            % round(rings[0]["radius_km"])
        )
    elif priority:
        explanation = (
            "%d of %d credible points agree on the highlighted zone (~%d km "
            "across), making it the priority area to search. This is a likely "
            "zone, not a confirmed location."
            % (priority["ring_count"], total, round(priority["radius_km"]))
        )
        if cone:
            explanation += " The trail suggests movement toward the %s." % cone["heading"]
    else:
        explanation = (
            "%d credible points were found but their reachability rings do not yet "
            "overlap into a single zone — search near the most recent point and add "
            "sightings to converge the estimate." % total
        )

    return {
        "rings": public_rings,
        "priority_zone": priority,
        "candidate_zones": ranked,
        "movement_cone": cone,
        "ring_count": total,
        "skipped_points": skipped,
        "disclaimer": DISCLAIMER,
        "explanation": explanation,
    }


# ===========================================================================
# SELF-TEST  (python engine/triangulate.py)
# ===========================================================================
if __name__ == "__main__":
    # Helper: build an ISO timestamp `hours_ago` before a fixed reference "now".
    # Fixed clock so the test is deterministic (the whole point of passing now_iso).
    NOW = datetime.datetime(2026, 6, 5, 12, 0, 0)
    NOW_ISO = NOW.isoformat(timespec="seconds")

    def ago(hours):
        return (NOW - datetime.timedelta(hours=hours)).isoformat(timespec="seconds")

    abuja = (9.0765, 7.3986)
    kaduna = (10.5105, 7.4165)

    # --- haversine parity with routing.py / api.py -------------------------
    d = haversine_km(abuja, kaduna)
    assert 150 < d < 210, d
    assert haversine_km(abuja, abuja) == 0.0
    # dict + lon-alias path == tuple path
    assert abs(haversine_km({"lat": 9.0765, "lon": 7.3986}, kaduna) - d) < 1e-9
    # coord-less point -> 0.0, never raises
    assert haversine_km({"lat": None, "lng": None}, kaduna) == 0.0

    # --- point coercion is forgiving (None, not raise) ---------------------
    assert _as_latlng((9.0, 7.0)) == (9.0, 7.0)
    assert _as_latlng({"lat": 9.0, "lng": 7.0}) == (9.0, 7.0)
    assert _as_latlng({"lat": 9.0, "lon": 7.0}) == (9.0, 7.0)
    for bad in (None, (1,), {"lat": 1}, "x", {"lat": "NaN", "lng": 1},
                {"lat": float("nan"), "lng": 1.0}):
        assert _as_latlng(bad) is None, bad

    # --- elapsed hours: floor, future, garbage all degrade safely ----------
    assert abs(_elapsed_hours(ago(3), NOW_ISO) - 3.0) < 1e-6
    assert _elapsed_hours(ago(0.0), NOW_ISO) == MIN_HOURS          # at-now -> floor
    assert _elapsed_hours(ago(-5), NOW_ISO) == MIN_HOURS           # future -> floor
    assert _elapsed_hours(None, NOW_ISO) == MIN_HOURS
    assert _elapsed_hours("not-a-date", NOW_ISO) == MIN_HOURS
    assert _elapsed_hours(ago(3), "garbage") == MIN_HOURS          # bad now -> floor

    # --- reach_radius_km: grows with time, capped, terrain-tighter ---------
    r1 = reach_radius_km(1, speed_kmh=25)
    r3 = reach_radius_km(3, speed_kmh=25)
    r6 = reach_radius_km(6, speed_kmh=25)
    assert r1 < r3 < r6, (r1, r3, r6)             # RING RADIUS GROWS WITH ELAPSED TIME
    assert reach_radius_km(3, speed_kmh=25) == 75.0
    # explicit speed beats terrain default; off-road (slower) -> tighter ring
    fast = reach_radius_km(3, speed_kmh=50)       # ~road
    slow = reach_radius_km(3, speed_kmh=12)       # ~forest on foot
    assert slow < fast, (slow, fast)
    # cap: long elapsed is clamped to MAX_RADIUS_KM, never unbounded
    assert reach_radius_km(1000, speed_kmh=50) == MAX_RADIUS_KM
    # bad hours -> floor, never raises / never negative
    assert reach_radius_km("x", speed_kmh=25) == 25.0 * MIN_HOURS
    assert reach_radius_km(-9, speed_kmh=25) == 25.0 * MIN_HOURS
    # no speed + no terrain -> conservative default (== terrain.py MIXED), not 50
    assert reach_radius_km(1) == DEFAULT_SPEED_KMH
    # terrain integration: when the sibling terrain module is importable, a class
    # name yields ITS speed (forest tighter than road). Skip cleanly if not on path.
    try:
        import terrain as _t
        rf = reach_radius_km(3, terrain="forest")
        rr = reach_radius_km(3, terrain="road")
        assert rf < rr, (rf, rr)
        assert rf == _t.reach_radius(3, "forest") or abs(rf - _t.speed_for("forest") * 3) < 1e-6
    except ImportError:
        pass

    # --- single point: one ring, no triangulation, low capped confidence ---
    res1 = search_zones({"lat": abuja[0], "lng": abuja[1], "seen_at": ago(3)},
                        [], NOW_ISO, speed_kmh=25)
    assert res1["ring_count"] == 1 and len(res1["rings"]) == 1
    assert res1["rings"][0]["from_source"] == "last_seen"
    assert res1["priority_zone"] is not None
    assert 0.0 <= res1["priority_zone"]["confidence"] <= 1.0     # CONFIDENCE IN [0,1]
    assert res1["priority_zone"]["confidence"] <= 0.3            # one point can't be sure
    assert res1["movement_cone"] is None                        # no direction from 1 pt
    assert res1["disclaimer"] == DISCLAIMER and res1["disclaimer"]   # DISCLAIMER PRESENT
    assert "exact" not in res1["explanation"].lower()           # bright line: no "exact"

    # --- two points: OVERLAP zone computed, confidence in [0,1] ------------
    # last-seen 4h ago at Abuja; a sighting 1h ago partway toward Kaduna.
    mid = (9.8, 7.41)
    res2 = search_zones(
        {"lat": abuja[0], "lng": abuja[1], "seen_at": ago(4)},
        [{"lat": mid[0], "lng": mid[1], "seen_at": ago(1), "source": "tip"}],
        NOW_ISO, speed_kmh=40)
    assert res2["ring_count"] == 2
    pz = res2["priority_zone"]
    assert pz is not None and pz["ring_count"] >= 1
    assert 0.0 <= pz["confidence"] <= 1.0                       # OVERLAP CONFIDENCE IN [0,1]
    assert pz["confidence"] < 1.0                               # never certainty
    assert pz["ring_count"] == 2                                # both rings agree on the zone
    # sighting source label is carried through
    srcs = {r["from_source"] for r in res2["rings"]}
    assert srcs == {"last_seen", "tip"}, srcs
    # candidate_zones is ranked by confidence (desc)
    confs = [z["confidence"] for z in res2["candidate_zones"]]
    assert confs == sorted(confs, reverse=True), confs
    # movement cone exists (last-seen -> sighting gives a direction) and is forward-N
    assert res2["movement_cone"] is not None
    assert res2["movement_cone"]["heading"] in _COMPASS
    assert "north" in res2["movement_cone"]["heading"]         # mid is ~due north of abuja

    # --- BRIGHT LINE: a more RECENT sighting TIGHTENS the priority zone -----
    # Same geometry; vary only the sighting's freshness. Fresher -> smaller ring ->
    # tighter (smaller-radius) and at-least-as-confident priority zone.
    def zone_for(sighting_age):
        return search_zones(
            {"lat": abuja[0], "lng": abuja[1], "seen_at": ago(6)},
            [{"lat": mid[0], "lng": mid[1], "seen_at": ago(sighting_age)}],
            NOW_ISO, speed_kmh=40)["priority_zone"]
    fresh = zone_for(0.5)     # very recent sighting
    stale = zone_for(5.0)     # older sighting
    assert fresh["radius_km"] <= stale["radius_km"], (fresh, stale)   # RECENT -> TIGHTER
    assert fresh["confidence"] >= stale["confidence"] - 1e-9, (fresh, stale)

    # --- no sightings at all: ring around last-seen only -------------------
    res0 = search_zones({"lat": abuja[0], "lng": abuja[1], "seen_at": ago(2)},
                        None, NOW_ISO, speed_kmh=25)
    assert res0["ring_count"] == 1 and res0["movement_cone"] is None
    assert res0["priority_zone"] is not None and res0["disclaimer"]

    # --- coincident points: no crash, returns a zone at that point ---------
    resc = search_zones(
        {"lat": abuja[0], "lng": abuja[1], "seen_at": ago(3)},
        [{"lat": abuja[0], "lng": abuja[1], "seen_at": ago(3)},
         {"lat": abuja[0], "lng": abuja[1], "seen_at": ago(2)}],
        NOW_ISO, speed_kmh=25)
    assert resc["ring_count"] == 3
    assert resc["priority_zone"] is not None
    assert 0.0 <= resc["priority_zone"]["confidence"] <= 1.0
    # all three rings overlap at the shared center
    assert resc["priority_zone"]["ring_count"] == 3

    # --- missing coords are SKIPPED, not pinned to (0,0) -------------------
    ress = search_zones(
        {"lat": abuja[0], "lng": abuja[1], "seen_at": ago(3)},
        [{"seen_at": ago(1)},                          # no coords -> skipped
         {"lat": None, "lng": None, "seen_at": ago(1)},  # null coords -> skipped
         {"lat": mid[0], "lng": mid[1], "seen_at": ago(1)}],
        NOW_ISO, speed_kmh=40)
    assert ress["ring_count"] == 2                     # last-seen + the 1 good sighting
    assert ress["skipped_points"] == 2
    # none of the rings sits at (0,0)
    assert all(not (r["center"] == [0.0, 0.0]) for r in ress["rings"])

    # --- bad / empty input -> well-formed EMPTY result, never raises -------
    for bad_in in (
        search_zones(None, None, NOW_ISO),
        search_zones(None, [], NOW_ISO),
        search_zones({}, [], NOW_ISO),
        search_zones({"lat": None, "lng": None, "seen_at": ago(1)}, [], NOW_ISO),
        search_zones(None, [{"foo": "bar"}], NOW_ISO),
        search_zones(None, None, None),                 # even now_iso missing
    ):
        assert bad_in["rings"] == []
        assert bad_in["priority_zone"] is None
        assert bad_in["candidate_zones"] == []
        assert bad_in["movement_cone"] is None
        assert bad_in["ring_count"] == 0
        assert bad_in["disclaimer"] == DISCLAIMER       # DISCLAIMER PRESENT even when empty
        assert "explanation" in bad_in and bad_in["explanation"]

    # --- purity: caller's inputs are never mutated -------------------------
    src_ls = {"lat": abuja[0], "lng": abuja[1], "seen_at": ago(3)}
    src_sg = [{"lat": mid[0], "lng": mid[1], "seen_at": ago(1)}]
    before = (dict(src_ls), [dict(s) for s in src_sg])
    _ = search_zones(src_ls, src_sg, NOW_ISO, speed_kmh=40)
    assert src_ls == before[0] and src_sg == before[1]   # unchanged

    # --- JSON-serializable end to end (api.py will json.dumps this) --------
    import json
    blob = json.dumps(search_zones(src_ls, src_sg, NOW_ISO, speed_kmh=40))
    assert isinstance(blob, str) and len(blob) > 0
    # bright line in the serialized payload: never the word "exact"; disclaimer there
    assert "exact" not in blob.lower()
    assert DISCLAIMER in blob

    # --- three sightings: cone reads the FRESHEST leg of the trail ---------
    res3 = search_zones(
        {"lat": abuja[0], "lng": abuja[1], "seen_at": ago(5)},
        [{"lat": 9.4, "lng": 7.40, "seen_at": ago(3)},
         {"lat": 9.8, "lng": 7.41, "seen_at": ago(2)},
         {"lat": 10.2, "lng": 7.42, "seen_at": ago(0.5)}],   # newest, still heading N
        NOW_ISO, speed_kmh=40)
    assert res3["ring_count"] == 4
    assert res3["movement_cone"] is not None
    assert "north" in res3["movement_cone"]["heading"]
    # cone anchored at the NEWEST sighting, projected forward, bounded by CONE_MAX_KM
    assert res3["movement_cone"]["anchor"] == [round(10.2, 6), round(7.42, 6)]
    assert res3["movement_cone"]["length_km"] <= CONE_MAX_KM
    assert len(res3["movement_cone"]["polygon"]) >= 3   # a real wedge

    # --- public surface carries docstrings ---------------------------------
    for fn in (search_zones, reach_radius_km, haversine_km):
        assert fn.__doc__, fn.__name__

    print("triangulate.py self-test OK")
