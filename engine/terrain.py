"""Terrain-aware search-radius helpers for DeySafe / SHIELD (FIND-02).

The original FindMe / missing_with_radius math assumed a flat ~50 km/h spread
from the last credible point (api.py: `radius_km = int(min(hrs * 50, 250))`).
That is a *highway* assumption. A4/A3-5.5 flagged it: an abductee moved on foot
through forest, hills, or riverine bush covers 5-15 km/h, not 50 — so a flat
50 km/h circle is 3-5x too large, diluting the search and sending responders to
the wrong ring. Over-large radii are not a harmless conservatism here: they make
the "most likely zone" meaningless and waste scarce ground-team time.

This module is the single, auditable home for the terrain -> speed -> reach
policy. Two public functions:

  - reach_radius(hours, terrain) -> km   distance reachable in `hours`, capped.
  - classify_terrain(direction_text, place) -> one of TERRAINS, a best guess from
    the free-text `direction` / locality the field user typed (e.g. "North into
    the forest toward Jibia" -> "forest").

Design rules (mirror security.py / response.py):
  - STDLIB ONLY. No DB handle, no env reads, no network, no I/O. Every public
    function is pure/deterministic given its inputs, so it is trivially unit-
    testable and safe to call from any request thread, and api.py / db.py can
    import it with zero side effects.
  - This module only computes a *radius*. It never widens a zone silently and
    never invents a location: classify_terrain falls back to a conservative
    DEFAULT_TERRAIN when it cannot tell, and reach_radius keeps the existing
    250 km hard cap so swapping it in for the flat-50 line is behaviour-
    preserving for the on-road case (the common-carrier default) while shrinking
    the off-road cases that were previously over-stated.
"""
import re

# ---------------------------------------------------------------------------
# Terrain -> overground speed policy
# ---------------------------------------------------------------------------
# Terrain classes and the approximate ground speed (km/h) a moving party can
# sustain across them. These are deliberately coarse, conservative search-
# planning figures (how far the subject *could* be), not travel estimates:
#   road     ~50  motorable highway / tarred road (vehicle-borne movement)
#   mixed    ~25  partly motorable: bush tracks, mixed bush-and-road, unknown
#   forest   ~12  dense bush / forest on foot (the typical NW/NC abduction case)
#   mountain  ~8  hills / rugged terrain / riverine on foot (slowest)
ROAD = "road"
MIXED = "mixed"
FOREST = "forest"
MOUNTAIN = "mountain"

TERRAINS = (ROAD, MIXED, FOREST, MOUNTAIN)

# When we cannot tell from the text, assume MIXED rather than ROAD. A wrong-but-
# smaller ring is safer for search planning than a wrong-but-huge one, and most
# real NW/NC abduction movement is off the highway within minutes.
DEFAULT_TERRAIN = MIXED

TERRAIN_SPEED_KMH = {
    ROAD: 50.0,
    MIXED: 25.0,
    FOREST: 12.0,
    MOUNTAIN: 8.0,
}

# Hard cap on the search radius (km), regardless of elapsed time — matches the
# existing api.py cap so the on-road path is behaviour-preserving. Even on a
# highway, an unbounded ring stops being a useful "most likely zone".
MAX_RADIUS_KM = 250

# A sane floor on elapsed time so a just-reported case still yields a non-zero,
# searchable ring (mirrors api.py's `max(0.25, ...)`).
MIN_HOURS = 0.25


def speed_for(terrain):
    """Overground speed (km/h) for a terrain class.

    Unknown / None terrain falls back to the DEFAULT_TERRAIN speed (never raises).
    """
    return TERRAIN_SPEED_KMH.get(terrain, TERRAIN_SPEED_KMH[DEFAULT_TERRAIN])


def reach_radius(hours, terrain=DEFAULT_TERRAIN):
    """Search radius (km) reachable in `hours` over `terrain`, capped.

    radius = speed_for(terrain) * max(hours, MIN_HOURS), clamped to
    [0, MAX_RADIUS_KM] and returned as an int (whole km — the search ring is
    drawn at km granularity). Pure: callers persist the result. Bad/None `hours`
    is treated as the MIN_HOURS floor rather than raising, so a malformed
    timestamp upstream degrades to the smallest sensible ring instead of an error.
    """
    try:
        h = float(hours)
    except (TypeError, ValueError):
        h = MIN_HOURS
    if h != h or h < MIN_HOURS:      # NaN or below floor -> floor
        h = MIN_HOURS
    km = speed_for(terrain) * h
    if km < 0:
        km = 0.0
    return int(min(km, MAX_RADIUS_KM))


# ---------------------------------------------------------------------------
# Free-text -> terrain classifier
# ---------------------------------------------------------------------------
# Ordered most-specific (slowest) first so the slowest matching terrain wins when
# a description mentions several features (e.g. "through the forest toward the
# highway" -> FOREST, because the off-road leg dominates the reachable radius and
# under-stating the ring is the dangerous direction). Each entry is
# (terrain, [keywords]); keywords are matched as whole words, case-insensitively,
# against the combined direction + place text.
_TERRAIN_KEYWORDS = (
    (MOUNTAIN, [
        "mountain", "mountains", "mountainous", "hill", "hills", "hilly",
        "highland", "highlands", "plateau", "rock", "rocks", "rocky", "cliff",
        "ridge", "valley", "gorge", "river", "riverine", "swamp", "swampy",
        "creek", "creeks", "marsh", "wetland", "mambilla", "mandara",
    ]),
    (FOREST, [
        "forest", "forests", "forested", "bush", "bushes", "jungle", "woods",
        "woodland", "thicket", "shrub", "scrub", "savannah", "savanna", "grove",
        "rugu", "reserve", "game reserve", "national park", "sambisa", "falgore",
        "kamuku", "into the bush", "into the forest",
    ]),
    (ROAD, [
        "road", "roads", "highway", "expressway", "motorway", "tarred", "tar",
        "asphalt", "checkpoint", "junction", "roundabout", "toll", "tollgate",
        "bypass", "ring road", "street", "by vehicle", "on the road",
        "abuja-kaduna", "kaduna-abuja", "by car", "convoy",
    ]),
    (MIXED, [
        "track", "tracks", "path", "footpath", "trail", "village", "villages",
        "hamlet", "outskirts", "rural", "farmland", "farm", "farms", "field",
        "fields", "settlement", "settlements", "border", "interland",
        "hinterland", "remote", "off-road", "off road", "dirt",
    ]),
)


def _norm(*parts):
    """Lower-cased, whitespace-collapsed join of the given text fragments."""
    text = " ".join(str(p) for p in parts if p)
    return re.sub(r"\s+", " ", text).strip().lower()


def _has_word(text, kw):
    """True if `kw` appears in `text` as a whole word / phrase (case-folded text).

    Word boundaries keep 'tar' from matching 'target' and 'hill' from 'Phillip',
    while still allowing multi-word phrases like 'national park'.
    """
    return re.search(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", text) is not None


def classify_terrain(direction_text=None, place=None):
    """Best-guess terrain class from the free-text direction + locality.

    `direction_text` is the operator/field 'direction' note (e.g. the missing-
    person 'direction' field: "North into the forest toward Jibia"); `place` is
    the locality label. Returns one of TERRAINS. Matching is most-specific-
    (slowest-)terrain-first, so when several features are named the one that
    most constrains the reachable radius wins (under-stating the search ring is
    the dangerous direction for a person on foot). No signal at all -> the
    conservative DEFAULT_TERRAIN. Never raises; never invents a location.
    """
    text = _norm(direction_text, place)
    if not text:
        return DEFAULT_TERRAIN
    for terrain, keywords in _TERRAIN_KEYWORDS:
        for kw in keywords:
            if _has_word(text, kw):
                return terrain
    return DEFAULT_TERRAIN


def reach_radius_for(hours, direction_text=None, place=None):
    """Convenience: classify the text, then return the terrain-aware reach radius.

    This is the single call api.py / FindMe substitutes for the old flat
    `int(min(hours * 50, 250))`: it derives the terrain from whatever 'direction'
    / 'place' text the case carries and returns (radius_km, terrain) so the caller
    can both size the ring AND surface the assumption it used (no silent widening).
    """
    terrain = classify_terrain(direction_text, place)
    return reach_radius(hours, terrain), terrain


# ===========================================================================
# SELF-TEST  (python engine/terrain.py)
# ===========================================================================
if __name__ == "__main__":
    # --- speed policy ------------------------------------------------------
    assert speed_for(ROAD) == 50.0
    assert speed_for(MIXED) == 25.0
    assert speed_for(FOREST) == 12.0
    assert speed_for(MOUNTAIN) == 8.0
    # unknown / None terrain -> default-terrain speed, never raises
    assert speed_for("bogus") == TERRAIN_SPEED_KMH[DEFAULT_TERRAIN]
    assert speed_for(None) == TERRAIN_SPEED_KMH[DEFAULT_TERRAIN]
    # speeds are strictly ordered slowest->fastest mountain<forest<mixed<road
    assert speed_for(MOUNTAIN) < speed_for(FOREST) < speed_for(MIXED) < speed_for(ROAD)

    # --- reach_radius: terrain shrinks the ring ----------------------------
    # 3 hours on each terrain (3h is the seeded Kankara case age).
    assert reach_radius(3, ROAD) == 150        # 3 * 50
    assert reach_radius(3, MIXED) == 75        # 3 * 25
    assert reach_radius(3, FOREST) == 36       # 3 * 12
    assert reach_radius(3, MOUNTAIN) == 24     # 3 * 8
    # the whole point of FIND-02: off-road is dramatically smaller than highway.
    assert reach_radius(3, FOREST) < reach_radius(3, ROAD)
    assert reach_radius(5, FOREST) <= reach_radius(5, ROAD) / 3 + 1  # ~3-5x tighter

    # default terrain is used when omitted, and it is the conservative MIXED
    assert reach_radius(3) == reach_radius(3, DEFAULT_TERRAIN) == 75

    # behaviour-preserving on-road path: matches the OLD api.py formula exactly
    # (radius_km = int(min(hrs * 50, 250))) for the ROAD case, including the cap.
    for hrs in (0.25, 1.0, 1.5, 2.0, 3.3, 4.9, 6.0):
        assert reach_radius(hrs, ROAD) == int(min(hrs * 50, 250)), hrs

    # cap: even a long elapsed time on a highway is clamped to MAX_RADIUS_KM
    assert reach_radius(100, ROAD) == MAX_RADIUS_KM
    assert reach_radius(1000, FOREST) == MAX_RADIUS_KM   # forest can cap too, eventually

    # floor + garbage hours degrade to the smallest sensible ring, never raise
    assert reach_radius(0, ROAD) == int(MIN_HOURS * 50)      # 12
    assert reach_radius(-5, ROAD) == int(MIN_HOURS * 50)     # negative -> floor
    assert reach_radius(None, ROAD) == int(MIN_HOURS * 50)
    assert reach_radius("not-a-number", ROAD) == int(MIN_HOURS * 50)
    assert reach_radius(float("nan"), ROAD) == int(MIN_HOURS * 50)
    # result is always a plain int within [0, MAX]
    r = reach_radius(7.2, FOREST)
    assert isinstance(r, int) and 0 <= r <= MAX_RADIUS_KM

    # --- classify_terrain --------------------------------------------------
    # the seeded Kankara case direction text classifies as forest (the dangerous,
    # tight ring), NOT road — this is the exact regression FIND-02 fixes.
    assert classify_terrain("North into the forest toward Jibia") == FOREST
    assert classify_terrain("taken on motorcycles into the bush") == FOREST
    assert classify_terrain("up into the hills past the village") == MOUNTAIN
    assert classify_terrain("along the Abuja-Kaduna highway") == ROAD
    assert classify_terrain("down to the river and across the creek") == MOUNTAIN
    # 'bush' is a FOREST signal even alongside 'track' (slowest match wins).
    assert classify_terrain("on a bush track toward the settlement") == FOREST
    # a clean MIXED case (no forest/road/mountain word, only a track/settlement).
    assert classify_terrain("along a dirt track to the next village") == MIXED
    # place text alone is enough
    assert classify_terrain(None, "Sambisa") == FOREST
    assert classify_terrain("", "Mambilla Plateau") == MOUNTAIN
    # most-specific (slowest) wins when several features co-occur: a forest leg
    # toward a highway is sized by the forest leg (under-stating is dangerous).
    assert classify_terrain("through the forest toward the highway") == FOREST
    assert classify_terrain("over the hills then onto the road") == MOUNTAIN
    # no usable signal -> conservative default, never raises
    assert classify_terrain(None, None) == DEFAULT_TERRAIN
    assert classify_terrain("", "") == DEFAULT_TERRAIN
    assert classify_terrain("headed somewhere unknown") == DEFAULT_TERRAIN
    # whole-word matching: 'tar' must not fire on 'target', 'hill' not on a name
    assert classify_terrain("the target was last seen") == DEFAULT_TERRAIN
    assert classify_terrain("with a man named Phillip") == DEFAULT_TERRAIN
    # case-insensensitive + punctuation tolerant
    assert classify_terrain("INTO THE FOREST.") == FOREST
    assert classify_terrain("North,  into   the   BUSH!") == FOREST
    # output is always a member of the controlled vocabulary
    for txt in ("forest", "hill road", "", None, "random words", "river bank"):
        assert classify_terrain(txt) in TERRAINS

    # --- reach_radius_for: end-to-end (text -> radius + surfaced assumption) -
    rad, terr = reach_radius_for(3, "North into the forest toward Jibia", "Kankara")
    assert terr == FOREST and rad == 36
    # an on-highway case stays at the old 150 km ring AND reports terrain='road'
    rad2, terr2 = reach_radius_for(3, "along the highway", "Kaduna")
    assert terr2 == ROAD and rad2 == 150
    # unknown text -> default terrain + its (tighter-than-road) ring
    rad3, terr3 = reach_radius_for(3, None, None)
    assert terr3 == DEFAULT_TERRAIN and rad3 == 75

    # docstrings present (these are the public surface api.py will lean on)
    for fn in (speed_for, reach_radius, classify_terrain, reach_radius_for):
        assert fn.__doc__, fn.__name__

    print("terrain.py self-test OK")
