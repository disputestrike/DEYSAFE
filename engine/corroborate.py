"""Cluster geo-parsed detections into incidents with calibrated confidence.

This module is where the governance rules live as code:
  - corroboration across *independent* sources raises confidence (diminishing returns),
  - a single unverified source is capped low,
  - nothing is ever auto-"verified": the strongest automatic status is
    `needs_human_review`, which routes the event to a human decision.

Corroboration hardening (audit DATA-06/07/08):
  - DATA-06 source independence: signals from outlets that share an owner or
    ride the same wire service do NOT count as independent corroboration. We
    collapse `source_name` to a canonical outlet/owner before counting.
  - DATA-07 temporal decay: a member's corroboration weight decays with age
    inside the 72h window, so a stale report props up confidence less than a
    fresh one.
  - DATA-08 semantic duplicate detection: ten people describing the SAME event
    in different words are ONE source, not ten. Near-duplicate member texts
    (high token Jaccard) are merged before independence is counted.

Status policy is unchanged: never auto-"verified"; a lone unverified source is
capped low.
"""
import math
import datetime
import re
import hashlib

WINDOW_HOURS = 72
CLUSTER_KM = 30          # default "same incident" radius (P2-06 baseline)

# P2-06: large northern LGAs (Shiroro, Birnin Gwari, Rafi, ...) span well over
# 30 km, so two reports of the SAME event geolocate to points >30 km apart and
# fail to cluster. The radius is therefore made adaptive (see cluster_radius_km):
#   - wider when the two detections are in the same LGA/town or same state, or
#     are a long-range incident type (kidnapping/banditry along highways);
#   - tighter for dense-urban types (armed robbery in a city) where two distant
#     reports are more likely to be genuinely separate events.
CLUSTER_KM_WIDE = 55     # same-area / long-range upper bound
CLUSTER_KM_URBAN = 18    # dense-urban types: keep "same incident" tight

# Incident types that routinely play out over long distances (convoys ambushed
# along a highway, raids sweeping several hamlets of one LGA). Two such reports a
# few dozen km apart are very likely the same rolling event.
LONG_RANGE_TYPES = frozenset((
    "kidnapping", "banditry_attack", "banditry", "abduction", "missing_person",
))
# Types that are point events in built-up areas; distant reports are likely
# distinct incidents, so we do NOT widen for these on distance alone.
URBAN_TYPES = frozenset(("armed_robbery",))

# DATA-07: a member at the far edge of the window still counts, but at this
# fraction of a fresh report. Linear decay between 1.0 (age 0) and the floor.
DECAY_FLOOR = 0.35

# DATA-08: two member texts with Jaccard token overlap >= this are treated as
# the same eyewitness account / syndicated copy (one source, not many).
DUP_JACCARD = 0.6

# P1-03: wire-service republication. When several outlets reprint ONE wire story
# (e.g. a single NAN dispatch carried verbatim by Punch, Vanguard, ThisDay,
# Leadership), the texts are near-identical. Token overlap at/above this higher
# threshold is treated as "the same story republished" and collapses to ONE
# effective source for confidence scoring, even across different mastheads --
# so four mirror copies do not inflate source_count to 4. Genuinely distinct
# independent reports (which share only place/topic words, not the whole story)
# fall well below this and keep counting separately.
DUP_JACCARD_TEXT = 0.8

# DATA-06: canonical outlet/owner aliases. Many Nigerian incidents are picked
# up by a single wire service (NAN, Reuters, AFP) and reprinted verbatim by
# dozens of papers; several mastheads also share a parent company. Counting
# those as independent corroboration inflates confidence. Map the noisy
# `source_name` to a stable owner key; anything unknown stays distinct (maps to
# itself), so genuine independent local reports are never wrongly merged.
OUTLET_ALIASES = {
    # --- wire services (syndication: one wire, many reprints) ---
    "nan": "wire:nan", "news agency of nigeria": "wire:nan",
    "reuters": "wire:reuters", "thomson reuters": "wire:reuters",
    "afp": "wire:afp", "agence france-presse": "wire:afp",
    "ap": "wire:ap", "associated press": "wire:ap",
    "bbc": "wire:bbc", "bbc news": "wire:bbc", "bbc hausa": "wire:bbc",
    # --- shared ownership / same masthead family ---
    "punch": "owner:punch", "punch newspapers": "owner:punch", "punch ng": "owner:punch",
    "the punch": "owner:punch",
    "vanguard": "owner:vanguard", "vanguard news": "owner:vanguard", "vanguard ngr": "owner:vanguard",
    "premium times": "owner:premiumtimes", "premiumtimes": "owner:premiumtimes",
    "daily trust": "owner:dailytrust", "dailytrust": "owner:dailytrust", "trust": "owner:dailytrust",
    "channels": "owner:channels", "channels tv": "owner:channels", "channels television": "owner:channels",
    "the nation": "owner:thenation", "thenation": "owner:thenation",
    "guardian": "owner:guardianng", "the guardian nigeria": "owner:guardianng",
    "guardian nigeria": "owner:guardianng", "guardian ng": "owner:guardianng",
    "sahara reporters": "owner:sahara", "saharareporters": "owner:sahara",
    "leadership": "owner:leadership", "leadership newspaper": "owner:leadership",
    "thisday": "owner:thisday", "this day": "owner:thisday",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")
# Boilerplate / demo / stop tokens that carry no event identity and would
# otherwise inflate the overlap between unrelated reports.
_STOP = frozenset((
    "sample", "the", "a", "an", "of", "in", "on", "at", "to", "for", "and",
    "near", "around", "along", "said", "reported", "reportedly", "report",
    "residents", "people", "after", "were", "was", "has", "have", "had",
    "into", "from", "with", "by", "an", "are", "is", "as", "that", "this",
    "second", "corroborating", "fresh", "some",
))


def _haversine(a, b):
    (lat1, lng1), (lat2, lng2) = a, b
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lng2 - lng1)
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(x))


def _parse(ts):
    try:
        return datetime.datetime.fromisoformat(ts)
    except Exception:
        return datetime.datetime.now()


def _norm_place(v):
    return re.sub(r"\s+", " ", (v or "").strip().lower())


def cluster_radius_km(a, b):
    """P2-06: adaptive "same incident" radius (km) for two detection dicts.

    Pure / deterministic / stdlib only. Reads only fields a detection is known to
    carry: type, location_name, state (and lga if a future source ever supplies
    one). It NEVER assumes a field exists -- everything goes through .get with a
    default -- so it is safe for both gazetteer detections and structured reports.

    Rule:
      * same LGA (if both carry an `lga`) or same named place/town  -> widen,
        because one large LGA can span >30 km and identical place names mean the
        two reports point at the same administrative area;
      * otherwise, same (non-empty) state AND a long-range type
        (kidnapping/banditry/abduction) -> widen, because such events roll along
        highways across an LGA/state;
      * a dense-urban type (armed_robbery) that is NOT in the same place stays
        tight, so two distant city robberies are not fused into one;
      * everything else -> the 30 km default.

    Symmetric in (a, b). Returns CLUSTER_KM, CLUSTER_KM_WIDE, or CLUSTER_KM_URBAN.
    """
    ta, tb = a.get("type"), b.get("type")

    lga_a, lga_b = _norm_place(a.get("lga")), _norm_place(b.get("lga"))
    same_lga = bool(lga_a) and lga_a == lga_b

    place_a, place_b = _norm_place(a.get("location_name")), _norm_place(b.get("location_name"))
    same_place = bool(place_a) and place_a == place_b

    state_a, state_b = _norm_place(a.get("state")), _norm_place(b.get("state"))
    same_state = bool(state_a) and state_a == state_b

    long_range = (ta in LONG_RANGE_TYPES) or (tb in LONG_RANGE_TYPES)
    urban = (ta in URBAN_TYPES) or (tb in URBAN_TYPES)

    # Same administrative area => widen regardless of type: it is one place.
    if same_lga or same_place:
        return CLUSTER_KM_WIDE

    # Long-range event sweeping one state => widen.
    if same_state and long_range:
        return CLUSTER_KM_WIDE

    # Dense-urban point event in different places => keep it tight.
    if urban and not long_range:
        return CLUSTER_KM_URBAN

    return CLUSTER_KM


def cluster(detections):
    clusters = []
    for d in detections:
        placed = False
        for c in clusters:
            if c["type"] != d["type"]:
                continue
            # P2-06: radius adapts to the area / incident type instead of a flat
            # 30 km, so one large northern LGA's worth of reports cluster as one
            # incident. `c` mirrors a detection's shape (type/location_name/state/
            # lga), so cluster_radius_km can read it directly.
            radius = cluster_radius_km(c, d)
            if _haversine((c["lat"], c["lng"]), (d["lat"], d["lng"])) > radius:
                continue
            if abs((_parse(d["published_at"]) - _parse(c["window_start"])).total_seconds()) > WINDOW_HOURS * 3600:
                continue
            c["members"].append(d)
            c["window_start"] = min(c["window_start"], d["published_at"])
            c["window_end"] = max(c["window_end"], d["published_at"])
            placed = True
            break
        if not placed:
            clusters.append({
                "type": d["type"], "lat": d["lat"], "lng": d["lng"],
                "location_name": d["location_name"], "state": d["state"],
                # carry lga through only if the detection had one (structured
                # reports may; gazetteer detections currently do not). Used by
                # cluster_radius_km for same-LGA widening; absent => ignored.
                "lga": d.get("lga"),
                "window_start": d["published_at"], "window_end": d["published_at"],
                "members": [d],
            })
    return clusters


# --- DATA-06: source independence -------------------------------------------

def outlet_of(source_name):
    """Collapse a raw `source_name` to a canonical outlet/owner key.

    Known wire services and same-owner mastheads map to a shared key so they
    cannot corroborate themselves. Unknown sources map to a normalized form of
    their own name, i.e. they stay independent of everyone else.
    """
    s = (source_name or "?").strip().lower()
    if s in OUTLET_ALIASES:
        return OUTLET_ALIASES[s]
    # substring match so "Punch Metro", "BBC News Pidgin", etc. still collapse
    for alias, owner in OUTLET_ALIASES.items():
        if alias in s:
            return owner
    return "src:" + re.sub(r"\s+", " ", s)


# --- DATA-08: semantic near-duplicate detection -----------------------------

def _tokens(m):
    text = ((m.get("title") or "") + " " + (m.get("text") or "")).lower()
    return frozenset(t for t in _TOKEN_RE.findall(text) if t not in _STOP and len(t) > 1)


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if not inter:
        return 0.0
    return inter / len(a | b)


def text_overlap(a, b):
    """Public, stdlib-only near-duplicate score in [0,1] for two member dicts.

    Normalized token (unigram) Jaccard over title+text with boilerplate/stop
    tokens removed. 1.0 == identical wording; ~0 == unrelated copy that merely
    shares a place name. Used to decide whether two sources are mirror copies of
    one story (P1-03) vs. genuinely independent reports.
    """
    return _jaccard(_tokens(a), _tokens(b))


def content_fingerprint(m):
    """P1-03: a stable content fingerprint for a member.

    Two reports carrying the SAME story text produce the SAME fingerprint
    regardless of which masthead republished it, so they can be collapsed to one
    effective source. Built from the sorted set of identity tokens (stop/boiler-
    plate removed) hashed to a short hex digest. Deterministic and stdlib-only.
    Empty text => a per-object sentinel so blank reports never collapse together.
    """
    toks = _tokens(m)
    if not toks:
        return "empty:" + str(id(m))
    key = " ".join(sorted(toks))
    return "fp:" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def dedup_members(members):
    """Group members that describe the SAME event (near-duplicate wording or a
    syndicated reprint) into one report. Returns a list of groups; each group is
    a list of the original member dicts. One real-world event => one group =>
    counts as one corroborating account regardless of how many copies exist.

    Two membership tests, both stdlib-only and order-independent in effect:
      * same canonical outlet/owner repeating itself (DATA-06) -> always a dup;
      * cross-outlet text overlap (P1-03):
          - >= DUP_JACCARD_TEXT (0.8): the SAME story republished -> collapse,
            so 4 outlets mirroring one NAN wire become ONE effective source;
          - >= DUP_JACCARD (0.6): the same eyewitness account in slightly
            different words (DATA-08) -> collapse.
    Each candidate is compared against a group's REPRESENTATIVE (first-member)
    tokens, not an accumulating union, so the similarity bar does not drift as a
    group grows and unrelated reports are never swept in by token bloat.
    """
    groups = []          # list of {"members": [...], "rep": frozenset}
    for m in members:
        tk = _tokens(m)
        mo = outlet_of(m.get("source_name"))
        placed = False
        for g in groups:
            same_outlet = any(outlet_of(x.get("source_name")) == mo for x in g["members"])
            sim = _jaccard(tk, g["rep"])
            if same_outlet or sim >= DUP_JACCARD_TEXT or sim >= DUP_JACCARD:
                g["members"].append(m)
                placed = True
                break
        if not placed:
            groups.append({"members": [m], "rep": tk})
    return [g["members"] for g in groups]


def effective_source_count(members):
    """P1-03/DATA-06/08: number of INDEPENDENT sources after collapsing wire
    republications and near-duplicate accounts, then counting distinct outlets.

    This is the integer that should drive corroboration/confidence: four mirror
    copies of one wire -> 1; four genuinely distinct reports -> 4. Pure helper so
    the rule can be tested and reused without recomputing the whole score.
    """
    outlets = set()
    for group in dedup_members(members):
        outlets.add(outlet_of(group[0].get("source_name")))
    return len(outlets)


# --- DATA-07: temporal decay -------------------------------------------------

def _now():
    return datetime.datetime.now()


def _recency_weight(published_at, ref=None):
    """Weight in [DECAY_FLOOR, 1.0] for a member by age within the 72h window.

    Fresh (age 0) -> 1.0; at/after the window edge -> DECAY_FLOOR. Future or
    unparseable timestamps clamp to 1.0 (treat as fresh, never negative).
    """
    ref = ref or _now()
    age_h = (ref - _parse(published_at)).total_seconds() / 3600.0
    if age_h <= 0:
        return 1.0
    frac = min(age_h / WINDOW_HOURS, 1.0)
    return 1.0 - (1.0 - DECAY_FLOOR) * frac


def score(c):
    members = c["members"]

    # DATA-08/P1-03 then DATA-06: collapse near-duplicate accounts and wire
    # republications (one NAN dispatch reprinted by 4 papers == 1 story), then
    # count how many *distinct outlets/owners* remain. This is the independent-
    # source signal that drives status; `source_count` below is exactly
    # effective_source_count(members) and can only be <= the raw member count, so
    # mirror copies can never inflate confidence.
    groups = dedup_members(members)
    ref = _now()

    independent_outlets = set()
    weighted_sources = 0.0          # DATA-07: decay-weighted independent count
    for g in groups:
        # one canonical outlet per de-duplicated account (the earliest/freshest
        # copy carries the group's recency)
        outlet = outlet_of(g[0].get("source_name"))
        independent_outlets.add(outlet)
        best_w = max(_recency_weight(x.get("published_at"), ref) for x in g)
        weighted_sources += best_w

    source_count = len(independent_outlets)          # integer independent sources
    # effective corroboration mass after independence + dedup + decay
    eff = min(weighted_sources, float(source_count))

    severity = max((m.get("severity", 0) for m in members), default=0)
    hotspot = any(m.get("hotspot") for m in members)

    # Calibrated-ish confidence with diminishing returns on extra *independent,
    # recent* sources. Using `eff` (<= source_count) means syndicated/stale
    # corroboration adds less than fresh independent corroboration.
    conf = 22 + 26 * math.log2(eff + 1)
    if severity:
        conf += 10
    if hotspot:
        conf += 6
    conf = int(max(5, min(99, conf)))

    # Decision policy / human gate. NEVER auto-"verified". Status keys on the
    # integer count of *independent* sources, so a 2nd genuinely-independent
    # report still corroborates (flow C), but 5 reprints of one wire do not.
    if source_count >= 2 and (severity or conf >= 65):
        status = "needs_human_review"
    elif source_count >= 2:
        status = "corroborated"
    else:
        status = "candidate_unverified"
        conf = min(conf, 45)  # a lone unverified source stays low by design

    summary = members[0].get("title") or "{} near {}".format(c["type"], c["location_name"])
    return {
        "type": c["type"],
        "location_name": c["location_name"],
        "state": c["state"],
        "lat": c["lat"], "lng": c["lng"],
        "window_start": c["window_start"], "window_end": c["window_end"],
        "source_count": source_count,
        "source_diversity": source_count,
        "severity": severity,
        "confidence": conf,
        "status": status,
        "summary": summary,
        "signal_ids": [m["signal_id"] for m in members],
    }


def build_incidents(detections):
    return [score(c) for c in cluster(detections)]


# --- self-test ---------------------------------------------------------------
if __name__ == "__main__":
    import datetime as _dt

    def _det(**kw):
        """Build a detection dict in the shape pipeline.py / api.recompute pass
        to build_incidents (gp fields + signal_id/source_name/published_at/title).
        """
        n = len(_det.calls)
        _det.calls.append(n)
        base = {
            "type": "kidnapping", "terms": [], "location_name": "?", "state": "",
            "lat": 0.0, "lng": 0.0, "hotspot": False, "lang": "en", "severity": 0,
            "signal_id": 1000 + n, "source_name": "Src", "title": "", "text": "",
            "published_at": _dt.datetime.now().isoformat(timespec="seconds"),
        }
        base.update(kw)
        return base
    _det.calls = []

    # ====================================================================
    # P2-06: adaptive cluster radius
    # ====================================================================
    # Two reports of the SAME kidnapping in Shiroro LGA, geolocated ~40 km
    # apart (a large northern LGA easily spans this). Same state (Niger),
    # long-range type -> cluster_radius_km widens past 30 km, so they MUST
    # collapse into ONE incident instead of two low-confidence candidates.
    p_a = _det(type="kidnapping", location_name="Shiroro", state="Niger",
               lat=9.9667, lng=6.8333, source_name="Daily Trust",
               title="Gunmen abduct residents in Shiroro",
               text="Gunmen abducted several residents in northern Shiroro overnight.",
               published_at="2026-06-08T08:00:00")
    p_b = _det(type="kidnapping", location_name="Shiroro", state="Niger",
               lat=10.3000, lng=6.5500, source_name="Premium Times",
               title="Several abducted in fresh Shiroro raid",
               text="A fresh raid in southern Shiroro left more travellers abducted.",
               published_at="2026-06-08T09:30:00")
    _gap = round(_haversine((p_a["lat"], p_a["lng"]), (p_b["lat"], p_b["lng"])), 1)
    assert _gap > CLUSTER_KM, "test setup: points should be >30km apart, got %s" % _gap
    _radius = cluster_radius_km(p_a, p_b)
    assert _radius == CLUSTER_KM_WIDE, "same-state long-range should widen, got %s" % _radius
    incs = build_incidents([p_a, p_b])
    assert len(incs) == 1, "P2-06 FAIL: same-LGA kidnapping ~%skm apart did NOT cluster -> %d incidents" % (_gap, len(incs))
    assert incs[0]["source_count"] == 2, "two independent outlets should corroborate, got %d" % incs[0]["source_count"]

    # Control 1: with the OLD flat 30 km radius these same points would NOT
    # cluster -> proves the fix (not coincidence) is what merged them.
    assert _haversine((p_a["lat"], p_a["lng"]), (p_b["lat"], p_b["lng"])) > CLUSTER_KM

    # Control 2: dense-urban type far apart in DIFFERENT cities must stay split
    # (we must not over-merge). Armed robberies ~40km apart, different places.
    r_a = _det(type="armed_robbery", location_name="Kaduna", state="Kaduna",
               lat=10.5222, lng=7.4383, source_name="Channels",
               title="Armed robbers hit Kaduna bank")
    r_b = _det(type="armed_robbery", location_name="Zaria", state="Kaduna",
               lat=10.5222, lng=7.9000, source_name="The Nation",
               title="Robbery at Zaria market")
    assert cluster_radius_km(r_a, r_b) == CLUSTER_KM_URBAN, "urban diff-place stays tight"
    assert len(build_incidents([r_a, r_b])) == 2, "distinct urban robberies must NOT merge"

    # ====================================================================
    # P1-03: wire-service republication must not inflate source_count
    # ====================================================================
    _WIRE_TITLE = "NAN: Gunmen abduct twelve travellers along Birnin Gwari highway"
    _WIRE_TEXT = ("The News Agency of Nigeria reports that gunmen abducted twelve "
                  "travellers along the Birnin Gwari highway on Tuesday, security "
                  "sources confirmed; a manhunt is underway.")
    # Four DIFFERENT mastheads carrying the SAME NAN dispatch verbatim.
    mirrors = [
        _det(source_name="Punch", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping", title=_WIRE_TITLE, text=_WIRE_TEXT,
             published_at="2026-06-08T07:00:00"),
        _det(source_name="Vanguard", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping", title=_WIRE_TITLE, text=_WIRE_TEXT,
             published_at="2026-06-08T07:20:00"),
        _det(source_name="ThisDay", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping", title=_WIRE_TITLE, text=_WIRE_TEXT,
             published_at="2026-06-08T07:40:00"),
        _det(source_name="Leadership", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping", title=_WIRE_TITLE, text=_WIRE_TEXT,
             published_at="2026-06-08T08:10:00"),
    ]
    # text_overlap on identical copies is ~1.0 and clears the republication bar.
    assert text_overlap(mirrors[0], mirrors[1]) >= DUP_JACCARD_TEXT
    # identical text -> identical fingerprint regardless of masthead.
    _fps = {content_fingerprint(m) for m in mirrors}
    assert len(_fps) == 1, "republished copies must share ONE fingerprint, got %d" % len(_fps)
    eff_wire = effective_source_count(mirrors)
    assert eff_wire == 1, "P1-03 FAIL: 4 wire copies counted as %d effective sources (want 1)" % eff_wire
    inc_wire = build_incidents(mirrors)
    assert len(inc_wire) == 1, "wire copies should form one incident, got %d" % len(inc_wire)
    assert inc_wire[0]["source_count"] == 1, \
        "P1-03 FAIL: source_count inflated to %d by republication (want 1)" % inc_wire[0]["source_count"]

    # Control: FOUR genuinely distinct independent reports of (different) events
    # — different outlets AND different wording — must STILL count as 4 sources.
    distinct = [
        _det(source_name="Punch", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping",
             title="Gunmen seize travellers near Birnin Gwari",
             text="Eyewitnesses say armed men blocked the road and seized passengers from two buses.",
             published_at="2026-06-08T07:00:00"),
        _det(source_name="Vanguard", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping",
             title="Police confirm Birnin Gwari abduction",
             text="A police spokesman confirmed an operation to rescue the captured commuters is ongoing.",
             published_at="2026-06-08T07:30:00"),
        _det(source_name="Channels", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping",
             title="Community leaders decry rising kidnappings",
             text="Local chiefs lamented frequent attacks and demanded more security checkpoints on the corridor.",
             published_at="2026-06-08T08:00:00"),
        _det(source_name="Sahara Reporters", location_name="Birnin Gwari", state="Kaduna",
             lat=11.05, lng=6.55, type="kidnapping",
             title="Families plead for help after relatives taken",
             text="Relatives of the missing pleaded for assistance, saying ransom demands had reached them.",
             published_at="2026-06-08T08:30:00"),
    ]
    # pairwise overlap of distinct reports stays below the republication bar.
    _max_ov = max(text_overlap(distinct[i], distinct[j])
                  for i in range(len(distinct)) for j in range(i + 1, len(distinct)))
    assert _max_ov < DUP_JACCARD_TEXT, "distinct reports must not look like republications (max overlap %.2f)" % _max_ov
    eff_distinct = effective_source_count(distinct)
    assert eff_distinct == 4, "distinct reports collapsed: %d effective sources (want 4)" % eff_distinct
    inc_distinct = build_incidents(distinct)
    assert inc_distinct[0]["source_count"] == 4, \
        "distinct independent reports must count separately, got source_count=%d" % inc_distinct[0]["source_count"]

    # ====================================================================
    # Entry point / return-shape guard (api.py & pipeline.py contract)
    # ====================================================================
    _shape = build_incidents([p_a])
    assert isinstance(_shape, list) and isinstance(_shape[0], dict)
    _required = {"type", "location_name", "state", "lat", "lng", "window_start",
                 "window_end", "source_count", "source_diversity", "severity",
                 "confidence", "status", "summary", "signal_ids"}
    assert _required <= set(_shape[0]), "return shape changed; missing %s" % (_required - set(_shape[0]))
    assert _shape[0]["status"] in ("needs_human_review", "corroborated", "candidate_unverified")
    assert _shape[0]["status"] != "verified", "must never auto-verify"

    print("corroborate.py self-test OK")
    print("  P2-06 adaptive radius : 2 same-LGA kidnapping points %.1f km apart "
          "(radius widened to %d km) -> 1 corroborated incident "
          "(source_count=%d)" % (_gap, _radius, incs[0]["source_count"]))
    print("  P2-06 control         : 2 armed_robberies in different cities "
          "(radius %d km) -> %d separate incidents" % (CLUSTER_KM_URBAN, 2))
    print("  P1-03 wire dedup      : 4 identical NAN republications "
          "-> effective_source_count=%d, incident source_count=%d "
          "(conf=%d)" % (eff_wire, inc_wire[0]["source_count"], inc_wire[0]["confidence"]))
    print("  P1-03 control         : 4 distinct independent reports "
          "-> effective_source_count=%d, incident source_count=%d "
          "(conf=%d)" % (eff_distinct, inc_distinct[0]["source_count"], inc_distinct[0]["confidence"]))
    print("  contract              : build_incidents -> list[dict], return keys "
          "intact, status never auto-'verified'")
