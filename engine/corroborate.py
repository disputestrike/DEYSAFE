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

WINDOW_HOURS = 72
CLUSTER_KM = 30

# DATA-07: a member at the far edge of the window still counts, but at this
# fraction of a fresh report. Linear decay between 1.0 (age 0) and the floor.
DECAY_FLOOR = 0.35

# DATA-08: two member texts with Jaccard token overlap >= this are treated as
# the same eyewitness account / syndicated copy (one source, not many).
DUP_JACCARD = 0.6

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


def cluster(detections):
    clusters = []
    for d in detections:
        placed = False
        for c in clusters:
            if c["type"] != d["type"]:
                continue
            if _haversine((c["lat"], c["lng"]), (d["lat"], d["lng"])) > CLUSTER_KM:
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


def dedup_members(members):
    """Group members that describe the SAME event (near-duplicate wording or a
    syndicated reprint) into one report. Returns a list of groups; each group is
    a list of the original member dicts. One real-world event => one group =>
    counts as one corroborating account regardless of how many copies exist.
    """
    groups = []          # list of {"members": [...], "tokens": frozenset}
    for m in members:
        tk = _tokens(m)
        placed = False
        for g in groups:
            same_outlet = any(outlet_of(x.get("source_name")) == outlet_of(m.get("source_name")) for x in g["members"])
            # Same outlet repeating itself is always a dup; cross-outlet copies
            # are dups only when the wording overlaps strongly (syndication).
            if same_outlet or _jaccard(tk, g["tokens"]) >= DUP_JACCARD:
                g["members"].append(m)
                g["tokens"] = g["tokens"] | tk
                placed = True
                break
        if not placed:
            groups.append({"members": [m], "tokens": tk})
    return [g["members"] for g in groups]


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

    # DATA-08 then DATA-06: collapse near-duplicate accounts, then count how
    # many *distinct outlets/owners* remain. This is the independent-source
    # signal that drives status; it can only be <= the raw member count.
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
