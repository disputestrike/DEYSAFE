"""Source/report reputation + coordinated-spam + data-poisoning defense.

This module is the single, auditable home for the *abuse-integrity* scoring that
the audit register calls out as ABU-03 (duplicate / coordinated spam), ABU-04
(historically-accurate sources weighted up; noisy/bad sources weighted down) and
ABU-11 (data poisoning / information warfare — gangs flood-verify, forces
flood-dismiss, rivals manipulate).

Design rules (mirror security.py / response.py):
  - STDLIB ONLY. No DB handle, no env reads, no network, no I/O. Every public
    function is pure/deterministic given its inputs. That makes the whole policy
    trivially unit-testable and safe to call from any request thread, and lets
    api.py / corroborate.py / db.py import it without side effects.
  - This module owns the *logic*; the db layer owns *persistence*. The one table
    we need (reporter_stats) is described here as plain DDL strings (one SQLite
    variant, one Postgres variant) so db.py can splice them into its dual-mode
    _migrate path exactly like response.RESPONSE_TABLES. Nothing here executes
    SQL; it only *describes* it.

BRIGHT LINES (FEEDBACK §B / §P — encoded here, not just documented):
  - Reputation may only DOWN-weight a suspect report or ROUTE it to a human
    (quarantine / needs_human_review). It can NEVER auto-promote, auto-verify,
    or auto-escalate anything. Volume alone never raises status — that is the
    exact data-poisoning failure mode (ABU-11). `should_quarantine()` and
    `is_coordinated()` therefore return "hold for a human", never "act".
  - Quarantine is reversible and advisory: it annotates, it does not delete.

What this module computes:
  1. A persisted-stats model for a reporter/source keyed by an opaque
     `reporter_key` (a hash of phone/owner/IP — never raw PII). Each outcome
     (an operator verify/dismiss of something the source reported) nudges a
     bounded reputation score. See ReporterStat + update_stat().
  2. score(report, stat) -> a per-report risk/trust read used to *weight*
     corroboration confidence (feeds corroborate.score) and to gate quarantine.
  3. is_coordinated(recent_reports) -> bool: a burst from the same caller/area
     with near-identical text (ABU-03 coordinated spam). Surfaces to the operator
     queue; never auto-escalates.
  4. should_quarantine(report, stat) -> bool: hold a single report for human
     review when it comes from a low-reputation source AND looks like part of a
     burst / poisoning pattern.
"""
import re
import math
import hashlib
import datetime


# ===========================================================================
# 0. Identity — opaque reporter key (never store raw PII)
# ===========================================================================
# A reporter is identified by whatever stable handle we have (phone, owner_token,
# device id) optionally salted with a coarse network signal (ip_hash). We never
# persist the raw value: reporter_key is a short sha256 hex so the reputation
# table holds no phone numbers / IPs (PRIV-01 / PRIV-02 reporter threat model).
def reporter_key(*parts):
    """Stable opaque key for a reporter from any identifying parts.

    Pass whatever you have (phone, owner_token, device id, ip hash). Falsy parts
    are ignored. Returns a 16-char sha256 hex prefix, or "anon" when nothing
    identifying is supplied (so anonymous traffic all shares one low-trust
    bucket rather than each looking like a brand-new pristine source).
    """
    vals = [str(p).strip().lower() for p in parts if p not in (None, "")]
    if not vals:
        return "anon"
    raw = "|".join(vals)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def key_of(report):
    """Best-effort reporter_key for a report/signal dict.

    Prefers an explicit reporter_key, then identifying handles, then falls back
    to the network/source signal. Mirrors the fields the api/db layer attaches to
    field reports (owner_token / client_id / ip_hash) and to ingested signals
    (source_name). Never reads raw PII out into the return value — only the hash.
    """
    if not isinstance(report, dict):
        return "anon"
    if report.get("reporter_key"):
        return str(report["reporter_key"])
    return reporter_key(
        report.get("owner_token"),
        report.get("phone"),
        report.get("device_id") or report.get("client_id"),
        report.get("ip_hash") or report.get("ip"),
        # source_name is the right identity for ingested news signals; for field
        # reports the handles above win, so this only bites for source traffic.
        report.get("source_name"),
    )


# ===========================================================================
# 1. Persisted reputation model (ABU-04) — pure data + pure updates
# ===========================================================================
# Reputation is a bounded score in [SCORE_MIN, SCORE_MAX] centered on
# SCORE_START. A verify (the source was right) nudges it up; a dismiss (the
# source was wrong / spam) nudges it down, weighted more heavily so a few bad
# reports cost more trust than they earn — abuse should be expensive.
SCORE_MIN = 0.0
SCORE_MAX = 100.0
SCORE_START = 50.0          # an unknown source starts neutral, NOT trusted
VERIFY_GAIN = 6.0           # reward for a confirmed-correct report
DISMISS_LOSS = 10.0         # penalty for a wrong/spam report (asymmetric)

# Trust bands derived from the score. Below LOW a source is "low reputation"
# (its reports get down-weighted and are quarantine-eligible); above HIGH it is
# "trusted" (its corroboration counts a little more). These are policy knobs in
# one place; nothing outside this module hard-codes the thresholds.
LOW_REP = 35.0
HIGH_REP = 70.0
# A source needs at least this many outcomes before HIGH_REP grants extra weight
# (so one lucky report can't mint a "trusted" source — blast-radius limit, ABU-05).
MIN_OUTCOMES_FOR_TRUST = 3


def new_stat(key):
    """A fresh neutral reputation record for `key` (dict, ready to persist)."""
    return {
        "reporter_key": key,
        "reports": 0,
        "verified": 0,
        "dismissed": 0,
        "score": SCORE_START,
        "updated_at": None,
    }


def _clamp(x, lo=SCORE_MIN, hi=SCORE_MAX):
    return max(lo, min(hi, x))


def update_stat(stat, outcome, now=None):
    """Return a NEW stat dict after applying one operator `outcome` to `stat`.

    `outcome` is "verified" (the reported event was real) or "dismissed" (it was
    false / spam). Any other value is treated as a neutral observation: it counts
    a report but does not move the score. Pure — does not mutate `stat`; the db
    layer persists the returned dict. `now` is injectable for deterministic tests.

    Asymmetric on purpose (DISMISS_LOSS > VERIFY_GAIN): trust is slow to earn and
    fast to lose, so flooding bad reports degrades a source quickly (ABU-04/11).
    """
    s = dict(stat) if stat else new_stat((stat or {}).get("reporter_key", "anon"))
    s["reports"] = int(s.get("reports", 0)) + 1
    score = float(s.get("score", SCORE_START))
    o = (outcome or "").strip().lower()
    if o in ("verified", "verify", "true", "confirmed"):
        s["verified"] = int(s.get("verified", 0)) + 1
        score = _clamp(score + VERIFY_GAIN)
    elif o in ("dismissed", "dismiss", "false", "rejected", "spam"):
        s["dismissed"] = int(s.get("dismissed", 0)) + 1
        score = _clamp(score - DISMISS_LOSS)
    # else: neutral observation — report counted, score unchanged.
    s["score"] = round(score, 3)
    s["updated_at"] = _iso(now)
    return s


def accuracy(stat):
    """Fraction of judged reports that were verified, in [0,1].

    Only counts reports an operator actually ruled on (verified+dismissed); an
    unjudged backlog neither helps nor hurts. Returns None when nothing has been
    judged yet (caller treats None as "no track record", distinct from 0.0).
    """
    if not stat:
        return None
    v = int(stat.get("verified", 0))
    d = int(stat.get("dismissed", 0))
    judged = v + d
    if judged <= 0:
        return None
    return v / float(judged)


def band(stat):
    """Coarse trust band for a stat: 'low' | 'neutral' | 'trusted'.

    'trusted' requires both a high score AND a minimum track record so a single
    lucky report can't unlock extra corroboration weight (ABU-05 blast radius).
    A missing/empty stat is 'neutral' (unknown), not 'low' — we don't punish a
    source merely for being new, only for being wrong.
    """
    if not stat:
        return "neutral"
    score = float(stat.get("score", SCORE_START))
    judged = int(stat.get("verified", 0)) + int(stat.get("dismissed", 0))
    if score <= LOW_REP and judged >= 1:
        return "low"
    if score >= HIGH_REP and judged >= MIN_OUTCOMES_FOR_TRUST:
        return "trusted"
    return "neutral"


def is_low_reputation(stat):
    """True if `stat` is in the 'low' trust band (down-weight + quarantine-eligible)."""
    return band(stat) == "low"


def corroboration_weight(stat):
    """Multiplier in [WEIGHT_MIN, WEIGHT_MAX] for how much this source's report
    should count toward corroboration confidence (feeds corroborate.score).

    Low-reputation sources count for less; trusted sources count for a little
    more; unknown/neutral sources count as exactly 1.0 (no free boost, no
    penalty). Bounded so reputation *tilts* confidence but can never dominate it —
    corroboration across independent sources stays the primary signal.
    """
    b = band(stat)
    if b == "low":
        return WEIGHT_MIN
    if b == "trusted":
        return WEIGHT_MAX
    return 1.0


WEIGHT_MIN = 0.4            # a low-rep source's report counts for <half
WEIGHT_MAX = 1.25          # a proven source's report counts for a bit more


# ===========================================================================
# 2. Per-report risk read (ABU-04 feed) — score(report, stat)
# ===========================================================================
def score(report, stat=None):
    """Per-report trust/risk read used to weight corroboration + gate quarantine.

    Returns a dict:
      {
        "reporter_key": <key>,
        "band": "low"|"neutral"|"trusted",
        "weight": <corroboration multiplier>,   # WEIGHT_MIN..WEIGHT_MAX
        "risk": <0..100>,                        # higher = more suspect
        "low_reputation": bool,
      }

    `risk` is the inverse of trust on a 0-100 scale (a low-rep source is high
    risk; a trusted source is low risk; unknown sits in the middle). It is a
    READ for operators/weighting only — it never by itself changes an incident's
    status (ABU-11: volume/risk alone must not move status).
    """
    key = key_of(report)
    if stat is None:
        stat = {"reporter_key": key}      # treated as no-track-record / neutral
    b = band(stat)
    w = corroboration_weight(stat)
    sc = float(stat.get("score", SCORE_START))
    risk = int(_clamp(100.0 - sc, 0, 100))
    return {
        "reporter_key": key,
        "band": b,
        "weight": w,
        "risk": risk,
        "low_reputation": (b == "low"),
    }


# ===========================================================================
# 3. Coordinated / burst spam detection (ABU-03)
# ===========================================================================
# A coordinated flood looks like: many reports, arriving close together, from a
# small number of callers/areas, carrying near-identical text. We detect that
# shape WITHOUT auto-acting on it — a hit annotates the incident so a human looks
# (it can equally be a real mass-casualty event with many genuine witnesses; the
# system must NOT assume malice and must NOT auto-escalate either way).

# Tunables (single source of truth for the burst policy).
BURST_WINDOW_MIN = 10        # "close together" = within this many minutes
BURST_MIN_REPORTS = 4        # need at least this many reports to call it a burst
# When this share (or more) of a burst comes from a single caller OR a single
# small area, treat it as coordinated rather than an independent crowd.
SAME_SOURCE_SHARE = 0.6
# Near-identical text: token Jaccard >= this (matches corroborate.DUP_JACCARD so
# the two modules agree on "same wording"). We keep our own copy to stay
# import-free / standalone like security.py and response.py.
TEXT_DUP_JACCARD = 0.6
SAME_TEXT_SHARE = 0.6        # share of a burst that must be near-identical text

# Coarse area bucketing for "same area": round lat/lng to ~11 km cells (2 dp).
_AREA_DP = 2

_TOKEN_RE = re.compile(r"[a-z0-9]+")
# Boilerplate/stop tokens that carry no event identity (kept in sync with the
# spirit of corroborate._STOP so unrelated reports don't look near-identical).
_STOP = frozenset((
    "the", "a", "an", "of", "in", "on", "at", "to", "for", "and", "near",
    "around", "along", "said", "reported", "reportedly", "report", "residents",
    "people", "after", "were", "was", "has", "have", "had", "into", "from",
    "with", "by", "are", "is", "as", "that", "this", "some", "help", "now",
    "please", "there", "here", "happening", "sos", "urgent",
))


def _iso(now=None):
    return (now or datetime.datetime.now()).isoformat(timespec="seconds")


def _parse(ts):
    """Best-effort parse of an ISO-ish timestamp to a naive datetime, or None."""
    if not ts:
        return None
    if isinstance(ts, datetime.datetime):
        return ts
    s = str(ts).strip()
    if s.endswith("Z"):
        s = s[:-1]
    if "T" not in s and " " in s:
        s = s.replace(" ", "T", 1)
    try:
        return datetime.datetime.fromisoformat(s)
    except Exception:
        try:
            return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None


def _tokens(report):
    """Identity tokens for a report's text (title+text+message), stop-words out."""
    text = " ".join(str(report.get(f, "") or "") for f in ("title", "text", "message"))
    return frozenset(t for t in _TOKEN_RE.findall(text.lower())
                     if t not in _STOP and len(t) > 1)


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if not inter:
        return 0.0
    return inter / len(a | b)


def _area_cell(report):
    """Coarse area bucket key for a report (rounded lat/lng), or None if no coords."""
    lat, lng = report.get("lat"), report.get("lng")
    if lat is None or lng is None:
        return None
    try:
        return (round(float(lat), _AREA_DP), round(float(lng), _AREA_DP))
    except (TypeError, ValueError):
        return None


def _time_span_minutes(reports):
    """Minutes between the earliest and latest parseable timestamp (0 if <2)."""
    times = [t for t in (_parse(r.get("published_at") or r.get("created_at"))
                         for r in reports) if t is not None]
    if len(times) < 2:
        return 0.0
    return (max(times) - min(times)).total_seconds() / 60.0


def _max_share(reports, key_fn):
    """Largest share [0,1] of `reports` that collapse to one non-None key_fn value."""
    if not reports:
        return 0.0
    counts = {}
    considered = 0
    for r in reports:
        k = key_fn(r)
        if k is None:
            continue
        considered += 1
        counts[k] = counts.get(k, 0) + 1
    if considered == 0:
        return 0.0
    return max(counts.values()) / float(considered)


def _near_identical_share(reports):
    """Share [0,1] of `reports` that fall into the single largest near-identical
    text cluster (token Jaccard >= TEXT_DUP_JACCARD)."""
    toks = [_tokens(r) for r in reports]
    toks = [t for t in toks if t]
    n = len(toks)
    if n < 2:
        return 0.0
    best = 1
    # Greedy single-link clustering on Jaccard; n is small (a burst), O(n^2) ok.
    used = [False] * n
    for i in range(n):
        if used[i]:
            continue
        members = [i]
        for j in range(i + 1, n):
            if used[j]:
                continue
            if _jaccard(toks[i], toks[j]) >= TEXT_DUP_JACCARD:
                members.append(j)
                used[j] = True
        used[i] = True
        if len(members) > best:
            best = len(members)
    return best / float(n)


def coordination_signals(reports):
    """Structural read of a set of recent reports (already scoped to one event/
    area/type by the caller). Returns a dict of the burst signals WITHOUT any
    verdict-acting:

      {
        "count": int,
        "span_minutes": float,
        "same_caller_share": float,   # 0..1
        "same_area_share": float,     # 0..1
        "same_text_share": float,     # 0..1
        "burst": bool,                # count+window threshold met
        "coordinated": bool,          # burst AND concentrated by caller/area/text
      }

    `coordinated=True` is a *flag for a human* (annotate the operator queue), not
    a trigger. A genuine mass event with many independent witnesses can trip the
    count/window but should NOT trip the concentration shares; that's the whole
    point of separating `burst` from `coordinated`.
    """
    reps = list(reports or [])
    count = len(reps)
    span = _time_span_minutes(reps)
    same_caller = _max_share(reps, key_of)
    same_area = _max_share(reps, _area_cell)
    same_text = _near_identical_share(reps)

    # A burst is a volume spike in a short window. With <2 timestamps span is 0,
    # which still counts as "tightly bunched" once the count threshold is met.
    burst = count >= BURST_MIN_REPORTS and span <= BURST_WINDOW_MIN
    coordinated = burst and (
        same_caller >= SAME_SOURCE_SHARE
        or same_area >= SAME_SOURCE_SHARE
        or same_text >= SAME_TEXT_SHARE
    )
    return {
        "count": count,
        "span_minutes": round(span, 3),
        "same_caller_share": round(same_caller, 3),
        "same_area_share": round(same_area, 3),
        "same_text_share": round(same_text, 3),
        "burst": burst,
        "coordinated": coordinated,
    }


def is_coordinated(recent_reports):
    """True if `recent_reports` look like coordinated spam (ABU-03).

    Thin boolean wrapper over coordination_signals()['coordinated']. Use the full
    coordination_signals() when you want to surface the *why* on the operator
    queue. Bright line: a True here means "hold/flag for a human", never
    "escalate" — volume must not raise status by itself.
    """
    return coordination_signals(recent_reports)["coordinated"]


# ===========================================================================
# 4. Quarantine gate (ABU-11 data poisoning) — should_quarantine
# ===========================================================================
def should_quarantine(report, stat=None, recent_reports=None):
    """True if a single `report` should be HELD for human review before it can
    influence anything (status, zone change, alert).

    Quarantine fires when the report is suspect on BOTH axes at once:
      - the source is low-reputation (proven wrong/spam before), AND
      - it arrives inside a coordinated burst (ABU-03 shape).
    Either signal alone is not enough: a new low-rep source making one isolated
    report is merely down-weighted (not quarantined), and a big genuine crowd of
    unknown-but-not-bad witnesses is flagged `coordinated` for a human but its
    individual reports aren't quarantined. Requiring both keeps quarantine narrow
    so it routes real poisoning attempts to a human without silencing legitimate
    mass reporting.

    `recent_reports` is the set of reports the caller considers contemporaneous
    with `report` (same event/area window). When omitted, only the reputation
    axis is considered, so an isolated low-rep report is NOT quarantined.

    BRIGHT LINE: quarantine is advisory + reversible — it marks `needs_human_
    review`, it never deletes, auto-verifies, or auto-escalates.
    """
    low_rep = is_low_reputation(stat)
    if recent_reports is None:
        return False
    coordinated = is_coordinated(recent_reports)
    return bool(low_rep and coordinated)


def quarantine_reason(report, stat=None, recent_reports=None):
    """Human-readable reason string when should_quarantine() is True, else ""."""
    if not should_quarantine(report, stat, recent_reports):
        return ""
    sig = coordination_signals(recent_reports or [])
    return ("low-reputation source in a coordinated burst "
            "(n=%d, span=%.0fmin, caller=%.0f%%, area=%.0f%%, text=%.0f%%) "
            "— held for human review" % (
                sig["count"], sig["span_minutes"],
                100 * sig["same_caller_share"], 100 * sig["same_area_share"],
                100 * sig["same_text_share"]))


# ===========================================================================
# 5. DDL  (db.py splices these into its dual-mode schema + _migrate path)
# ===========================================================================
# One table: reporter_stats, keyed by the opaque reporter_key (PRIMARY KEY so
# upserts are a single row per source). Two flavours, matching response.py's
# convention (SQLite AUTOINCREMENT-style vs Postgres). reporter_key is the PK in
# BOTH so there is exactly one reputation row per source. Score is stored as a
# REAL/DOUBLE; counts as INTEGER; updated_at as TEXT ISO (matches the rest of the
# schema). NO raw PII column exists by design (PRIV-01/02): only the hash.
REPORTER_STATS_SQLITE = """
CREATE TABLE IF NOT EXISTS reporter_stats (
  reporter_key TEXT PRIMARY KEY,
  reports INTEGER DEFAULT 0,
  verified INTEGER DEFAULT 0,
  dismissed INTEGER DEFAULT 0,
  score REAL DEFAULT 50.0,
  updated_at TEXT
);
"""

REPORTER_STATS_PG = """
CREATE TABLE IF NOT EXISTS reporter_stats (
  reporter_key TEXT PRIMARY KEY,
  reports INTEGER DEFAULT 0,
  verified INTEGER DEFAULT 0,
  dismissed INTEGER DEFAULT 0,
  score DOUBLE PRECISION DEFAULT 50.0,
  updated_at TEXT
);
"""

# Convenience bundles mirroring response.RESPONSE_TABLES so db.py can iterate.
DDL_SQLITE = (REPORTER_STATS_SQLITE,)
DDL_PG = (REPORTER_STATS_PG,)
REPUTATION_TABLES = {
    "reporter_stats": (REPORTER_STATS_SQLITE, REPORTER_STATS_PG),
}


# ===========================================================================
# 6. SELF-TEST  (python engine/reputation.py)
# ===========================================================================
if __name__ == "__main__":
    NOW = datetime.datetime(2026, 6, 4, 12, 0, 0)

    # --- reporter_key: opaque, stable, PII-free ----------------------------
    k1 = reporter_key("+2348012345678")
    k2 = reporter_key("+2348012345678")
    assert k1 == k2 and len(k1) == 16, "key must be stable + short hex"
    assert "+234" not in k1, "key must not leak the raw phone"
    assert reporter_key() == "anon" and reporter_key(None, "") == "anon"
    # order/identity: different inputs -> different keys
    assert reporter_key("a") != reporter_key("b")
    # key_of pulls the right field and never returns raw PII
    r = {"owner_token": "tok-XYZ", "title": "x"}
    assert key_of(r) == reporter_key("tok-xyz")
    assert key_of({"reporter_key": "preset"}) == "preset"
    assert key_of({}) == "anon" and key_of("notadict") == "anon"
    assert "tok-XYZ" not in key_of(r)

    # --- reputation model: asymmetric, bounded, neutral start --------------
    s = new_stat(k1)
    assert s["score"] == SCORE_START and s["reports"] == 0
    assert accuracy(s) is None, "no judged reports yet -> None, not 0"
    assert band(s) == "neutral", "unknown source is neutral, not low"

    # a verify nudges up, a dismiss nudges down harder (abuse is expensive)
    up = update_stat(s, "verified", now=NOW)
    assert up["score"] == round(SCORE_START + VERIFY_GAIN, 3)
    assert up["verified"] == 1 and up["reports"] == 1 and up["updated_at"]
    down = update_stat(s, "dismissed", now=NOW)
    assert down["score"] == round(SCORE_START - DISMISS_LOSS, 3)
    assert (SCORE_START - down["score"]) > (up["score"] - SCORE_START), "asymmetric"
    # purity: original stat untouched
    assert s["score"] == SCORE_START and s["reports"] == 0
    # neutral/unknown outcome counts a report but doesn't move the score
    neu = update_stat(s, "ignored", now=NOW)
    assert neu["reports"] == 1 and neu["score"] == SCORE_START
    assert neu["verified"] == 0 and neu["dismissed"] == 0

    # clamping: score never leaves [SCORE_MIN, SCORE_MAX]
    bad = new_stat("flooder")
    for _ in range(20):
        bad = update_stat(bad, "dismissed", now=NOW)
    assert bad["score"] == SCORE_MIN, bad["score"]
    assert is_low_reputation(bad) is True and band(bad) == "low"
    assert accuracy(bad) == 0.0, "all dismissed -> 0.0 accuracy (not None)"
    good = new_stat("trusty")
    for _ in range(20):
        good = update_stat(good, "verified", now=NOW)
    assert good["score"] == SCORE_MAX
    assert band(good) == "trusted" and accuracy(good) == 1.0

    # --- trust band guards (ABU-05 blast radius) ---------------------------
    # one lucky verify is NOT enough to become "trusted"
    lucky = update_stat(new_stat("lucky"), "verified", now=NOW)
    assert band(lucky) == "neutral", "needs a track record to be trusted"
    # corroboration weights track the band and stay bounded
    assert corroboration_weight(bad) == WEIGHT_MIN
    assert corroboration_weight(good) == WEIGHT_MAX
    assert corroboration_weight(new_stat("x")) == 1.0
    assert WEIGHT_MIN < 1.0 < WEIGHT_MAX

    # --- per-report score read --------------------------------------------
    rd = score({"owner_token": "trusty"}, good)
    assert rd["band"] == "trusted" and rd["weight"] == WEIGHT_MAX
    assert rd["risk"] == 0 and rd["low_reputation"] is False
    rd2 = score({"owner_token": "flooder"}, bad)
    assert rd2["risk"] == 100 and rd2["low_reputation"] is True
    # no stat supplied -> neutral read, never crashes
    rd3 = score({"owner_token": "newbie"})
    assert rd3["band"] == "neutral" and rd3["weight"] == 1.0 and 0 <= rd3["risk"] <= 100

    # --- coordinated / burst detection (ABU-03) ---------------------------
    def rep(key, mins, text, lat=10.5, lng=7.4):
        return {"owner_token": key, "title": text,
                "published_at": (NOW + datetime.timedelta(minutes=mins)).isoformat(),
                "lat": lat, "lng": lng}

    # 5 near-identical reports from ONE caller within a few minutes => coordinated
    flood = [rep("same-caller", i, "they took the children near the market road") for i in range(5)]
    sig = coordination_signals(flood)
    assert sig["count"] == 5 and sig["burst"] is True
    assert sig["same_caller_share"] == 1.0 and sig["same_text_share"] == 1.0
    assert sig["coordinated"] is True
    assert is_coordinated(flood) is True

    # a genuine crowd: many DISTINCT callers, DISTINCT wording, spread in area,
    # still within the window -> a burst but NOT coordinated (must not be flagged
    # as spam; it's real mass reporting that a human should see)
    crowd = [
        {"owner_token": "w%d" % i, "title": t,
         "published_at": (NOW + datetime.timedelta(minutes=i % 5)).isoformat(),
         "lat": 10.5 + i * 0.05, "lng": 7.4 + i * 0.05}
        for i, t in enumerate([
            "gunmen attacked the village this morning",
            "I heard shooting close to the school gate",
            "people running from the market, danger",
            "armed men on motorcycles near the river",
            "my neighbour saw the attackers flee north",
        ])
    ]
    csig = coordination_signals(crowd)
    assert csig["burst"] is True, csig
    assert csig["same_caller_share"] < SAME_SOURCE_SHARE, csig
    assert csig["coordinated"] is False, "real distinct crowd must NOT be coordinated"
    assert is_coordinated(crowd) is False

    # below the count threshold is never a burst, even if identical
    tiny = [rep("c", 0, "same text"), rep("c", 1, "same text")]
    assert coordination_signals(tiny)["burst"] is False
    assert is_coordinated(tiny) is False
    # empty / single input is safe
    assert is_coordinated([]) is False and is_coordinated(None) is False
    assert coordination_signals([])["count"] == 0

    # same wording but spread OVER HOURS (outside the window) is not a burst
    slow = [rep("a%d" % i, i * 60, "they took the children near the market road")
            for i in range(5)]
    assert coordination_signals(slow)["burst"] is False

    # same AREA from many distinct callers with identical text -> coordinated via
    # the area/text axis even though no single caller dominates
    area_flood = [
        {"owner_token": "diff-%d" % i, "title": "kidnap kidnap kidnap at the same spot",
         "published_at": (NOW + datetime.timedelta(minutes=i)).isoformat(),
         "lat": 10.500, "lng": 7.400}
        for i in range(6)
    ]
    asig = coordination_signals(area_flood)
    assert asig["same_area_share"] == 1.0 and asig["coordinated"] is True

    # --- quarantine gate (ABU-11): needs BOTH low-rep AND coordinated ------
    # low-rep source caught inside a coordinated flood -> quarantine (hold)
    assert should_quarantine({"owner_token": "flooder"}, bad, flood) is True
    assert quarantine_reason({"owner_token": "flooder"}, bad, flood) != ""
    # same low-rep source but NO burst context -> not quarantined, only down-weighted
    assert should_quarantine({"owner_token": "flooder"}, bad, None) is False
    assert should_quarantine({"owner_token": "flooder"}, bad, [flood[0]]) is False
    # coordinated burst but from a GOOD/neutral source -> not quarantined
    assert should_quarantine({"owner_token": "trusty"}, good, flood) is False
    assert should_quarantine({"owner_token": "newbie"}, None, flood) is False
    # reason is empty exactly when not quarantined
    assert quarantine_reason({"owner_token": "trusty"}, good, flood) == ""

    # --- BRIGHT LINE: nothing here can auto-promote/escalate ---------------
    # The public surface only ever returns down-weights (<=WEIGHT_MAX), risk
    # reads (0..100), and hold-for-human booleans/dicts — never an action verb,
    # a status, or a state transition. Assert the *return contracts* hold rather
    # than scanning prose (the docstrings legitimately say the words we forbid).
    assert isinstance(is_coordinated(flood), bool)
    assert isinstance(should_quarantine({"owner_token": "flooder"}, bad, flood), bool)
    assert set(score({"owner_token": "x"}, good)) == {
        "reporter_key", "band", "weight", "risk", "low_reputation"}
    # bands/weights can only TILT confidence, never set/raise a status: the worst
    # a source can do to corroboration is be worth WEIGHT_MAX, the least WEIGHT_MIN.
    assert all(corroboration_weight(s2) <= WEIGHT_MAX
               for s2 in (bad, good, lucky, new_stat("z"), None))
    assert all(corroboration_weight(s2) >= WEIGHT_MIN
               for s2 in (bad, good, lucky, new_stat("z"), None))
    # weights are bounded so reputation can tilt but never dominate confidence
    assert 0 < WEIGHT_MIN < 1 < WEIGHT_MAX <= 2

    # --- DDL sanity + it actually executes on a real SQLite connection -----
    for ddl in DDL_SQLITE:
        assert "CREATE TABLE IF NOT EXISTS" in ddl and "reporter_key TEXT PRIMARY KEY" in ddl
    for ddl in DDL_PG:
        assert "CREATE TABLE IF NOT EXISTS" in ddl and "DOUBLE PRECISION" in ddl
    assert set(REPUTATION_TABLES) == {"reporter_stats"}
    assert len(DDL_SQLITE) == len(DDL_PG) == 1

    import sqlite3 as _sqlite3
    _c = _sqlite3.connect(":memory:")
    for ddl in DDL_SQLITE:
        _c.executescript(ddl)
    # round-trip a stat row through the live schema (upsert-by-PK)
    st = update_stat(new_stat(k1), "verified", now=NOW)
    _c.execute(
        "INSERT INTO reporter_stats (reporter_key, reports, verified, dismissed, score, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        (st["reporter_key"], st["reports"], st["verified"], st["dismissed"],
         st["score"], st["updated_at"]))
    row = _c.execute(
        "SELECT reporter_key, verified, score FROM reporter_stats WHERE reporter_key=?",
        (k1,)).fetchone()
    assert row[0] == k1 and row[1] == 1 and abs(row[2] - (SCORE_START + VERIFY_GAIN)) < 1e-6
    # PRIMARY KEY really is unique (second raw insert of same key must fail)
    try:
        _c.execute("INSERT INTO reporter_stats (reporter_key) VALUES (?)", (k1,))
        raise AssertionError("reporter_key should be a unique PRIMARY KEY")
    except _sqlite3.IntegrityError:
        pass
    _c.close()

    print("reputation.py self-test OK")
