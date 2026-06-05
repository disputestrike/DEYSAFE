"""Life-saving metrics for DeySafe / SHIELD (MET-01).

This module answers one question the audit register (FEEDBACK §P / MET-01) says
the system was never measuring: *are verified emergencies actually getting an
acknowledged human response in time?* It turns the raw tables into the funnel the
operating model is judged on — signal -> review -> warn -> deliver -> acknowledge
-> resolve — plus the North-Star count of verified emergencies with an
acknowledged human response.

Design rules (mirror security.py / response.py / reputation.py):
  - STDLIB ONLY. No env reads, no network, no writes. compute(db) is a PURE READ:
    it issues SELECTs through the db's backend-neutral helpers and never mutates a
    row, so it is safe to call from any request thread and from a read-only/
    operator-gated endpoint (GET /api/metrics).
  - BEST-EFFORT / DEGRADE-CLEANLY. Several inputs (sos_events, responder_tasks,
    deliveries, and the alert-lifecycle columns) are created by the response-loop
    migration and may be absent on an older DB or a partial deploy. Every read is
    guarded: a missing table/column yields None for that metric, never an
    exception. A caller therefore always gets a complete dict; `null` means "no
    data / not wired yet", which is distinct from 0 ("wired, but none yet").
  - NO BRIGHT-LINE SURFACE. Metrics only *count* what already happened. Nothing
    here verifies, escalates, dispatches, or writes.

The headline contract (keys always present; value is a number or None):
    signal_to_review_min   median minutes from a signal landing to it being ruled
                           on by an operator (signal.ingested_at -> decision.ts)
    review_to_alert_min    median minutes from the operator decision to the public
                           alert firing (decision.ts -> alert.created_at)
    alerts_active          alerts still live by lifecycle+TTL (response.alert_is_active)
    false_positive_rate    dismissed / (verified + dismissed), latest ruling per
                           incident — the share of human rulings that were "not real"
    sos_open               SOS events not in a terminal state (still needing a human)
    responder_ack_rate     responder tasks acknowledged / total (ack ladder moved
                           past 'received', or an ack_at stamp is present)
    cases_open             missing-person cases still active
    cases_resolved         missing-person cases located/recovered
    deliveries             total broadcast/SOS delivery receipts recorded

It also returns a `detail` block with the supporting counts (so the figures above
are auditable, not magic) and a `north_star` block (verified emergencies with an
acknowledged human response within SLA). Read the self-test at the bottom for the
exact shape.
"""
import datetime

try:  # timestamp parsing + alert liveness live in response.py; reuse, don't fork.
    import response
except Exception:  # pragma: no cover - keep metrics importable on its own
    response = None


# ---------------------------------------------------------------------------
# 0. Tunables
# ---------------------------------------------------------------------------
# Responder-ack SLA target (minutes). A task acknowledged within this window
# counts toward the North-Star "acknowledged human response within SLA". Kept
# here so the one policy number is auditable in one place. This is a *measurement*
# threshold only — it never gates or triggers anything.
ACK_SLA_MIN = 30


# ---------------------------------------------------------------------------
# 1. Safe read + small math helpers (the whole module's robustness lives here)
# ---------------------------------------------------------------------------
def _all_safe(db, sql, params=()):
    """db._all(sql) but never raises: a missing table/column -> [].

    This is what lets compute() run against a DB that hasn't had the response-loop
    tables spliced in yet. We swallow ANY exception (OperationalError, etc.) and
    treat the dataset as empty/unavailable.
    """
    try:
        return db._all(sql, params)
    except Exception:
        return []


def _one_safe(db, sql, params=()):
    """db._one(sql) but never raises: a missing table/column -> None."""
    try:
        return db._one(sql, params)
    except Exception:
        return None


def _count(db, table, where="", params=()):
    """COUNT(*) of `table` (optionally filtered). Missing table -> None.

    None is deliberately distinct from 0: None == "table not present / not wired",
    0 == "table present, zero matching rows".
    """
    sql = "SELECT COUNT(*) AS c FROM %s" % table
    if where:
        sql += " WHERE " + where
    try:
        row = db._one(sql, params)
    except Exception:
        return None
    if not row:
        return 0
    c = row.get("c")
    return int(c) if c is not None else 0


def _parse(ts):
    """Parse an ISO timestamp to a naive datetime (or None). Delegates to
    response._parse_iso when available; falls back to a local parser otherwise so
    the module still works if response.py is missing."""
    if response is not None:
        return response._parse_iso(ts)
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


def _minutes_between(a, b):
    """Whole-ish minutes from timestamp `a` to `b` (both ISO/datetime).

    Returns a float >= 0, or None if either is missing/unparseable or b precedes
    a (a negative gap means our two events are out of order -> not a meaningful
    latency sample, so we drop it rather than report a negative duration).
    """
    da, dbt = _parse(a), _parse(b)
    if da is None or dbt is None:
        return None
    delta = (dbt - da).total_seconds() / 60.0
    if delta < 0:
        return None
    return delta


def _median(values):
    """Median of a list of numbers, or None for an empty/all-None list.

    Medians (not means) so one freak outlier — a signal someone reviewed a week
    late — doesn't blow up the headline latency. None-safe: Nones are filtered.
    """
    nums = sorted(v for v in (values or []) if v is not None)
    n = len(nums)
    if n == 0:
        return None
    mid = n // 2
    if n % 2:
        return float(nums[mid])
    return (nums[mid - 1] + nums[mid]) / 2.0


def _rate(numerator, denominator):
    """numerator/denominator as a float in [0,1], or None when denominator is 0
    or either side is None (no sample yet -> 'unknown', not 0.0)."""
    if numerator is None or denominator is None:
        return None
    if denominator <= 0:
        return None
    return numerator / float(denominator)


# ---------------------------------------------------------------------------
# 2. Funnel sections (each is best-effort and returns plain numbers/None)
# ---------------------------------------------------------------------------
def _decision_rows(db):
    """Latest ruling per incident as a list of {incident_uuid, decision, ts}.

    Prefers the public db.decisions() (latest-per-uuid, the live view used
    everywhere else). Falls back to a guarded raw read if that surface isn't
    present. Rows with no incident_uuid (decisions logged against a display key
    with no live incident) are kept for FP counting but won't join to an alert.
    """
    try:
        live = db.decisions()  # {incident_uuid: latest row}
        rows = list(live.values())
        if rows:
            return rows
    except Exception:
        pass
    # Fallback: reduce the append-only log to the latest row per uuid ourselves.
    log = _all_safe(db, "SELECT incident_uuid, decision, ts FROM decisions ORDER BY id ASC")
    latest = {}
    for r in log:
        u = r.get("incident_uuid")
        if u:
            latest[u] = r
    return list(latest.values())


def _false_positive(db):
    """{verified, dismissed, total_ruled, rate}.

    rate = dismissed / (verified + dismissed) over the LATEST ruling per incident
    — i.e. of the events a human actually adjudicated, how many turned out not to
    be real. None rate when nothing has been ruled yet.
    """
    rows = _decision_rows(db)
    verified = sum(1 for r in rows if (r.get("decision") == "verified"))
    dismissed = sum(1 for r in rows if (r.get("decision") == "dismissed"))
    total = verified + dismissed
    return {
        "verified": verified,
        "dismissed": dismissed,
        "total_ruled": total,
        "rate": _rate(dismissed, total),
    }


def _signal_to_review_min(db):
    """Median minutes signal.ingested_at -> the decision that ruled its incident.

    We join signals -> incident_signals -> incidents -> latest decision, and take
    the gap from when each *contributing signal* was ingested to when its incident
    was ruled on. Best-effort: any missing piece just yields fewer/zero samples.
    """
    dec = {r.get("incident_uuid"): r for r in _decision_rows(db) if r.get("incident_uuid")}
    if not dec:
        return None
    # signal ingest time + the incident_uuid it rolls up to.
    rows = _all_safe(
        db,
        "SELECT s.ingested_at AS ingested_at, i.incident_uuid AS u "
        "FROM signals s "
        "JOIN incident_signals isig ON isig.signal_id = s.id "
        "JOIN incidents i ON i.id = isig.incident_id")
    samples = []
    for r in rows:
        d = dec.get(r.get("u"))
        if not d:
            continue
        m = _minutes_between(r.get("ingested_at"), d.get("ts"))
        if m is not None:
            samples.append(m)
    return _median(samples)


def _review_to_alert_min(db):
    """Median minutes from the operator decision to the public alert firing.

    Joins the latest verified decision per incident to the alert keyed on that
    same immutable incident_uuid (alerts.incident_key == incident_uuid). Only
    'verified' rulings can produce an alert, so dismissed rows contribute nothing.
    """
    dec = {r.get("incident_uuid"): r for r in _decision_rows(db)
           if r.get("incident_uuid") and r.get("decision") == "verified"}
    if not dec:
        return None
    alerts = _all_safe(db, "SELECT incident_key, created_at FROM alerts")
    samples = []
    for a in alerts:
        d = dec.get(a.get("incident_key"))
        if not d:
            continue
        m = _minutes_between(d.get("ts"), a.get("created_at"))
        if m is not None:
            samples.append(m)
    return _median(samples)


def _alerts_active(db):
    """Count of alerts still LIVE (lifecycle state live AND within TTL).

    Uses response.alert_is_active when the lifecycle columns + helper are present;
    otherwise falls back to the legacy status='active' count so the figure still
    means *something* on a pre-lifecycle DB. None only if the alerts table itself
    is unreadable.
    """
    rows = _all_safe(db, "SELECT * FROM alerts")
    if rows is None:
        return None
    # Detect whether the lifecycle columns are actually populated on these rows.
    have_lifecycle = response is not None and any(
        ("state" in r and r.get("state")) for r in rows)
    if have_lifecycle:
        live = 0
        for r in rows:
            ttl = None
            if hasattr(response, "ttl_for_level"):
                ttl = response.ttl_for_level(r.get("level_label"))
            # Prefer an explicit expires_at if present by comparing against now via
            # the lifecycle helper's TTL path; alert_is_active takes (state, created_at, ttl).
            if response.alert_is_active(r.get("state"), r.get("created_at"), ttl):
                live += 1
        return live
    # Legacy fallback: the old active/resolved flag.
    return sum(1 for r in rows if r.get("status") == "active")


# --- SOS ---------------------------------------------------------------------
def _sos(db):
    """{total, open, safe, closed}. Open = not in a terminal SOS state.

    Terminal set comes from response.SOS_TERMINAL (SAFE/CLOSED); if response is
    unavailable we fall back to the literal terminal strings. Counts are None when
    the sos_events table isn't present.
    """
    total = _count(db, "sos_events")
    if total is None:
        return {"total": None, "open": None, "safe": None, "closed": None}
    rows = _all_safe(db, "SELECT state FROM sos_events")
    terminal = set()
    if response is not None and hasattr(response, "SOS_TERMINAL"):
        terminal = set(response.SOS_TERMINAL)
    if not terminal:
        terminal = {"SAFE", "CLOSED"}
    safe = sum(1 for r in rows if r.get("state") == (
        response.SOS_SAFE if response is not None else "SAFE"))
    closed = sum(1 for r in rows if r.get("state") == (
        response.SOS_CLOSED if response is not None else "CLOSED"))
    open_ = sum(1 for r in rows if r.get("state") not in terminal)
    return {"total": total, "open": open_, "safe": safe, "closed": closed}


# --- responder tasks ---------------------------------------------------------
def _responder(db):
    """{total, acknowledged, ack_rate, within_sla, sla_rate}.

    A task is 'acknowledged' if it carries an ack_at timestamp OR its state has
    moved past the initial 'received' (the ack ladder advanced). within_sla counts
    acknowledged tasks whose created_at -> ack_at gap is <= ACK_SLA_MIN. All None
    when responder_tasks isn't present.
    """
    total = _count(db, "responder_tasks")
    if total is None:
        return {"total": None, "acknowledged": None, "ack_rate": None,
                "within_sla": None, "sla_rate": None}
    rows = _all_safe(db, "SELECT state, created_at, ack_at FROM responder_tasks")
    initial = response.TASK_INITIAL if (response is not None and hasattr(response, "TASK_INITIAL")) else "received"
    acked = 0
    within = 0
    for r in rows:
        has_ack_ts = bool(r.get("ack_at"))
        moved = r.get("state") not in (None, "", initial)
        if has_ack_ts or moved:
            acked += 1
            if has_ack_ts:
                m = _minutes_between(r.get("created_at"), r.get("ack_at"))
                if m is not None and m <= ACK_SLA_MIN:
                    within += 1
    return {
        "total": total,
        "acknowledged": acked,
        "ack_rate": _rate(acked, total),
        "within_sla": within,
        "sla_rate": _rate(within, total),
    }


# --- missing-person cases ----------------------------------------------------
def _cases(db):
    """{open, resolved}. open = status 'active'; resolved = located/recovered.

    None when the missing table is unreadable (it is part of the base schema, so
    in practice these are concrete numbers).
    """
    open_ = _count(db, "missing", "status = ?", ("active",))
    resolved = _count(db, "missing", "status IN ('located','recovered')")
    return {"open": open_, "resolved": resolved}


# --- deliveries --------------------------------------------------------------
def _deliveries(db):
    """{total, real, sim}. Distinguishes SIM-mode receipts from real sends so a
    simulated delivery is never counted as a real one (mirrors broadcast.py)."""
    total = _count(db, "deliveries")
    if total is None:
        return {"total": None, "real": None, "sim": None}
    sim = _count(db, "deliveries", "sim = 1")
    sim = sim or 0
    return {"total": total, "real": total - sim, "sim": sim}


def _north_star(db, fp, resp):
    """North-Star: verified emergencies with an acknowledged human response.

    `verified_emergencies` = count of incidents whose latest ruling is 'verified'.
    `acknowledged` reuses the responder ack count (a human picked the task up).
    `within_sla_rate` reuses the responder SLA rate. This is intentionally a
    *composed* read of figures already computed above — one obvious headline, no
    new query surface to audit.
    """
    return {
        "verified_emergencies": (fp.get("verified") if fp else None),
        "acknowledged_responses": (resp.get("acknowledged") if resp else None),
        "within_sla_rate": (resp.get("sla_rate") if resp else None),
        "ack_sla_min": ACK_SLA_MIN,
    }


# ---------------------------------------------------------------------------
# 3. Public entry point
# ---------------------------------------------------------------------------
def compute(db):
    """Compute the life-saving metric set from `db` (a db.DB). Pure read.

    Returns a dict with the headline keys (always present; value is a number or
    None where the underlying data isn't available), plus `detail` (the supporting
    counts that back each headline) and `north_star` (the operating-model
    headline). Never raises on a missing table/column — those degrade to None.
    """
    fp = _false_positive(db)
    sos = _sos(db)
    resp = _responder(db)
    cases = _cases(db)
    deliv = _deliveries(db)

    headline = {
        # signal -> review -> warn timing
        "signal_to_review_min": _signal_to_review_min(db),
        "review_to_alert_min": _review_to_alert_min(db),
        # warn surface
        "alerts_active": _alerts_active(db),
        # quality
        "false_positive_rate": fp["rate"],
        # response loop
        "sos_open": sos["open"],
        "responder_ack_rate": resp["ack_rate"],
        # outcomes
        "cases_open": cases["open"],
        "cases_resolved": cases["resolved"],
        # last mile
        "deliveries": deliv["total"],
    }
    headline["detail"] = {
        "false_positive": fp,
        "sos": sos,
        "responder": resp,
        "cases": cases,
        "deliveries": deliv,
    }
    headline["north_star"] = _north_star(db, fp, resp)
    return headline


# ===========================================================================
# 4. SELF-TEST  (python engine/metrics.py)
# ===========================================================================
if __name__ == "__main__":
    import os
    import sqlite3
    import sys

    # Import the real db + response modules the way api.py does (flat, from engine/).
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import db as _db
    import response as _resp  # noqa: F401  (already imported above; assert presence)

    # --- A. BARE DB (base schema only, no response-loop tables): degrade cleanly
    # db.DB(":memory:") now ALWAYS runs _migrate() -> _migrate_phase_tables(),
    # which creates sos_events / responder_tasks / deliveries (from
    # response.RESPONSE_TABLES) on EVERY DB. So a plain db.DB no longer leaves
    # those tables *absent* — _count would see an empty-but-present table and
    # return 0, not None. To keep this section's real coverage — proving compute()'s
    # best-effort guards degrade a GENUINELY-ABSENT table to None (distinct from a
    # wired-but-empty table's 0) — we build a real db.DB that loads ONLY the base
    # schema and skips _migrate() (and therefore the phase tables). This still
    # exercises the exact _all/_one/decisions read paths the live endpoint uses,
    # against a DB where sos_events/responder_tasks/deliveries truly don't exist.
    bare = _db.DB.__new__(_db.DB)        # real DB instance, but __init__/_migrate NOT run
    bare.pg = False
    bare.conn = sqlite3.connect(":memory:")
    bare.conn.row_factory = sqlite3.Row
    bare.conn.executescript(_db.SCHEMA_SQLITE)   # base tables only; no sos/responder/deliveries
    bare.conn.commit()
    m0 = compute(bare)
    for k in ("signal_to_review_min", "review_to_alert_min", "alerts_active",
              "false_positive_rate", "sos_open", "responder_ack_rate",
              "cases_open", "cases_resolved", "deliveries"):
        assert k in m0, ("missing headline key %s" % k)
    assert "detail" in m0 and "north_star" in m0
    # sos/responder/deliveries tables absent -> their counts degrade to None.
    assert m0["sos_open"] is None, m0["sos_open"]
    assert m0["responder_ack_rate"] is None, m0["responder_ack_rate"]
    assert m0["deliveries"] is None, m0["deliveries"]
    # missing table IS present -> concrete zero, not None.
    assert m0["cases_open"] == 0 and m0["cases_resolved"] == 0, m0
    # nothing ruled yet -> false-positive rate unknown (None), not 0.0.
    assert m0["false_positive_rate"] is None, m0["false_positive_rate"]
    bare.close()

    # --- B. FULL DB: splice the response-loop tables in and exercise real data --
    full = _db.DB(":memory:")
    for ddl in _resp.DDL_SQLITE:               # create sos_events/responder_tasks/...
        full.conn.executescript(ddl)
    for col, sdecl, _p in _resp.ALERT_LIFECYCLE_COLUMNS:   # alert lifecycle columns
        try:
            full.conn.execute("ALTER TABLE alerts ADD COLUMN " + col + " " + sdecl)
        except Exception:
            pass
    full.conn.commit()

    now = datetime.datetime(2026, 6, 4, 12, 0, 0)
    t0 = now.isoformat(timespec="seconds")
    t10 = (now + datetime.timedelta(minutes=10)).isoformat(timespec="seconds")
    t20 = (now + datetime.timedelta(minutes=20)).isoformat(timespec="seconds")

    # one signal -> one incident -> verified decision -> alert (full funnel)
    sid, _ = full.insert_signal({"source_name": "src", "title": "kidnap on road",
                                 "text": "x", "kind": "rss", "lang": "en",
                                 "published_at": t0})
    # force a known ingest time so the signal->review latency is deterministic.
    full.conn.execute("UPDATE signals SET ingested_at=? WHERE id=?", (t0, sid))
    iid = full._insert(
        "INSERT INTO incidents (incident_uuid, event_version, type, location_name, state,"
        " lat, lng, window_start, window_end, source_count, source_diversity, severity,"
        " confidence, status, summary, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("inc-uuid-1", 1, "kidnapping", "Kankara", "Katsina", 11.6, 7.9, t0, t0,
         1, 1, 4, 80, "candidate_unverified", "s", t0))
    full._run("INSERT INTO incident_signals (incident_id, signal_id) VALUES (?,?)", (iid, sid))
    # decision ruled 10 min after ingest
    full.conn.execute(
        "INSERT INTO decisions (incident_uuid, event_version, key, decision, note, actor, ts,"
        " prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
        ("inc-uuid-1", 1, "k", "verified", "", "amina", t10, "", "h1"))
    # a second incident ruled dismissed (drives false-positive rate to 1/2 = 0.5)
    full.conn.execute(
        "INSERT INTO decisions (incident_uuid, event_version, key, decision, note, actor, ts,"
        " prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
        ("inc-uuid-2", 1, "k2", "dismissed", "", "bola", t10, "h1", "h2"))
    # alert fired 10 min after the verify (review->alert = 10 min), lifecycle live
    full.conn.execute(
        "INSERT INTO alerts (incident_key, level, level_label, title, guidance, lat, lng,"
        " radius_km, reach, status, created_at, state, expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("inc-uuid-1", 3, "RED", "t", "g", 11.6, 7.9, 50, 6000, "active", t20,
         _resp.ALERT_PUBLISHED, (now + datetime.timedelta(hours=24)).isoformat(timespec="seconds")))
    full.conn.commit()

    # sos: two events, one open (TRIGGERED), one terminal (SAFE)
    full.conn.execute("INSERT INTO sos_events (sos_uuid, created_at, state, mode) VALUES (?,?,?,?)",
                      ("sos-1", t0, _resp.SOS_TRIGGERED, "silent"))
    full.conn.execute("INSERT INTO sos_events (sos_uuid, created_at, state, mode) VALUES (?,?,?,?)",
                      ("sos-2", t0, _resp.SOS_SAFE, "auto"))
    # responder tasks: one acked within SLA (ack 10m after create), one un-acked
    full.conn.execute(
        "INSERT INTO responder_tasks (task_uuid, created_at, state, ack_at) VALUES (?,?,?,?)",
        ("task-1", t0, _resp.TASK_RESPONDING, t10))
    full.conn.execute(
        "INSERT INTO responder_tasks (task_uuid, created_at, state) VALUES (?,?,?)",
        ("task-2", t0, _resp.TASK_RECEIVED))
    # deliveries: one real, one sim
    full.conn.execute(
        "INSERT INTO deliveries (created_at, channel, address, status, sim) VALUES (?,?,?,?,?)",
        (t0, "sms", "+234x", "sent", 0))
    full.conn.execute(
        "INSERT INTO deliveries (created_at, channel, address, status, sim) VALUES (?,?,?,?,?)",
        (t0, "sms", "+234y", "sim_delivered", 1))
    # missing cases: one active, one recovered
    full.insert_missing({"name": "A B", "place": "Kankara", "lat": 11.6, "lng": 7.9,
                         "last_seen": t0})
    full.insert_missing({"name": "C D", "place": "Zaria", "lat": 11.1, "lng": 7.7,
                         "last_seen": t0})
    full.set_missing_status(2, "recovered")
    full.conn.commit()

    m = compute(full)

    # timing funnel
    assert m["signal_to_review_min"] == 10.0, m["signal_to_review_min"]
    assert m["review_to_alert_min"] == 10.0, m["review_to_alert_min"]
    # warn surface: the lifecycle-PUBLISHED, in-TTL alert is live
    assert m["alerts_active"] == 1, m["alerts_active"]
    # quality: 1 dismissed of 2 ruled
    assert abs(m["false_positive_rate"] - 0.5) < 1e-9, m["false_positive_rate"]
    # response loop
    assert m["sos_open"] == 1, m["detail"]["sos"]
    assert m["detail"]["sos"]["safe"] == 1 and m["detail"]["sos"]["total"] == 2
    assert abs(m["responder_ack_rate"] - 0.5) < 1e-9, m["detail"]["responder"]
    assert m["detail"]["responder"]["within_sla"] == 1, m["detail"]["responder"]
    assert abs(m["detail"]["responder"]["sla_rate"] - 0.5) < 1e-9
    # outcomes
    assert m["cases_open"] == 1 and m["cases_resolved"] == 1, m["detail"]["cases"]
    # last mile: 2 receipts, 1 real + 1 sim
    assert m["deliveries"] == 2, m["deliveries"]
    assert m["detail"]["deliveries"]["real"] == 1 and m["detail"]["deliveries"]["sim"] == 1
    # north star composed from the above
    ns = m["north_star"]
    assert ns["verified_emergencies"] == 1, ns
    assert ns["acknowledged_responses"] == 1, ns
    assert abs(ns["within_sla_rate"] - 0.5) < 1e-9, ns
    assert ns["ack_sla_min"] == ACK_SLA_MIN
    full.close()

    # --- C. pure-helper edge cases --------------------------------------------
    assert _median([]) is None
    assert _median([5]) == 5.0
    assert _median([1, 3]) == 2.0
    assert _median([3, 1, 2]) == 2.0
    assert _median([None, 4, None]) == 4.0
    assert _rate(1, 2) == 0.5
    assert _rate(0, 0) is None and _rate(None, 5) is None
    assert _minutes_between(t0, t10) == 10.0
    assert _minutes_between(t10, t0) is None          # out-of-order -> dropped
    assert _minutes_between(None, t0) is None
    assert _minutes_between("garbage", t0) is None

    print("metrics.py self-test OK")
