"""Server-side safety timers for Journey Guard and SafeMeet.

The phone may disappear after the last packet. This module gives the server an
independent tick that can mark stale/overdue sessions without waiting for another
client request.
"""
import datetime


TERMINAL_JOURNEY = {"arrived", "closed", "cancelled", "CLOSED_VERIFIED"}
TERMINAL_MEET = {"completed", "cancelled", "closed"}


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00").replace("+00:00", ""))
    except Exception:
        return None


def _age_minutes(value, now):
    ts = _parse_iso(value)
    if not ts:
        return None
    return max(0.0, (now - ts).total_seconds() / 60.0)


def _overdue_minutes(expected, now):
    ts = _parse_iso(expected)
    if not ts:
        return None
    return (now - ts).total_seconds() / 60.0


def tick(db, now=None):
    now = now or datetime.datetime.now()
    out = {"ok": True, "journeys_checked": 0, "journeys_escalated": 0,
           "safemeets_checked": 0, "safemeets_escalated": 0, "events": []}

    for row in db.active_journeys(limit=500):
        out["journeys_checked"] += 1
        jid = row.get("journey_uuid")
        stale = _age_minutes(row.get("last_packet_at") or row.get("updated_at"), now)
        overdue = _overdue_minutes(row.get("expected_arrival"), now)
        reason = ""
        event_type = ""
        if overdue is not None and overdue > 15:
            event_type = "server_overdue"
            reason = "journey overdue by %d min" % int(overdue)
        if stale is not None and stale > 10 and row.get("state") not in TERMINAL_JOURNEY:
            event_type = "server_stale_device"
            reason = "device silent for %d min" % int(stale)
        if event_type and row.get("anomaly_reason") != reason:
            db.record_journey_event(jid, {"event_type": event_type, "note": reason})
            db.set_journey_anomaly(jid, "critical" if event_type == "server_stale_device" else "warning",
                                   reason, state="escalated")
            out["journeys_escalated"] += 1
            out["events"].append({"type": event_type, "journey_uuid": jid,
                                  "handoff_ref": row.get("handoff_ref"), "reason": reason})

    for row in db.active_safemeets(limit=500):
        out["safemeets_checked"] += 1
        sid = row.get("session_uuid")
        stale = _age_minutes(row.get("last_checkin_at") or row.get("updated_at"), now)
        expected = row.get("expected_end") or row.get("expected_arrival")
        overdue = _overdue_minutes(expected, now)
        reason = ""
        if overdue is not None and overdue > 15:
            reason = "meeting overdue by %d min" % int(overdue)
        if stale is not None and stale > 10:
            reason = "meeting device silent for %d min" % int(stale)
        if reason and row.get("escalation_reason") != reason:
            db.update_safemeet_session(sid, {
                "state": "escalated",
                "escalation_reason": reason,
            })
            out["safemeets_escalated"] += 1
            out["events"].append({"type": "safemeet_timer", "session_uuid": sid,
                                  "reference": row.get("reference_code"), "reason": reason})

    try:
        db.audit("safetytick", "tick", "journeys=%s/%s safemeets=%s/%s" % (
            out["journeys_escalated"], out["journeys_checked"],
            out["safemeets_escalated"], out["safemeets_checked"]))
    except Exception:
        pass
    return out
