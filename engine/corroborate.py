"""Cluster geo-parsed detections into incidents with calibrated confidence.

This module is where the governance rules live as code:
  - corroboration across independent sources raises confidence (diminishing returns),
  - a single unverified source is capped low,
  - nothing is ever auto-"verified": the strongest automatic status is
    `needs_human_review`, which routes the event to a human decision.
"""
import math
import datetime

WINDOW_HOURS = 72
CLUSTER_KM = 30


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


def score(c):
    members = c["members"]
    sources = set(m.get("source_name", "?") for m in members)
    source_count = len(sources)
    severity = max((m.get("severity", 0) for m in members), default=0)
    hotspot = any(m.get("hotspot") for m in members)

    # Calibrated-ish confidence with diminishing returns on extra sources.
    conf = 22 + 26 * math.log2(source_count + 1)
    if severity:
        conf += 10
    if hotspot:
        conf += 6
    conf = int(max(5, min(99, conf)))

    # Decision policy / human gate. NEVER auto-"verified".
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
