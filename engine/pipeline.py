"""Run one detection pass: ingest -> geoparse -> corroborate -> store + export.

Usage:
  python engine/pipeline.py            # synthetic sample data (deterministic)
  python engine/pipeline.py --live     # also pull live Nigerian news RSS
"""
import sys
import os
import json
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from db import DB
import ingest
import geoparse
import corroborate

EXPORT_KEYS = ("type", "location_name", "state", "confidence", "status",
               "source_count", "severity", "summary", "window_start", "window_end")


def export(incidents):
    feats = []
    for inc in incidents:
        feats.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [inc["lng"], inc["lat"]]},
            "properties": {k: inc[k] for k in EXPORT_KEYS},
        })
    fc = {
        "type": "FeatureCollection",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "features": feats,
    }
    out = os.path.join(BASE, "console", "incidents.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(fc, f, ensure_ascii=False, indent=2)
    return out


def report(signals, detections, incidents):
    print("\n=== GUARDIAN-NG detection pass ===")
    print("signals ingested                   : %d" % len(signals))
    print("candidate detections (type+place)  : %d" % len(detections))
    print("clustered incidents                : %d\n" % len(incidents))
    order = {"needs_human_review": 0, "corroborated": 1, "candidate_unverified": 2}
    for inc in sorted(incidents, key=lambda i: (order.get(i["status"], 9), -i["confidence"])):
        print("[{status:>20}] conf {confidence:>3} | {type:<16} | {location_name}, {state} "
              "| sources={source_count} sev={severity}".format(**inc))
        print("     -> {}".format((inc["summary"] or "")[:88]))
    print("\nNote: 'verified' is never set automatically. "
          "Items at needs_human_review await a human decision.")


def main():
    ap = argparse.ArgumentParser(description="Guardian-NG detection pipeline (prototype)")
    ap.add_argument("--live", action="store_true", help="also pull live Nigerian news RSS feeds")
    args = ap.parse_args()

    db = DB(os.path.join(BASE, "data", "guardian.db"))
    db.audit("pipeline", "run_start", "live=%s" % args.live)

    signals = ingest.gather(use_live=args.live, use_sample=True)
    detections = []
    for s in signals:
        sid, _is_new = db.insert_signal(s)
        gp = geoparse.geoparse(s)
        if gp:
            gp.update({"signal_id": sid, "source_name": s["source_name"],
                       "published_at": s["published_at"], "title": s.get("title", "")})
            detections.append(gp)

    incidents = corroborate.build_incidents(detections)
    db.replace_incidents(incidents)
    db.audit("pipeline", "run_complete",
             "signals=%d detections=%d incidents=%d" % (len(signals), len(detections), len(incidents)))

    out = export(incidents)
    report(signals, detections, incidents)
    print("\nexported -> %s" % out)


if __name__ == "__main__":
    main()
