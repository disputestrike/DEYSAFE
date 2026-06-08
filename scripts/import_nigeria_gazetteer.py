"""Build DeySafe's generated Nigeria-wide offline gazetteer.

The embedded table in engine/gazetteer.py is intentionally small and curated.
This script refreshes a larger, source-attributed table from public datasets:

* all 774 Nigerian LGAs with state and approximate coordinates
* all ward coordinate records exposed by the optional wards source

It writes config/nigeria_admin_places.json. The app still supports live Google
Places/OSM lookup, but this file gives DeySafe a nationwide offline baseline.
"""
import datetime
import json
import os
import re
import sys
import urllib.request


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(ROOT, "config", "nigeria_admin_places.json")

LGA_URL = "https://raw.githubusercontent.com/xosasx/nigerian-local-government-areas/master/lgas.json"
WARD_URL = "https://raw.githubusercontent.com/temikeezy/nigeria-geojson-data/main/data/wards.json"

SOURCES = [
    {
        "name": "xosasx/nigerian-local-government-areas",
        "kind": "lga",
        "url": LGA_URL,
        "license": "see upstream repository",
    },
    {
        "name": "temikeezy/nigeria-geojson-data",
        "kind": "ward",
        "url": WARD_URL,
        "license": "see upstream repository",
    },
]


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "DeySafe-Gazetteer-Importer/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read().decode("utf-8"))


def clean_text(value, limit=120):
    text = re.sub(r"\s+", " ", str(value or "").strip())
    return text[:limit]


def norm(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def in_nigeria(lat, lng):
    try:
        lat = float(lat)
        lng = float(lng)
    except Exception:
        return False
    return 3.0 <= lat <= 15.0 and 2.0 <= lng <= 15.5


def add_place(out, seen, name, lat, lng, state, kind, aliases=None, source=""):
    name = clean_text(name)
    state = clean_text(state, 80)
    if not name or not state or not in_nigeria(lat, lng):
        return False
    key = norm(name)
    if not key or key in seen:
        return False
    seen.add(key)
    aliases = [clean_text(a) for a in (aliases or []) if clean_text(a)]
    out.append({
        "name": name,
        "lat": round(float(lat), 7),
        "lng": round(float(lng), 7),
        "state": state,
        "kind": kind,
        "hotspot": False,
        "aliases": sorted(set(a for a in aliases if norm(a) != key)),
        "source": source,
    })
    return True


def build():
    places = []
    seen = set()
    counts = {"lga": 0, "ward": 0, "skipped": 0}

    lgas = fetch_json(LGA_URL)
    for row in lgas:
        state = clean_text(row.get("state_name"))
        name = clean_text(row.get("name"))
        canonical = "%s, %s" % (name, state)
        ok = add_place(
            places,
            seen,
            canonical,
            row.get("latitude"),
            row.get("longitude"),
            state,
            "lga",
            aliases=[
                name,
                "%s, Nigeria" % name,
            ],
            source="xosasx_nigerian_local_government_areas",
        )
        counts["lga" if ok else "skipped"] += 1

    wards = fetch_json(WARD_URL)
    for row in wards:
        state = clean_text(row.get("State"))
        lga = clean_text(row.get("LGA"))
        ward = clean_text(row.get("Ward"))
        canonical = "%s, %s, %s" % (ward, lga, state)
        ok = add_place(
            places,
            seen,
            canonical,
            row.get("Latitude"),
            row.get("Longitude"),
            state,
            "ward",
            aliases=[
                ward,
                "%s Ward" % ward,
                "%s, %s" % (ward, lga),
                "%s, %s State" % (ward, state),
            ],
            source="temikeezy_nigeria_geojson_data",
        )
        counts["ward" if ok else "skipped"] += 1

    places.sort(key=lambda p: (p["state"], p["kind"], p["name"]))
    return {
        "schema": "deysafe.nigeria_admin_places.v1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "sources": SOURCES,
        "counts": {
            "states": len({p["state"] for p in places}),
            "lga": counts["lga"],
            "ward": counts["ward"],
            "total": len(places),
            "skipped": counts["skipped"],
        },
        "places": places,
    }


def main():
    data = build()
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=True, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote %s" % OUT_PATH)
    print(json.dumps(data["counts"], sort_keys=True))
    if data["counts"]["lga"] < 774:
        print("expected at least 774 LGAs, got %s" % data["counts"]["lga"], file=sys.stderr)
        return 2
    if data["counts"]["ward"] < 8000:
        print("expected at least 8000 ward records, got %s" % data["counts"]["ward"], file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
