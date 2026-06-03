"""Geo-parse a free-text signal into a candidate incident (event-centric).

Returns None (abstains) unless the text yields BOTH an incident type AND a
known Nigerian location. We detect events at places; we never profile people.
"""
import re
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(BASE, "config")


def _load(name):
    with open(os.path.join(CONFIG, name), encoding="utf-8") as f:
        return json.load(f)


_KW = _load("keywords.json")
_LOC = _load("locations.json")["places"]


def _terms_for(type_key):
    out = []
    for _lang, terms in _KW["incident_types"][type_key].items():
        out.extend(terms)
    return out


def detect_type(text):
    t = text.lower()
    best, best_hits = None, []
    for type_key in _KW["incident_types"]:
        hits = [term for term in _terms_for(type_key) if term and term.lower() in t]
        if hits and len(hits) > len(best_hits):
            best, best_hits = type_key, hits
    return best, best_hits


def detect_location(text):
    t = text.lower()
    found = []
    for p in _LOC:
        for nm in [p["name"]] + p.get("aliases", []):
            if re.search(r"\b" + re.escape(nm.lower()) + r"\b", t):
                found.append(p)
                break
    if not found:
        return None
    # Prefer a known hotspot, then the most specific (longest) name.
    found.sort(key=lambda p: (not p.get("hotspot", False), -len(p["name"])))
    return found[0]


def detect_language(text):
    t = " " + text.lower() + " "
    scores = {lang: sum(1 for h in hints if h.lower() in t)
              for lang, hints in _KW.get("language_hints", {}).items()}
    if scores:
        lang = max(scores, key=scores.get)
        if scores[lang] > 0:
            return lang
    return "en"


def detect_severity(text):
    t = text.lower()
    return sum(1 for s in _KW.get("severity_terms", []) if s.lower() in t)


def geoparse(signal):
    text = (signal.get("title", "") + ". " + signal.get("text", "")).strip()
    type_key, terms = detect_type(text)
    if not type_key:
        return None  # abstain: no incident type
    loc = detect_location(text)
    if not loc:
        return None  # abstain: event-centric requires a location
    return {
        "type": type_key,
        "terms": terms,
        "location_name": loc["name"],
        "state": loc.get("state", ""),
        "lat": loc["lat"],
        "lng": loc["lng"],
        "hotspot": loc.get("hotspot", False),
        "lang": signal.get("lang") or detect_language(text),
        "severity": detect_severity(text),
    }
