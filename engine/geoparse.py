"""Geo-parse a free-text signal into a candidate incident (event-centric).

Returns None (abstains) unless the text yields BOTH an incident type AND a
known Nigerian location. We detect events at places; we never profile people.

PRECISION HARDENING (DATA-05 false-positive suppression):
A bare keyword is not enough. The live news firehose is full of headlines that
*contain* an incident word in a non-emergency sense -- politics ("APC leaders
demand primary reviews"), economics ("groan over high cost of tomatoes"),
entertainment ("celebrates 17 years"), opinion, sport. The old substring matcher
also fired on accidental fragments (the Yoruba token "nu" inside "Ka-nu" and
"E-nu-gu" -> missing_person). To fire an incident we now require, near a place:

  1. word-boundary matches (no more "nu" inside "Kanu"); and
  2. at least one STRONG, unambiguous danger term for the type (a real
     violence/abduction VERB or phrase -- abduct / kidnap / gunmen / bandits /
     raid / armed robbery / "missing student" ...), not a lone weak keyword
     ("attack", "raid", "missing", "snatched") that routinely appears in benign
     copy; and
  3. no dominant non-emergency context (the negative_terms block in
     keywords.json) unless the strong danger signal clearly overrides it.

This trades a sliver of recall for a large precision gain. A safety app must not
cry wolf over tomato prices or party primaries.
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


# --- term classification (strong vs. weak) ----------------------------------
# WEAK terms appear constantly in benign news and must NOT, on their own, mint an
# incident. They can still *reinforce* a type that already has a strong hit. Most
# are short/ambiguous fragments or generic nouns. Everything else in the keyword
# lists is treated as a STRONG, unambiguous danger signal.
#
# NOTE: this is data, not a parallel vocabulary -- it filters the existing
# keywords.json so the two never drift. Add a term here to demote it to "weak".
_WEAK_TERMS = frozenset(s.lower() for s in (
    # generic English that fires on politics/sport/opinion/business copy
    "attack", "attacked", "raid", "raided", "ambush", "ambushed", "missing",
    "snatched", "robbery", "robbers", "extortion", "bribe", "bribery",
    "intimidation", "abuse of power", "disappeared", "last seen", "hostage",
    "hostages", "captives", "ransom", "gunfire", "open fire",
    # short / accidental-substring-prone non-English fragments
    "nu", "ja l", "bata", "bace", "sace", "satar", "fansa", "hari", "efu",
    "ego", "egbe", "nu ", "ohi", "sonu", "abete", "fashi", "danniya",
    "ngari", "mwakpo", "olota", "jaguda", "wepu", "garkuwa", "ta'addanci",
    "mahara", "ifipabanilo",
))

# A type can ONLY be fired by a strong hit. These are the per-type strong sets,
# derived from keywords.json minus the weak demotions above. Multi-word phrases
# and unambiguous verbs survive; bare fragments do not.
def _strong_terms_for(type_key):
    out = []
    for _lang, terms in _KW["incident_types"][type_key].items():
        for term in terms:
            if not term:
                continue
            tl = term.lower().strip()
            if tl in _WEAK_TERMS:
                continue
            out.append(tl)
    return out


def _all_terms_for(type_key):
    out = []
    for _lang, terms in _KW["incident_types"][type_key].items():
        out.extend(t.lower() for t in terms if t)
    return out


_STRONG = {k: _strong_terms_for(k) for k in _KW["incident_types"]}
_ALL = {k: _all_terms_for(k) for k in _KW["incident_types"]}


# --- person-context gate for missing_person ---------------------------------
# missing_person is the worst over-firer ("demand reviews", "groan over", any
# stray "missing"). It may fire ONLY with genuine person-missing / abduction
# phrasing: a missing *person* (student/girl/boy/son/daughter/...), a "declared/
# went missing", or an abduction verb. Otherwise we abstain on that type.
_PERSON_NOUN = (
    r"(?:student|students|pupil|pupils|girl|girls|boy|boys|child|children|kid|kids|"
    r"son|daughter|woman|women|man|men|person|persons|people|resident|residents|"
    r"traveller|travellers|traveler|travelers|commuter|commuters|passenger|passengers|"
    r"villager|villagers|farmer|farmers|worker|workers|sister|brother|"
    r"father|mother|husband|wife|relative|relatives|family|teenager|teenagers|"
    r"undergraduate|undergraduates|schoolgirl|schoolgirls|schoolboy|schoolboys)"
)
_MISSING_PERSON_RE = [
    re.compile(r"\b" + _PERSON_NOUN + r"\b[^.]{0,40}\b(?:go|goes|went|gone)\s+missing\b"),
    re.compile(r"\b(?:go|goes|went|gone)\s+missing\b"),
    re.compile(r"\b(?:declared|reported|feared|presumed)\s+missing\b"),
    re.compile(r"\bmissing\b[^.]{0,20}\b" + _PERSON_NOUN + r"\b"),
    re.compile(r"\b" + _PERSON_NOUN + r"\b[^.]{0,20}\bmissing\b"),
    re.compile(r"\bwhereabouts\s+(?:unknown|of)\b"),
    re.compile(r"\bsearch\s+for\s+(?:the\s+)?missing\b"),
]
# Abduction verbs that, on their own, also satisfy "a person is missing".
_ABDUCT_RE = re.compile(
    r"\b(?:abduct|abducts|abducted|abduction|abductors|kidnap|kidnaps|"
    r"kidnapped|kidnapping|kidnappers|whisked\s+away|held\s+captive|"
    r"taken\s+hostage|forcibly\s+taken)\b"
)


# --- negative (non-emergency) context (DATA-05) -----------------------------
_NEG = _KW.get("negative_terms", {})


def _neg_categories(t):
    """Which non-emergency contexts are present, with hit counts."""
    cats = {}
    for cat, terms in _NEG.items():
        if cat.startswith("_"):
            continue
        n = 0
        for term in terms:
            term = (term or "").lower().strip()
            if not term:
                continue
            if " " in term:
                if term in t:
                    n += 1
            elif re.search(r"\b" + re.escape(term) + r"\b", t):
                n += 1
        if n:
            cats[cat] = n
    return cats


# Extra, high-precision suppression cues the brief calls out explicitly that go
# beyond the generic negative_terms block: legal / electoral-party / economic /
# civic-opinion language. These never appear in a genuine abduction report, so
# their presence (absent a strong danger verb) is a strong "this is not an
# incident" signal.
_SUPPRESS_RE = re.compile(
    r"\b("
    r"apc|pdp|adc|lp|nnpp|apga|"                                 # parties
    r"primary|primaries|faction|factions|caucus|aspirant|aspirants|"
    r"ward\s+congress|congress|delegate|delegates|"
    r"appeal|appeals|appellate|tribunal|court|courts|judgment|judgement|"
    r"jurisdiction|suit|litigation|injunction|verdict|ruling|"
    r"sworn\s+in|swearing-in|impeach|impeachment|"
    r"groan|groans|inflation|hike|hikes|cost\s+of\s+living|"
    r"price|prices|pricing|tariff|subsidy|levy|"
    r"celebrate|celebrates|celebrated|celebration|anniversary|"
    r"award|awards|unveils|unveil|launch|launches|festival|carnival|"
    r"crisis\s+as|rival\s+factions|leadership\s+tussle"
    r")\b"
)


def detect_type(text):
    """Return (type_key, matched_terms) or (None, []) if no genuine incident.

    Precision rules:
      * matches are word-boundary (no accidental substrings);
      * a type needs at least one STRONG danger term to be a candidate;
      * missing_person additionally needs person-missing/abduction phrasing;
      * dominant non-emergency context suppresses a candidate unless a strong
        danger verb clearly overrides it.
    """
    t = text.lower()

    # Pre-compute context signals once.
    neg = _neg_categories(t)
    suppress_hit = bool(_SUPPRESS_RE.search(t))
    has_abduct = bool(_ABDUCT_RE.search(t))

    candidates = []  # (type_key, strong_hits, all_hits)
    for type_key in _KW["incident_types"]:
        strong_hits = [term for term in _STRONG[type_key]
                       if re.search(r"\b" + re.escape(term) + r"\b", t)]
        if not strong_hits:
            continue  # a lone weak keyword can never fire a type
        all_hits = [term for term in _ALL[type_key]
                    if re.search(r"\b" + re.escape(term) + r"\b", t)]

        if type_key == "missing_person":
            # Require genuine person-missing or abduction phrasing.
            if not (has_abduct or any(rx.search(t) for rx in _MISSING_PERSON_RE)):
                continue

        candidates.append((type_key, strong_hits, all_hits))

    if not candidates:
        return None, []

    # A genuine violence/abduction verb overrides non-emergency context; without
    # one, any dominant non-emergency cue makes us abstain (false-positive guard).
    strong_override = has_abduct or any(
        re.search(r"\b" + re.escape(term) + r"\b", t)
        for term in ("gunmen", "gun men", "bandit", "bandits", "armed men",
                     "armed group", "armed robber", "armed robbers", "raided",
                     "stormed the", "shot dead", "open fire", "ambushed")
    )
    if not strong_override and (suppress_hit or neg):
        return None, []

    # Pick the type with the most STRONG hits, then the most total hits.
    candidates.sort(key=lambda c: (len(c[1]), len(c[2])), reverse=True)
    best = candidates[0]
    return best[0], best[2]


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
        return None  # abstain: no genuine incident type
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


# --- self-test ---------------------------------------------------------------
if __name__ == "__main__":
    # ---- FALSE POSITIVES: these must now be SUPPRESSED (no detection) -------
    # Mirrors the verified junk from a live RSS pull. The second element is a
    # representative description so the title+text path is exercised.
    JUNK = [
        ("Enugu residents, sellers groan over high cost of tomatoes, pepper",
         "Traders in Enugu lament the rising cost of tomatoes, pepper and crayfish in the market."),
        ("Nnamdi Kanu's appeal: Nigerian Govt admitted Justice Omotosho acted without jurisdiction",
         "The appeal at the court raised questions of jurisdiction in the IPOB leader's case."),
        ("Lagos APC leaders demand primary reviews",
         "APC chieftains in Lagos demand a review of the party primaries and ward congress results."),
        ("Lagos celebrates 17 years of KingModel",
         "The entertainment outfit celebrates its anniversary with an award gala in Lagos."),
        ("Zamfara ADC faces internal crisis as two rival factions emerge",
         "The ADC in Zamfara is split as two rival factions emerge ahead of the congress."),
        ("Arewa Group: Greatest threat to Nigeria today is Fear",
         "In an opinion piece, the Arewa group said fear, not bandits, is the threat to the nation."),
        # extra economic / sport / metaphor guards
        ("Tinubu unveils new economic policy in Abuja",
         "The president launches a subsidy plan amid inflation concerns."),
        ("Super Eagles ambushed by late goal in Kaduna friendly",
         "The team was robbed of a win as the striker missed a penalty at the stadium."),
    ]
    for title, body in JUNK:
        res = geoparse({"title": title, "text": body})
        assert res is None, "FALSE POSITIVE not suppressed -> %r got %r" % (title, res)

    # detect_type alone must abstain on the junk titles too (defence in depth).
    for title, _ in JUNK:
        tk, _terms = detect_type(title)
        assert tk is None, "detect_type fired on junk title %r -> %r" % (title, tk)

    # ---- REAL INCIDENTS: these MUST still be detected ----------------------
    REAL = [
        ("Gunmen abduct travellers along Kaduna-Abuja highway",
         "Armed men kidnapped several travellers near Kaduna.", "kidnapping"),
        ("Gunmen abduct residents in Shiroro, Niger State",
         "Gunmen abducted and kidnapped several residents in Shiroro.", "kidnapping"),
        ("Travellers kidnapped near Lokoja",
         "Gunmen kidnapped travellers along a road near Lokoja, Kogi State.", "kidnapping"),
        ("Bandits raid Gusau community in Zamfara",
         "Armed bandits raided a community near Gusau, abducting two residents.", "banditry_attack"),
        ("Parents report missing students in Kankara",
         "Families in Kankara said some students went missing after gunmen were seen near a school.",
         "missing_person"),
        # additional real cases to lock recall
        ("Schoolgirl declared missing in Chibok", "Family searches for the missing girl.", "missing_person"),
        ("Armed robbers attack bank in Kano", "Armed robbers carried out a robbery at gunpoint.", "armed_robbery"),
    ]
    for title, body, want in REAL:
        res = geoparse({"title": title, "text": body})
        assert res is not None, "REAL incident lost -> %r" % (title,)
        assert res["type"] == want, \
            "REAL incident mis-typed -> %r got %r want %r" % (title, res["type"], want)

    # ---- DEMO SAMPLES: every sample_signals.json entry MUST still detect ----
    # (corroboration gates depend on these producing incidents.)
    _samples = _load("sample_signals.json")["signals"]
    for s in _samples:
        res = geoparse({"title": s.get("title", ""), "text": s.get("text", ""),
                        "lang": s.get("lang", "en")})
        assert res is not None, "DEMO sample no longer detects -> %r" % (s.get("title"),)

    # ---- word-boundary regression: the "nu" / fragment bug is dead ---------
    assert detect_type("Nnamdi Kanu")[0] is None
    assert detect_type("Enugu market")[0] is None

    print("geoparse.py self-test OK -- %d junk suppressed, %d real kept, %d demo samples detect"
          % (len(JUNK), len(REAL), len(_samples)))
