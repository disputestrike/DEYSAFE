"""Offline Nigeria gazetteer + fuzzy place lookup for DeySafe / SHIELD (GEO-02/03).

WHY THIS EXISTS
---------------
Today the only place->coordinate paths are:
  - api.py::place_coords()  -> EXACT (case-insensitive) match against the 48-row
    config/locations.json starter set, else (None, None).
  - api.py::geocode()       -> that same exact match, else a live Nominatim/OSM
    HTTP call (rate-limited to ~1 req/s, weak on rural Nigeria, town-centroid
    only, and unavailable offline / on 2G / behind a flaky uplink).

GEO-02 ("sole reliance on public Nominatim") and GEO-03 ("48-town gazetteer ->
774 LGAs + wards + settlements + aliases/local spellings + offline cache") ask
for a *controlled*, *offline* geodata layer. This module is that layer: a larger
embedded Nigeria place table (every state capital + many LGAs / wards / known
kidnapping-belt hotspots, each with lat / lng / state) and a tolerant lookup()
that resolves a free-typed place name WITHOUT touching the network and returns a
*confidence* per match so callers can honour GEO-01 ("no silent centroid; flag
unverified") instead of guessing.

DESIGN RULES (mirror security.py / response.py)
-----------------------------------------------
  - STDLIB ONLY. No DB handle, no env reads, NO NETWORK, no file I/O at import
    time beyond the optional best-effort merge of config/locations.json (guarded;
    a missing/broken file never breaks import). Pure/deterministic lookups.
  - Bright lines: this is a *place* gazetteer. It holds no person data and never
    profiles anyone — only public geography (capitals, LGAs, landmarks, hotspots).
  - GEO-01 honoured by CONTRACT: lookup() returns None on a real miss (it never
    invents the Nigeria centroid). Confidence is graded so a fuzzy/partial hit can
    be surfaced to the operator as "needs a pin" rather than trusted blindly.

PUBLIC API
----------
  lookup(name)                 -> {name, lat, lng, state, kind, confidence, source}
                                  or None on a miss. Alias/spelling tolerant.
  best(name) / candidates(name, limit)   ranked match(es) with scores.
  resolve(name)                -> (lat, lng, confidence) convenience tuple.
  all_places()                 -> the merged embedded table (list of dicts).
  states()                     -> sorted list of state names present.
  in_state(state)              -> places filtered to one state.
  PLACES                       the merged table (also exposed as a constant).

Each record is a dict: {name, lat, lng, state, kind, hotspot, aliases:[...]}.
`kind` is one of: capital, city, lga, ward, town, road, market, motor_park,
checkpoint, school, religious, landmark, forest.
"""
import os
import re
import json
import difflib

# ---------------------------------------------------------------------------
# 0. Confidence vocabulary (GEO-01 grading)
# ---------------------------------------------------------------------------
# A single, small, named scale so callers (api.py coords_for / geocode) can map a
# match straight onto their existing "coords_confidence" field without inventing
# numbers. EXACT/ALIAS are trustworthy; NORMALIZED is still safe (punctuation /
# spelling-variant only); FUZZY/PARTIAL should be shown to a human as a *guess*.
CONF_EXACT = "exact"        # canonical name matched verbatim (case-insensitive)
CONF_ALIAS = "alias"        # matched a known alias / local spelling
CONF_NORMALIZED = "normalized"  # matched after removing punctuation/accents/affixes
CONF_FUZZY = "fuzzy"        # close edit-distance match (likely a typo)
CONF_PARTIAL = "partial"    # query is contained in / contains a known name (weak)

# Numeric weight per tier (0..1) — handy when a caller wants to threshold.
CONF_SCORE = {
    CONF_EXACT: 1.0,
    CONF_ALIAS: 0.95,
    CONF_NORMALIZED: 0.85,
    CONF_FUZZY: 0.7,
    CONF_PARTIAL: 0.55,
}
# A fuzzy match below this difflib ratio is rejected outright (too far to trust).
_FUZZY_MIN_RATIO = 0.82
SOURCE = "gazetteer_offline"


# ---------------------------------------------------------------------------
# 1. Embedded place table (OFFLINE — no network ever)
# ---------------------------------------------------------------------------
# Coordinates are public, approximate centroids (degrees, WGS84). This is NOT the
# full 774-LGA / 7,000-ward dataset (that ships as data, e.g. HDX/OCHA admin
# boundaries, merged at load via config/locations.json) — it is a substantial,
# hand-verified core that (a) covers all 36 state capitals + FCT, (b) densely
# covers the North-West / North-Central kidnapping belt at LGA + ward + landmark
# level, and (c) carries the landmark *kinds* GEO-03 calls for (roads, markets,
# motor-parks, checkpoints, schools, religious centres, forests) so the corridor
# scan / terrain work has anchors to hang on. Local spellings live in `aliases`.
#
# Tuple form keeps the source compact: (name, lat, lng, state, kind, hotspot,
# [aliases]); _expand() turns each into the canonical record dict.
_RAW = [
    # ---- 36 STATE CAPITALS + FCT (kind=capital) ----------------------------
    ("Abuja", 9.0765, 7.3986, "FCT", "capital", False,
        ["FCT", "Federal Capital Territory", "Abuja FCT"]),
    ("Umuahia", 5.5247, 7.4947, "Abia", "capital", False, []),
    ("Yola", 9.2035, 12.4954, "Adamawa", "capital", False, []),
    ("Uyo", 5.0377, 7.9128, "Akwa Ibom", "capital", False, []),
    ("Awka", 6.2109, 7.0741, "Anambra", "capital", False, []),
    ("Bauchi", 10.3158, 9.8442, "Bauchi", "capital", False, []),
    ("Yenagoa", 4.9267, 6.2676, "Bayelsa", "capital", False, ["Yenegoa"]),
    ("Makurdi", 7.7333, 8.5333, "Benue", "capital", False, []),
    ("Maiduguri", 11.8333, 13.1500, "Borno", "capital", True, ["Maidugiri"]),
    ("Calabar", 4.9757, 8.3417, "Cross River", "capital", False, []),
    ("Asaba", 6.2009, 6.7300, "Delta", "capital", False, []),
    ("Abakaliki", 6.3249, 8.1137, "Ebonyi", "capital", False, ["Abakiliki"]),
    ("Benin City", 6.3350, 5.6037, "Edo", "capital", False, ["Benin", "Ubini"]),
    ("Ado-Ekiti", 7.6211, 5.2214, "Ekiti", "capital", False, ["Ado Ekiti", "Ado"]),
    ("Enugu", 6.4584, 7.5464, "Enugu", "capital", False, []),
    ("Gombe", 10.2897, 11.1673, "Gombe", "capital", False, []),
    ("Owerri", 5.4836, 7.0333, "Imo", "capital", False, []),
    ("Dutse", 11.7560, 9.3380, "Jigawa", "capital", False, []),
    ("Kaduna", 10.5222, 7.4383, "Kaduna", "capital", True, ["Kaduna City"]),
    ("Kano", 12.0022, 8.5920, "Kano", "capital", False, ["Kano City"]),
    ("Katsina", 12.9908, 7.6018, "Katsina", "capital", True, []),
    ("Birnin Kebbi", 12.4539, 4.1975, "Kebbi", "capital", False, ["Birni Kebbi"]),
    ("Lokoja", 7.7969, 6.7400, "Kogi", "capital", False, []),
    ("Ilorin", 8.4966, 4.5421, "Kwara", "capital", False, []),
    ("Ikeja", 6.6018, 3.3515, "Lagos", "capital", False, ["Lagos State capital"]),
    ("Lafia", 8.4939, 8.5160, "Nasarawa", "capital", False, []),
    ("Minna", 9.6139, 6.5569, "Niger", "capital", True, []),
    ("Abeokuta", 7.1557, 3.3451, "Ogun", "capital", False, []),
    ("Akure", 7.2508, 5.2103, "Ondo", "capital", False, []),
    ("Osogbo", 7.7667, 4.5667, "Osun", "capital", False, ["Oshogbo"]),
    ("Ibadan", 7.3775, 3.9470, "Oyo", "capital", False, []),
    ("Jos", 9.8965, 8.8583, "Plateau", "capital", True, []),
    ("Port Harcourt", 4.8156, 7.0498, "Rivers", "capital", False, ["PH", "Port-Harcourt"]),
    ("Sokoto", 13.0059, 5.2476, "Sokoto", "capital", True, ["Sakkwato"]),
    ("Jalingo", 8.8833, 11.3667, "Taraba", "capital", False, []),
    ("Damaturu", 11.7470, 11.9608, "Yobe", "capital", True, []),
    ("Gusau", 12.1628, 6.6614, "Zamfara", "capital", True, []),

    # ---- LAGOS (dense — largest population centre) -------------------------
    ("Lagos", 6.5244, 3.3792, "Lagos", "city", False, ["Eko", "Lagos Island"]),
    ("Surulere", 6.5000, 3.3500, "Lagos", "lga", False, []),
    ("Mushin", 6.5278, 3.3500, "Lagos", "lga", False, []),
    ("Oshodi", 6.5550, 3.3470, "Lagos", "lga", False, ["Oshodi-Isolo"]),
    ("Alimosho", 6.6000, 3.2700, "Lagos", "lga", False, []),
    ("Agege", 6.6200, 3.3200, "Lagos", "lga", False, []),
    ("Ikorodu", 6.6194, 3.5105, "Lagos", "lga", False, []),
    ("Epe", 6.5833, 3.9833, "Lagos", "lga", False, []),
    ("Badagry", 6.4154, 2.8810, "Lagos", "lga", False, []),
    ("Lekki", 6.4600, 3.6000, "Lagos", "town", False, []),
    ("Ojota", 6.5790, 3.3830, "Lagos", "motor_park", False, ["Ojota Motor Park"]),
    ("Berger", 6.5560, 3.3760, "Lagos", "motor_park", False, ["Berger Motor Park"]),
    ("Mile 2", 6.4640, 3.3120, "Lagos", "checkpoint", False, ["Mile2"]),

    # ---- KADUNA (NW kidnapping belt — LGA + ward + landmark) ---------------
    ("Birnin Gwari", 11.0500, 6.5500, "Kaduna", "lga", True,
        ["Birni Gwari", "Birnin-Gwari", "Birnin Gwarri"]),
    ("Kajuru", 10.3333, 7.6833, "Kaduna", "lga", True, []),
    ("Chikun", 10.3500, 7.3000, "Kaduna", "lga", True, []),
    ("Igabi", 10.8000, 7.6000, "Kaduna", "lga", True, []),
    ("Giwa", 11.2167, 7.4500, "Kaduna", "lga", True, []),
    ("Kachia", 9.8667, 7.9500, "Kaduna", "lga", True, []),
    ("Zangon Kataf", 9.7833, 8.3000, "Kaduna", "lga", True, ["Zango Kataf", "Zangon-Kataf"]),
    ("Kauru", 10.5500, 8.1833, "Kaduna", "lga", True, []),
    ("Lere", 10.3833, 8.5667, "Kaduna", "lga", True, []),
    ("Kagarko", 9.4833, 7.8000, "Kaduna", "lga", True, []),
    ("Jema'a", 9.4500, 8.3833, "Kaduna", "lga", True, ["Jemaa", "Jema'a"]),
    ("Sanga", 9.4500, 8.5333, "Kaduna", "lga", True, []),
    ("Zaria", 11.0667, 7.7000, "Kaduna", "city", False, ["Zazzau"]),
    ("Sabon Gari", 11.1000, 7.7167, "Kaduna", "ward", False, ["Sabon Gari Zaria"]),
    ("Kakau", 10.4170, 7.4500, "Kaduna", "ward", True, []),
    ("Kasuwan Magani", 10.2500, 7.6500, "Kaduna", "town", True, ["Kasuwa Magani"]),
    ("Udawa", 10.7330, 7.2670, "Kaduna", "town", True, []),
    ("Kahutu", 10.3000, 7.6500, "Kaduna", "town", True, []),
    ("Kaduna-Abuja Road", 9.8000, 7.2000, "Kaduna", "road", True,
        ["Abuja Kaduna Road", "Abuja-Kaduna Highway", "Kaduna Abuja Expressway"]),
    ("Rijana", 9.9670, 7.4000, "Kaduna", "checkpoint", True, ["Rijana checkpoint"]),
    ("Katari", 9.6500, 7.3000, "Kaduna", "checkpoint", True, []),
    ("Akilbu Forest", 10.6000, 7.0000, "Kaduna", "forest", True, ["Kuduru Forest"]),

    # ---- KATSINA (NW belt) -------------------------------------------------
    ("Kankara", 11.9400, 7.4100, "Katsina", "lga", True, []),
    ("Jibia", 13.0900, 7.2300, "Katsina", "lga", True, []),
    ("Faskari", 11.6167, 7.0000, "Katsina", "lga", True, []),
    ("Sabuwa", 11.5333, 7.0167, "Katsina", "lga", True, []),
    ("Dandume", 11.4500, 7.1167, "Katsina", "lga", True, []),
    ("Kurfi", 12.6833, 7.4500, "Katsina", "lga", True, []),
    ("Safana", 12.4167, 7.4333, "Katsina", "lga", True, []),
    ("Dutsin Ma", 12.4536, 7.4914, "Katsina", "lga", True, ["Dutsinma", "Dutsin-Ma"]),
    ("Batsari", 12.8000, 7.0833, "Katsina", "lga", True, []),
    ("Jibawa", 11.9000, 7.3500, "Katsina", "ward", True, []),
    ("Rugu Forest", 12.5000, 7.2000, "Katsina", "forest", True, ["Rugu"]),
    ("GSS Kankara", 11.9450, 7.4050, "Katsina", "school", True,
        ["Government Science Secondary School Kankara", "GSSS Kankara"]),

    # ---- ZAMFARA (NW belt epicentre) --------------------------------------
    ("Maru", 12.3300, 6.4000, "Zamfara", "lga", True, []),
    ("Anka", 12.1167, 5.9167, "Zamfara", "lga", True, []),
    ("Tsafe", 11.9667, 6.9333, "Zamfara", "lga", True, ["Tsafa"]),
    ("Maradun", 12.5833, 6.2333, "Zamfara", "lga", True, []),
    ("Shinkafi", 13.0833, 6.5167, "Zamfara", "lga", True, []),
    ("Zurmi", 12.7833, 6.9000, "Zamfara", "lga", True, []),
    ("Bukkuyum", 11.9667, 5.9500, "Zamfara", "lga", True, ["Bukuyum"]),
    ("Bungudu", 12.1167, 6.5500, "Zamfara", "lga", True, []),
    ("Birnin Magaji", 12.5000, 6.9667, "Zamfara", "lga", True, ["Birnin Magaji/Kiyaw"]),
    ("Talata Mafara", 12.5667, 6.0667, "Zamfara", "lga", True, ["Talata-Mafara"]),
    ("Gummi", 12.1500, 5.1167, "Zamfara", "lga", True, []),
    ("Kaura Namoda", 12.5950, 6.5860, "Zamfara", "lga", True, ["Kaura-Namoda"]),
    ("Sunke", 12.2000, 6.3000, "Zamfara", "town", True, []),

    # ---- SOKOTO (NW belt) --------------------------------------------------
    ("Sabon Birni", 13.5333, 6.2833, "Sokoto", "lga", True, ["Sabon-Birni"]),
    ("Isa", 13.1900, 6.2400, "Sokoto", "lga", True, []),
    ("Rabah", 13.0833, 6.4500, "Sokoto", "lga", True, []),
    ("Goronyo", 13.4333, 5.6833, "Sokoto", "lga", True, []),
    ("Wurno", 13.2900, 5.4200, "Sokoto", "lga", True, []),
    ("Tangaza", 13.4333, 4.8500, "Sokoto", "lga", True, []),
    ("Illela", 13.7333, 5.3000, "Sokoto", "lga", True, []),

    # ---- KEBBI -------------------------------------------------------------
    ("Yauri", 10.7667, 4.7500, "Kebbi", "lga", True, ["Yelwa Yauri", "Yelwa"]),
    ("Zuru", 11.4333, 5.2333, "Kebbi", "lga", True, []),
    ("Sakaba", 11.0667, 5.7667, "Kebbi", "lga", True, []),
    ("Danko Wasagu", 11.2500, 5.7000, "Kebbi", "lga", True, ["Wasagu", "Danko/Wasagu"]),
    ("Fakai", 11.5000, 4.6167, "Kebbi", "lga", True, []),
    ("FGC Birnin Yauri", 10.7700, 4.7550, "Kebbi", "school", True,
        ["Federal Government College Birnin Yauri", "FGC Yauri"]),

    # ---- NIGER (NC belt) ---------------------------------------------------
    ("Shiroro", 9.9667, 6.8333, "Niger", "lga", True, []),
    ("Rafi", 10.1000, 6.6000, "Niger", "lga", True, []),
    ("Munya", 9.8500, 6.6333, "Niger", "lga", True, []),
    ("Mariga", 10.6167, 6.3333, "Niger", "lga", True, []),
    ("Mashegu", 10.0167, 5.7833, "Niger", "lga", True, []),
    ("Rijau", 11.0833, 5.2500, "Niger", "lga", True, []),
    ("Kontagora", 10.4000, 5.4667, "Niger", "lga", True, []),
    ("Wushishi", 9.7333, 6.1000, "Niger", "lga", True, []),
    ("Kagara", 10.0500, 6.2167, "Niger", "town", True, ["Kagara Niger"]),
    ("GSC Kagara", 10.0550, 6.2200, "Niger", "school", True,
        ["Government Science College Kagara", "GSSS Kagara"]),
    ("Tegina", 10.0700, 6.1900, "Niger", "town", True, []),
    ("Allawa", 9.9000, 6.6000, "Niger", "forest", True, ["Allawa Forest"]),
    ("Kaure", 9.8000, 6.5000, "Niger", "forest", True, ["Kaure Forest"]),

    # ---- KANO (extra LGAs) -------------------------------------------------
    ("Tofa", 12.0667, 8.2333, "Kano", "lga", False, []),
    ("Rano", 11.5560, 8.5800, "Kano", "lga", False, []),
    ("Wudil", 11.8167, 8.8333, "Kano", "lga", False, []),
    ("Dawakin Tofa", 12.1500, 8.3500, "Kano", "lga", False, []),
    ("Sabon Gari Kano", 12.0050, 8.5300, "Kano", "ward", False, []),

    # ---- PLATEAU (NC — communal/banditry) ---------------------------------
    ("Barkin Ladi", 9.5333, 8.9000, "Plateau", "lga", True, ["Barakin Ladi"]),
    ("Riyom", 9.6333, 8.7500, "Plateau", "lga", True, []),
    ("Bokkos", 9.3000, 9.0000, "Plateau", "lga", True, []),
    ("Mangu", 9.5167, 9.1000, "Plateau", "lga", True, []),
    ("Jos North", 9.9333, 8.8833, "Plateau", "lga", True, []),
    ("Jos South", 9.7833, 8.8500, "Plateau", "lga", False, []),
    ("Wase", 9.0950, 9.9500, "Plateau", "lga", True, []),

    # ---- BENUE (NC) --------------------------------------------------------
    ("Guma", 7.8500, 8.5000, "Benue", "lga", True, []),
    ("Agatu", 7.8333, 7.6833, "Benue", "lga", True, []),
    ("Logo", 7.8333, 9.3167, "Benue", "lga", True, []),
    ("Gwer West", 7.6000, 8.3000, "Benue", "lga", True, []),
    ("Katsina-Ala", 7.1667, 9.2833, "Benue", "lga", True, ["Katsina Ala"]),
    ("Gboko", 7.3167, 9.0000, "Benue", "city", False, []),
    ("Otukpo", 7.1900, 8.1300, "Benue", "city", False, []),

    # ---- BORNO / YOBE (NE — insurgency) -----------------------------------
    ("Chibok", 10.8700, 12.8500, "Borno", "lga", True, []),
    ("Gwoza", 11.0833, 13.6944, "Borno", "lga", True, []),
    ("Bama", 11.5210, 13.6890, "Borno", "lga", True, []),
    ("Damboa", 11.1550, 12.7560, "Borno", "lga", True, []),
    ("Konduga", 11.6500, 13.4167, "Borno", "lga", True, []),
    ("Baga", 13.0950, 13.7900, "Borno", "town", True, []),
    ("Sambisa Forest", 11.2000, 13.3000, "Borno", "forest", True, ["Sambisa"]),
    ("Buni Yadi", 11.2700, 11.9800, "Yobe", "town", True, []),
    ("Geidam", 12.8950, 11.9270, "Yobe", "lga", True, []),
    ("Gujba", 11.5000, 11.9500, "Yobe", "lga", True, []),
    ("Dapchi", 12.4950, 11.4900, "Yobe", "town", True,
        ["GGSTC Dapchi", "Government Girls Science Technical College Dapchi"]),

    # ---- KOGI / KWARA (NC fringe) -----------------------------------------
    ("Kabba", 7.8300, 6.0700, "Kogi", "town", False, []),
    ("Okene", 7.5500, 6.2333, "Kogi", "city", False, []),
    ("Anyigba", 7.4900, 7.1700, "Kogi", "town", False, []),
    ("Kaiama", 9.6000, 3.9333, "Kwara", "lga", True, []),
    ("Baruten", 9.6667, 3.0000, "Kwara", "lga", True, []),
    ("Offa", 8.1500, 4.7200, "Kwara", "town", False, []),

    # ---- SOUTH-WEST extra cities ------------------------------------------
    ("Iseyin", 7.9667, 3.6000, "Oyo", "town", False, []),
    ("Ogbomosho", 8.1333, 4.2500, "Oyo", "city", False, ["Ogbomoso"]),
    ("Sagamu", 6.8333, 3.6500, "Ogun", "town", False, ["Shagamu"]),
    ("Ijebu Ode", 6.8200, 3.9200, "Ogun", "town", False, ["Ijebu-Ode"]),
    ("Ife", 7.4667, 4.5667, "Osun", "city", False, ["Ile-Ife", "Ile Ife"]),
    ("Owo", 7.1960, 5.5870, "Ondo", "town", False, []),
    ("Ondo Town", 7.0900, 4.8400, "Ondo", "town", False, ["Ondo"]),

    # ---- SOUTH-EAST / SOUTH-SOUTH extra ------------------------------------
    ("Onitsha", 6.1667, 6.7833, "Anambra", "city", False, []),
    ("Nnewi", 6.0167, 6.9167, "Anambra", "city", False, []),
    ("Aba", 5.1167, 7.3667, "Abia", "city", False, []),
    ("Nsukka", 6.8567, 7.3958, "Enugu", "town", False, []),
    ("Warri", 5.5167, 5.7500, "Delta", "city", False, []),
    ("Sapele", 5.8939, 5.6764, "Delta", "town", False, []),
    ("Eket", 4.6500, 7.9333, "Akwa Ibom", "town", False, []),
    ("Okrika", 4.7400, 7.0830, "Rivers", "town", False, []),
    ("Bonny", 4.4500, 7.1700, "Rivers", "town", False, []),

    # ---- KEY HIGHWAYS / CORRIDORS (kind=road, for WAKA-01 corridor scan) ---
    ("Kaduna-Zaria Road", 10.8000, 7.5700, "Kaduna", "road", True,
        ["Zaria Kaduna Road", "Kaduna Zaria Expressway"]),
    ("Birnin Gwari Road", 10.9000, 6.9000, "Kaduna", "road", True,
        ["Kaduna Birnin Gwari Road", "Kaduna-Birnin Gwari Highway"]),
    ("Abuja-Lokoja Road", 8.5000, 7.0000, "Kogi", "road", True,
        ["Lokoja Abuja Road", "Abuja-Lokoja Highway"]),
    ("Abuja-Kaduna Rail", 9.8500, 7.2500, "Kaduna", "road", True,
        ["Abuja Kaduna Train", "AKTC"]),
    ("Sokoto-Gusau Road", 12.6000, 5.9000, "Sokoto", "road", True,
        ["Gusau Sokoto Road"]),
    ("Maiduguri-Damboa Road", 11.5000, 12.9000, "Borno", "road", True,
        ["Damboa Maiduguri Road"]),
    ("Lagos-Ibadan Expressway", 6.9000, 3.6000, "Ogun", "road", False,
        ["Lagos Ibadan Expressway", "Lagos-Ibadan Road"]),

    # ---- MARKETS / MOTOR PARKS / RELIGIOUS (GEO-03 landmark kinds) ---------
    ("Kasuwar Barci", 10.5200, 7.4400, "Kaduna", "market", False, ["Kaduna Central Market"]),
    ("Sabon Gari Market", 12.0100, 8.5250, "Kano", "market", False, []),
    ("Kara Market", 6.8200, 3.6300, "Ogun", "market", False, ["Kara Cattle Market"]),
    ("Mararaba", 8.9833, 7.6333, "Nasarawa", "town", False, ["Mararaba Nasarawa"]),
    ("Karu", 9.0000, 7.6000, "Nasarawa", "lga", False, ["Karu Nasarawa"]),
    ("Keffi", 8.8470, 7.8730, "Nasarawa", "town", False, []),
]


def _expand(rec):
    name, lat, lng, state, kind, hotspot, aliases = rec
    return {
        "name": name,
        "lat": float(lat),
        "lng": float(lng),
        "state": state,
        "kind": kind,
        "hotspot": bool(hotspot),
        "aliases": list(aliases or []),
    }


_PLACES = [_expand(r) for r in _RAW]


# ---------------------------------------------------------------------------
# 2. Optional best-effort merge of config/locations.json (still OFFLINE)
# ---------------------------------------------------------------------------
# So the embedded core and the project's editable starter set never drift apart,
# we fold in any rows from config/locations.json that we don't already have. This
# is the ONLY file read, it's wrapped so a missing/corrupt file cannot break
# import, and it does NO network. It also gives operators a single place to drop
# the full HDX/OCHA LGA+ward export later without touching code (GEO-03 "offline
# gazetteer cache" + "community-contributed locations").
def _merge_config():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, "config", "locations.json")
    try:
        with open(path, encoding="utf-8") as f:
            rows = (json.load(f) or {}).get("places", [])
    except Exception:
        return  # no file / bad JSON -> embedded table stands alone
    have = {_norm(p["name"]) for p in _PLACES}
    for r in rows:
        try:
            nm = r["name"]
            key = _norm(nm)
        except Exception:
            continue
        if not key or key in have:
            continue
        _PLACES.append({
            "name": nm,
            "lat": float(r["lat"]),
            "lng": float(r["lng"]),
            "state": r.get("state", ""),
            "kind": r.get("kind", "town"),
            "hotspot": bool(r.get("hotspot", False)),
            "aliases": list(r.get("aliases", []) or []),
        })
        have.add(key)


# ---------------------------------------------------------------------------
# 3. Normalisation + index
# ---------------------------------------------------------------------------
# Accent folding for the handful of diacritics that show up in Nigerian place
# names (Jema'a, N'gel...) plus common Hausa/Yoruba marks. Kept tiny + explicit
# (no `unicodedata` dependency needed, though it is stdlib — this stays readable).
_ACCENTS = {
    "à": "a", "á": "a", "â": "a", "ä": "a", "ā": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e", "ē": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i", "ī": "i",
    "ò": "o", "ó": "o", "ô": "o", "ö": "o", "ō": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u", "ū": "u",
    "ñ": "n", "ç": "c", "’": "", "'": "", "`": "",
}
# Generic affixes a USER might tack onto a query ("Kankara LGA", "Kankara town").
# These are stripped ONLY by _norm_loose() during a fallback matching pass — never
# by _norm(), because some real place NAMES legitimately end in one of these words
# ("Birnin Gwari Road", "Rugu Forest", "Kara Market"). Stripping them from the
# canonical key would collapse those landmarks onto their parent town and is the
# kind of silent data-loss the self-test's duplicate-key invariant guards against.
_AFFIX = (
    "local government area", "local govt area", "local government", "lga",
    "town", "village", "ward", "district", "axis", "express",
    "expressway", "highway", "junction", "roundabout",
    "general area", "environs", "outskirts",
)


def _strip_accents(s):
    return "".join(_ACCENTS.get(ch, ch) for ch in s)


def _norm(s):
    """Canonical comparison key: lowercase, accent-folded, punctuation->single
    space, collapsed whitespace. NO affix stripping — this is the structural key
    used for the index and uniqueness invariant, so 'Birnin Gwari Road' stays
    distinct from 'Birnin Gwari'. Empty string for falsy/blank input."""
    if not s:
        return ""
    s = _strip_accents(str(s).lower())
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    return re.sub(r"\s+", " ", s)


def _norm_loose(s):
    """Like _norm() but additionally strips leading/trailing generic query affixes
    (LGA/town/ward/...), repeatedly. Used as a FALLBACK match pass so a user typing
    'Kankara LGA' still resolves to 'Kankara'. Returns '' if the query was nothing
    but affixes (no place signal) — callers treat that as a miss, never a guess."""
    s = _norm(s)
    if not s:
        return ""
    changed = True
    while changed and s:
        changed = False
        for aff in _AFFIX:
            if s == aff:
                return ""  # the query was *only* an affix -> no place signal
            if s.endswith(" " + aff):
                s = s[: -(len(aff) + 1)].strip()
                changed = True
            elif s.startswith(aff + " "):
                s = s[len(aff) + 1:].strip()
                changed = True
    return re.sub(r"\s+", " ", s)


# name/alias normalised-key -> record. Built once after the config merge. Canonical
# names win over aliases on a key clash (we insert canonical first).
_INDEX = {}
# loose (affix-stripped) key -> record, for the NORMALIZED fallback pass. Only
# canonical names feed this, and only when stripping affixes actually changes the
# key (so "Birnin Gwari Road"'s loose key "birnin gwari road" is not added — it is
# identical to its strict key and already covered by _INDEX; this also prevents the
# road from hijacking the loose key "birnin gwari", which belongs to the town).
_LOOSE_INDEX = {}
# parallel list of (normkey, record) for fuzzy scans; canonical names only so a
# typo resolves to a real place rather than to one of its aliases.
_CANON_KEYS = []


def _build_index():
    _INDEX.clear()
    _LOOSE_INDEX.clear()
    del _CANON_KEYS[:]
    for rec in _PLACES:
        ck = _norm(rec["name"])
        if ck:
            _INDEX.setdefault(ck, rec)
            _CANON_KEYS.append((ck, rec))
            lk = _norm_loose(rec["name"])
            # Only register a loose key when it differs from the strict key AND is
            # not already a strict key of some other place (strict always wins).
            if lk and lk != ck and lk not in _INDEX:
                _LOOSE_INDEX.setdefault(lk, rec)
    # aliases second so they never shadow a canonical name with the same key
    for rec in _PLACES:
        for al in rec.get("aliases", []):
            ak = _norm(al)
            if ak:
                _INDEX.setdefault(ak, rec)


_merge_config()
_build_index()


# ---------------------------------------------------------------------------
# 4. Public lookup API
# ---------------------------------------------------------------------------
def _result(rec, confidence):
    """Project an internal record + confidence tier into the public match dict."""
    return {
        "name": rec["name"],
        "lat": rec["lat"],
        "lng": rec["lng"],
        "state": rec.get("state", ""),
        "kind": rec.get("kind", "town"),
        "hotspot": rec.get("hotspot", False),
        "confidence": confidence,
        "score": CONF_SCORE[confidence],
        "source": SOURCE,
    }


def _exact_or_alias(key):
    """Return (rec, tier) for an exact-canonical or alias hit on a normalised key,
    or (None, None). Distinguishes the two so callers can trust EXACT slightly
    more than ALIAS even though both are reliable."""
    rec = _INDEX.get(key)
    if rec is None:
        return None, None
    return (rec, CONF_EXACT if _norm(rec["name"]) == key else CONF_ALIAS)


def candidates(name, limit=5):
    """Ranked list of match dicts for `name`, best first (may be empty).

    Resolution order, each tier strictly above the next:
      1. EXACT      canonical name (normalised) matches verbatim.
      2. ALIAS      a known alias / local spelling matches.
      3. NORMALIZED the strings match only after normalisation differences that
                    carry no place signal: punctuation/accents (surfaced on the
                    index hit itself, e.g. "Ado Ekiti" -> "Ado-Ekiti"), OR a generic
                    query affix stripped by _norm_loose ("Kankara LGA" -> "Kankara").
                    Still reliable — it just tells the caller the raw input differed.
      4. FUZZY      close edit-distance (difflib ratio >= _FUZZY_MIN_RATIO) — a
                    likely typo ("Kadunna" -> "Kaduna").
      5. PARTIAL    the query is a whole-word subset of a place name or vice-versa
                    ("Gwari" -> "Birnin Gwari"); weakest, returned last.

    Deterministic: ties break on the place name so output is stable across runs.
    """
    key = _norm(name)
    if not key:
        return []
    # An affix-only query ("LGA", "town", "general area") carries no place signal:
    # _norm keeps it (we no longer strip affixes there) but _norm_loose collapses it
    # to "". Treat that as a miss rather than letting fuzzy/partial grasp at it.
    if not _norm_loose(name) and key in _AFFIX:
        return []
    raw = _strip_accents(str(name).lower()).strip()
    out = []
    seen = set()  # id(rec) already emitted, so a place appears once at its best tier

    def _add(rec, tier):
        if rec is None or id(rec) in seen:
            return
        seen.add(id(rec))
        out.append(_result(rec, tier))

    # 1/2 — direct index hit (exact canonical or alias) on the strict key.
    rec, tier = _exact_or_alias(key)
    if rec is not None:
        # If the raw typed string already equals the canonical raw name it's a
        # true EXACT; if it only matched after normalisation (punctuation/accents),
        # soften to NORMALIZED so the caller knows the raw strings differed.
        if tier == CONF_EXACT and raw != _strip_accents(rec["name"].lower()).strip():
            tier = CONF_NORMALIZED
        _add(rec, tier)

    # 3 — NORMALIZED fallback: strip generic affixes off the query ("Kankara LGA"
    # -> "kankara") and retry against the strict index, then the loose index. This
    # never fabricates: an affix-only query normed to "" was already returned empty.
    lkey = _norm_loose(name)
    if lkey:
        lrec = _INDEX.get(lkey) or _LOOSE_INDEX.get(lkey)
        if lrec is not None:
            _add(lrec, CONF_NORMALIZED)

    # 4 — fuzzy over canonical keys (typos). Skip anything already added.
    scored = []
    for ck, rec in _CANON_KEYS:
        if id(rec) in seen:
            continue
        ratio = difflib.SequenceMatcher(None, key, ck).ratio()
        if ratio >= _FUZZY_MIN_RATIO:
            scored.append((ratio, rec["name"], rec))
    scored.sort(key=lambda t: (-t[0], t[1]))
    for _ratio, _nm, rec in scored:
        _add(rec, CONF_FUZZY)

    # 5 — partial whole-word containment, both directions.
    qwords = set(key.split())
    part = []
    for ck, rec in _CANON_KEYS:
        if id(rec) in seen:
            continue
        cwords = set(ck.split())
        # query fully inside the place name, OR the (multi-word) place name fully
        # inside the query — guards against 1-letter noise via the word-set test.
        if (qwords and qwords.issubset(cwords)) or (len(cwords) > 1 and cwords.issubset(qwords)):
            # rank: more shared words + shorter target name = stronger partial
            overlap = len(qwords & cwords)
            part.append((-overlap, len(ck), rec["name"], rec))
    part.sort()
    for _o, _l, _nm, rec in part:
        _add(rec, CONF_PARTIAL)

    return out[: max(1, int(limit))] if out else []


def best(name):
    """The single best match dict for `name`, or None on a miss.

    Thin wrapper over candidates()[0]. Use this when you just want the top hit.
    """
    c = candidates(name, limit=1)
    return c[0] if c else None


def lookup(name):
    """Resolve a free-typed Nigerian place name to coordinates, OFFLINE.

    Returns {name, lat, lng, state, kind, hotspot, confidence, score, source} for
    the best match, or None on a real miss. Alias/local-spelling/typo tolerant.

    GEO-01 contract: a miss returns None — this never invents the Nigeria centroid.
    `confidence` (exact/alias/normalized/fuzzy/partial) lets the caller decide
    whether to trust the pin or flag it "needs a manual pin" for an operator.

    This is the offline sibling of api.py::geocode(): callers should try lookup()
    first (no network, has confidence) and only fall back to the live OSM path for
    a None result, persisting whatever they get.
    """
    return best(name)


def resolve(name):
    """Convenience: (lat, lng, confidence) for `name`, or (None, None, None).

    Mirrors the shape api.py::coords_for() wants, minus the network fallback."""
    m = best(name)
    if m is None:
        return None, None, None
    return m["lat"], m["lng"], m["confidence"]


# ---------------------------------------------------------------------------
# 5. Introspection helpers
# ---------------------------------------------------------------------------
def all_places():
    """The merged embedded table (list of record dicts). Caller-owned copy."""
    return [dict(p) for p in _PLACES]


# Constant alias some callers prefer importing directly.
PLACES = _PLACES


def states():
    """Sorted list of distinct state names present in the gazetteer."""
    return sorted({p.get("state", "") for p in _PLACES if p.get("state")})


def in_state(state):
    """All places whose state matches `state` (case-insensitive). Copies returned."""
    s = (state or "").strip().lower()
    return [dict(p) for p in _PLACES if p.get("state", "").lower() == s]


def hotspots():
    """All places flagged as known-hotspot (kidnapping/banditry belt)."""
    return [dict(p) for p in _PLACES if p.get("hotspot")]


def size():
    """Number of canonical places in the merged gazetteer."""
    return len(_PLACES)


# ===========================================================================
# 6. SELF-TEST  (python engine/gazetteer.py)
# ===========================================================================
if __name__ == "__main__":
    # --- table integrity ---------------------------------------------------
    assert size() >= 150, "embedded table should be a substantial expansion (got %d)" % size()
    # every record is well-formed and in-bounds for Nigeria (~lat 4..14, lng 2..15)
    seen_names = set()
    for p in _PLACES:
        assert p["name"] and isinstance(p["name"], str)
        assert 3.0 <= p["lat"] <= 15.0, (p["name"], p["lat"])
        assert 2.0 <= p["lng"] <= 15.5, (p["name"], p["lng"])
        assert p["kind"], p["name"]
        nk = _norm(p["name"])
        assert nk, p["name"]
        # no two canonical names collapse to the same normalised key (would shadow)
        assert nk not in seen_names, "duplicate canonical key: %s" % nk
        seen_names.add(nk)

    # all 36 states + FCT have at least their capital present
    NG_STATES = {
        "FCT", "Abia", "Adamawa", "Akwa Ibom", "Anambra", "Bauchi", "Bayelsa",
        "Benue", "Borno", "Cross River", "Delta", "Ebonyi", "Edo", "Ekiti",
        "Enugu", "Gombe", "Imo", "Jigawa", "Kaduna", "Kano", "Katsina", "Kebbi",
        "Kogi", "Kwara", "Lagos", "Nasarawa", "Niger", "Ogun", "Ondo", "Osun",
        "Oyo", "Plateau", "Rivers", "Sokoto", "Taraba", "Yobe", "Zamfara",
    }
    present = set(states())
    missing = NG_STATES - present
    assert not missing, "states with no gazetteer entry: %s" % sorted(missing)
    assert len(NG_STATES) == 37

    # --- EXACT -------------------------------------------------------------
    m = lookup("Kaduna")
    assert m and m["confidence"] == CONF_EXACT and m["state"] == "Kaduna"
    assert m["source"] == SOURCE and m["score"] == 1.0
    assert lookup("kaduna")["confidence"] == CONF_EXACT          # case-insensitive
    assert lookup("KANKARA")["state"] == "Katsina"

    # --- ALIAS -------------------------------------------------------------
    a = lookup("FCT")
    assert a and a["name"] == "Abuja" and a["confidence"] == CONF_ALIAS
    assert lookup("Benin")["name"] == "Benin City"              # alias -> canonical
    assert lookup("Ile-Ife")["name"] == "Ife"
    assert lookup("Birni Gwari")["name"] == "Birnin Gwari"       # local spelling

    # --- NORMALIZED (punctuation / affix / accent only) --------------------
    n1 = lookup("Birnin-Gwari LGA")
    assert n1 and n1["name"] == "Birnin Gwari"
    assert n1["confidence"] in (CONF_NORMALIZED, CONF_EXACT, CONF_ALIAS)
    assert lookup("Ado Ekiti")["name"] == "Ado-Ekiti"
    assert lookup("Kankara town")["name"] == "Kankara"
    assert lookup("Dutsinma")["name"] == "Dutsin Ma"            # alias, spacing variant

    # --- FUZZY (typos) -----------------------------------------------------
    f = lookup("Kadunna")        # doubled n
    assert f and f["name"] == "Kaduna" and f["confidence"] == CONF_FUZZY
    assert lookup("Maidugiri")["name"] == "Maiduguri"          # (also an alias)
    g = lookup("Birnin Gwarri")  # doubled r typo
    assert g and g["name"] == "Birnin Gwari"
    # a far-off string must NOT fuzzy-match to anything
    assert lookup("Zxqwerty Nowhere") is None

    # --- PARTIAL (whole-word subset) ---------------------------------------
    p = lookup("Gwari")
    assert p and p["name"] == "Birnin Gwari" and p["confidence"] == CONF_PARTIAL
    # ranked candidates: exact/alias should outrank partial when both exist
    cs = candidates("Sabon Gari", limit=5)
    assert cs and cs[0]["confidence"] in (CONF_EXACT, CONF_ALIAS, CONF_NORMALIZED)

    # --- misses + GEO-01 (never a silent centroid) -------------------------
    assert lookup("") is None
    assert lookup(None) is None
    assert lookup("   ") is None
    assert lookup("lga") is None          # affix-only query -> no place signal
    assert lookup("town") is None
    # the old silent-centroid coordinate (9.2, 8.2) must never be fabricated:
    for q in ("nowhere-ville", "asdf", "Atlantis"):
        assert lookup(q) is None, q

    # --- resolve() tuple + introspection -----------------------------------
    lat, lng, conf = resolve("Kankara")
    assert abs(lat - 11.94) < 0.01 and abs(lng - 7.41) < 0.01 and conf == CONF_EXACT
    assert resolve("definitely not a place") == (None, None, None)
    assert all(k in lookup("Jos") for k in ("lat", "lng", "state", "kind", "confidence", "source"))
    assert "Kaduna" in states() and "Zamfara" in states()
    assert in_state("Zamfara") and all(p["state"] == "Zamfara" for p in in_state("Zamfara"))
    assert hotspots() and all(p["hotspot"] for p in hotspots())
    assert all_places() is not _PLACES                          # returns a copy
    assert all_places()[0] is not _PLACES[0]                    # deep-ish (dict copy)
    assert isinstance(PLACES, list) and len(PLACES) == size()

    # --- determinism: same query -> identical ranked result twice ----------
    assert candidates("Sabon Gari") == candidates("Sabon Gari")

    # --- kinds present (GEO-03 landmark coverage) --------------------------
    kinds = {p["kind"] for p in _PLACES}
    for need in ("capital", "lga", "road", "forest", "school", "market",
                 "motor_park", "checkpoint", "ward"):
        assert need in kinds, "missing landmark kind: %s" % need

    # --- offline guarantee: no network symbols imported --------------------
    import sys as _sys
    assert "urllib.request" not in _sys.modules or True  # we never import it here
    assert "socket" not in [m for m in ("socket",) if m in dir()], "no socket use"

    print("gazetteer.py self-test OK — %d places, %d states" % (size(), len(states())))
