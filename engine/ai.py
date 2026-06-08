"""Real LLM incident classifier (Part 5 of the master doc). Standard library only.

Cerebras is PRIMARY with ROUND-ROBIN across up to 5 keys + failover on rate
limits/errors, so it won't time out under load. Gemini / Groq are alternatives.
KEY-GATED: returns None when no key is configured (caller uses rule-based geoparse).

Environment variables (set in Railway):
  CEREBRAS_API_KEY_1 .. CEREBRAS_API_KEY_5   round-robin pool (or single CEREBRAS_API_KEY)
  CEREBRAS_MODEL                              default: llama-3.3-70b (override if Cerebras renames it)
  GEMINI_API_KEY / GROQ_API_KEY               alternatives (free tiers)
"""
import os
import json
import time
import urllib.request
import urllib.error

SYSTEM = (
    "You are an intelligence analyst for a Nigerian public-safety platform. "
    "Read the text (English, Hausa, Yoruba, or Nigerian Pidgin) and extract structured "
    "incident data. Respond with ONLY valid JSON, no markdown, no preamble:\n"
    '{"is_incident": true/false, "incident_type": str or null, "location_text": str or null, '
    '"state": str or null, "victim_count": int or null, "vehicle_description": str or null, '
    '"direction": str or null, "summary": str, "urgency": "low|medium|high|critical", '
    '"confidence": 0.0-1.0}\n'
    "incident_type one of: kidnapping, banditry_attack, armed_robbery, missing_person, other."
)

MISSING_SYSTEM = (
    "You are an intake assistant for a Nigerian missing-person platform. From the "
    "report (English, Hausa, Yoruba, or Nigerian Pidgin) extract the case. Respond "
    "with ONLY valid JSON, no markdown, no preamble:\n"
    '{"name": str or null, "age": str or null, "count": int, "place": str or null, '
    '"exact_place": str or null, "hours_ago": number or null, "description": str, '
    '"vehicle": str or null, "clothing": str or null, "direction": str or null}\n'
    "place = nearest town/area; exact_place = the specific spot (school, market, road). "
    "count > 1 for a group/mass abduction (default 1). hours_ago = time since last seen."
)

_rr = [0]  # round-robin cursor across requests


def _cerebras_keys():
    ks = [os.environ.get("CEREBRAS_API_KEY_%d" % i) for i in range(1, 6)]
    ks = [k for k in ks if k]
    if not ks and os.environ.get("CEREBRAS_API_KEY"):
        ks = [os.environ["CEREBRAS_API_KEY"]]
    return ks


def provider():
    if _cerebras_keys():
        return "cerebras"
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("GROQ_API_KEY"):
        return "groq"
    return None


def available():
    return provider() is not None


def key_count():
    return len(_cerebras_keys())


def _post(url, payload, headers):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers=dict({"Content-Type": "application/json"}, **headers))
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _cerebras(text, system):
    keys = _cerebras_keys()
    if not keys:
        return None
    model = os.environ.get("CEREBRAS_MODEL", "llama-3.3-70b")
    n = len(keys)
    start = _rr[0] % n
    _rr[0] = (_rr[0] + 1) % n  # advance so load spreads across keys
    order = [keys[(start + j) % n] for j in range(n)]
    last = None
    for key in order:
        try:
            out = _post("https://api.cerebras.ai/v1/chat/completions", {
                "model": model, "temperature": 0.1, "max_tokens": 600,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": text}],
            }, {"Authorization": "Bearer " + key})
            return json.loads(out["choices"][0]["message"]["content"])
        except urllib.error.HTTPError as e:
            last = "HTTP %s" % e.code
            if e.code in (429, 408, 500, 502, 503):  # rate-limited / transient -> next key
                time.sleep(0.4)
            continue
        except Exception as e:
            last = repr(e)
            continue
    return {"error": "all cerebras keys exhausted", "detail": last, "model": model}


def _gemini(text, system):
    key = os.environ["GEMINI_API_KEY"]
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           "gemini-1.5-flash:generateContent?key=" + key)
    out = _post(url, {
        "contents": [{"parts": [{"text": system + "\n\nTEXT:\n" + text}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }, {})
    return json.loads(out["candidates"][0]["content"]["parts"][0]["text"])


def _groq(text, system):
    key = os.environ["GROQ_API_KEY"]
    out = _post("https://api.groq.com/openai/v1/chat/completions", {
        "model": "llama-3.3-70b-versatile", "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": text}],
    }, {"Authorization": "Bearer " + key})
    return json.loads(out["choices"][0]["message"]["content"])


def classify(text, system=SYSTEM):
    """Extract structured data via a real LLM, or None if no key is set."""
    p = provider()
    if not p:
        return None
    try:
        if p == "cerebras":
            return _cerebras(text, system)
        if p == "gemini":
            return _gemini(text, system)
        if p == "groq":
            return _groq(text, system)
    except Exception as e:
        return {"error": repr(e), "provider": p}


def extract_missing(text):
    """Extract a missing-person case from free text/speech, or None if no key."""
    return classify(text, MISSING_SYSTEM)


MEETING_SYSTEM = (
    "You are a safety assistant for a Nigerian personal-safety app (SafeMeet). From the "
    "user's spoken or typed description of a meeting they are about to attend (English, "
    "Hausa, Yoruba, Igbo, or Nigerian Pidgin), extract the details. Respond with ONLY "
    "valid JSON, no markdown, no preamble:\n"
    '{"meeting_type": "personal|date|transaction|business|other", "person_name": str or null, '
    '"person_phone": str or null, "place": str or null, "address": str or null, '
    '"expected_arrival": "HH:MM" or null, "expected_duration_min": int or null, '
    '"vehicle": str or null, "risk_factors": str or null, "user_notes": str}\n'
    "expected_arrival in 24h HH:MM. Infer meeting_type from context (buying/selling a "
    "thing = transaction, online/blind date = date, work/client/contract = business). "
    "place = the area/town; address = the specific street or building if stated."
)


def extract_meeting(text):
    """Extract a SafeMeet meeting from free text/speech, or None if no key."""
    return classify(text, MEETING_SYSTEM)
