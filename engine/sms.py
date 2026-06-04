"""Africa's Talking SMS/USSD channel — the basic-phone REACH (Ushahidi-style).

KEY-GATED: outbound send works only when AT_USERNAME + AT_API_KEY are set
(set them on Railway). Inbound SMS + USSD are parsed by the app regardless — no
key needed to RECEIVE — so the whole flow is testable without an account; only
sending replies/alerts needs the live credentials.
"""
import os
import json
import urllib.request
import urllib.parse
import urllib.error


def available():
    return bool(os.environ.get("AT_API_KEY") and os.environ.get("AT_USERNAME"))


def send(to, message):
    """Send an SMS via Africa's Talking. Returns {ok, ...}. No-ops (ok:False) with
    no key so callers never crash when the channel isn't configured."""
    if not available():
        return {"ok": False, "error": "AT not configured (set AT_USERNAME + AT_API_KEY)"}
    try:
        body = urllib.parse.urlencode({
            "username": os.environ["AT_USERNAME"], "to": to, "message": message,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.africastalking.com/version1/messaging", data=body,
            headers={"apiKey": os.environ["AT_API_KEY"],
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return {"ok": True, "resp": json.loads(r.read().decode("utf-8"))}
    except Exception as e:
        return {"ok": False, "error": repr(e)}
