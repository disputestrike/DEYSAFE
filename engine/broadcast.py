"""Outbound broadcast channel adapter — the LAST-MILE send (BC-01/02/03).

This module is the single place the app fans a *verified* alert (or an SOS
trusted-circle notify) out to real people over real channels. It is the channel
layer only: persistence of delivery receipts lives in the db/api layer; here we
own the wire + a testable SIM mode.

CHANNELS
  - "sms"      reuses engine/sms.py (Africa's Talking). Real send only when
               AT_USERNAME + AT_API_KEY are set.
  - "whatsapp" stub for the WhatsApp Business API (not wired yet).
  - "push"     stub for web-push / OneSignal (not wired yet).

KEY-GATED (bright line: never fake a real send)
  A channel only performs a real send when its credentials are present. With no
  key it degrades cleanly to {"ok": False, "status": "unconfigured"} and never
  raises — exactly like sms.send() no-ops without AT keys. Callers can always
  call send() safely regardless of configuration.

SIM MODE (testable with no accounts)
  When env DEYSAFE_BROADCAST_SIM=1 (or =true/yes/on), every channel "delivers"
  to an in-process list SENT and returns ok with a generated delivery id. SIM
  deliveries are *explicitly* flagged: status == "sim_delivered" and sim == 1,
  so a simulated delivery can never be mistaken for a real one. The env var is
  read at call time (not import time) so tests/gates can toggle it per call.

Stdlib only. The api/db layer persists deliveries separately; recent()/record()
here are an in-process mirror for observability and the SIM gate.
"""
import os
import json
import time
import threading
import uuid
import urllib.request
import urllib.error

# Channels this adapter knows how to address. Priority order for fan-out and
# last-mile reach (BC-03): WhatsApp -> SMS -> push.
CHANNELS = ("whatsapp", "sms", "push")

# Status vocabulary returned by send() (mirrors what the db `deliveries` table
# records; keep these strings stable for the api/db layer).
ST_SIM = "sim_delivered"      # SIM mode: recorded to SENT, NOT a real send
ST_SENT = "sent"             # real send accepted by the provider
ST_FAILED = "failed"          # provider/transport error
ST_UNCONFIGURED = "unconfigured"  # no credentials for this channel (key-gated)

# In-process delivery log. Each entry is a dict (see _entry()). This is a mirror
# for tests/observability; the durable receipt store is the db `deliveries`
# table owned by the api/db layer.
SENT = []
_LOCK = threading.Lock()

# How many entries to keep in the in-process SENT mirror (newest wins). Keeps a
# long-running process from growing unbounded; the durable store is the db.
_MAX_SENT = int(os.environ.get("DEYSAFE_BROADCAST_LOG_MAX", "5000"))


def sim_enabled():
    """True when SIM mode is on (env DEYSAFE_BROADCAST_SIM truthy). Read live so
    tests can flip it between calls."""
    return os.environ.get("DEYSAFE_BROADCAST_SIM", "").strip().lower() in (
        "1", "true", "yes", "on")


def _new_id():
    """A fresh delivery id (uuid4 hex). Matches security.new_uuid()'s shape so
    ids are uniform across the codebase without importing it here."""
    return uuid.uuid4().hex


def available(channel):
    """True when `channel` can perform a REAL send right now (keys present).

    SIM mode does not count as "available" — SIM is a test substitute, not a
    configured channel. Callers wanting "will send() do *something*" should check
    `available(ch) or sim_enabled()`.
    """
    ch = (channel or "").strip().lower()
    if ch == "sms":
        try:
            import sms  # engine/sms.py, imported flatly like api.py does
            return bool(sms.available())
        except Exception:
            return False
    if ch == "whatsapp":
        # WhatsApp Business API: needs token + phone-number id (not wired yet).
        return bool(os.environ.get("WHATSAPP_TOKEN")
                    and os.environ.get("WHATSAPP_PHONE_ID"))
    if ch == "push":
        # Web push / OneSignal (not wired yet).
        return bool(os.environ.get("ONESIGNAL_API_KEY")
                    and os.environ.get("ONESIGNAL_APP_ID"))
    return False


def _entry(channel, to, message, ok, status, ident=None, sim=False, error=None,
           provider=None):
    """Build a normalized delivery record dict."""
    return {
        "id": ident,
        "channel": (channel or "").strip().lower(),
        "to": to,
        "message": message,
        "ok": bool(ok),
        "status": status,
        "sim": 1 if sim else 0,
        "provider": provider,
        "error": error,
        "ts": time.time(),
    }


def record(delivery):
    """Append a delivery record to the in-process SENT log (thread-safe, capped).

    Accepts a dict (as built by _entry / returned by send()). Returns the stored
    record. The api/db layer persists its own copy to the `deliveries` table;
    this is the channel-side mirror used by recent() and the SIM gate.
    """
    if not isinstance(delivery, dict):
        raise TypeError("delivery must be a dict")
    with _LOCK:
        SENT.append(delivery)
        # trim oldest if we exceeded the cap
        if len(SENT) > _MAX_SENT:
            del SENT[:len(SENT) - _MAX_SENT]
    return delivery


def recent(limit=50):
    """Return up to `limit` most-recent delivery records, newest first."""
    n = max(0, int(limit))
    with _LOCK:
        if n == 0:
            return []
        return list(reversed(SENT[-n:]))


def clear():
    """Empty the in-process SENT log (test hygiene)."""
    with _LOCK:
        SENT.clear()


def _send_sms_real(to, message):
    """Real SMS via engine/sms.py. Returns (ok, status, provider_resp, error)."""
    try:
        import sms
        r = sms.send(to, message)
    except Exception as e:  # import or unexpected failure — degrade, never raise
        return False, ST_FAILED, None, repr(e)
    if r.get("ok"):
        return True, ST_SENT, r.get("resp"), None
    # sms.send already no-ops cleanly with no key; surface its error verbatim.
    return False, ST_UNCONFIGURED, None, r.get("error")


def _send_whatsapp_real(to, message):
    """Real WhatsApp Business Cloud API send.

    Keys:
      WHATSAPP_TOKEN
      WHATSAPP_PHONE_ID
      WHATSAPP_GRAPH_VERSION optional, default v20.0
    """
    token = os.environ.get("WHATSAPP_TOKEN", "").strip()
    phone_id = os.environ.get("WHATSAPP_PHONE_ID", "").strip()
    if not token or not phone_id:
        return False, ST_UNCONFIGURED, None, "WHATSAPP_TOKEN/WHATSAPP_PHONE_ID not set"
    version = os.environ.get("WHATSAPP_GRAPH_VERSION", "v20.0").strip() or "v20.0"
    url = "https://graph.facebook.com/%s/%s/messages" % (version, phone_id)
    payload = {
        "messaging_product": "whatsapp",
        "to": str(to).strip().lstrip("+"),
        "type": "text",
        "text": {"body": str(message)[:4096], "preview_url": False},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            resp = json.loads(raw)
        except Exception:
            resp = {"raw": raw}
        ident = None
        if isinstance(resp, dict) and isinstance(resp.get("messages"), list) and resp["messages"]:
            ident = resp["messages"][0].get("id")
        return True, ST_SENT, {"id": ident, "response": resp}, None
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return False, ST_FAILED, None, "whatsapp http %s: %s" % (e.code, raw[:300])
    except Exception as e:
        return False, ST_FAILED, None, repr(e)


def _send_push_real(to, message):
    """Real OneSignal push send.

    Keys:
      ONESIGNAL_API_KEY
      ONESIGNAL_APP_ID

    `to` is a OneSignal player id by default. Prefix `external:` to target an
    external user id, e.g. external:family-123.
    """
    key = os.environ.get("ONESIGNAL_API_KEY", "").strip()
    app_id = os.environ.get("ONESIGNAL_APP_ID", "").strip()
    if not key or not app_id:
        return False, ST_UNCONFIGURED, None, "ONESIGNAL_API_KEY/ONESIGNAL_APP_ID not set"
    target = str(to).strip()
    payload = {"app_id": app_id, "contents": {"en": str(message)[:1900]}}
    if target.startswith("external:"):
        payload["include_external_user_ids"] = [target.split(":", 1)[1]]
    else:
        payload["include_player_ids"] = [target]
    req = urllib.request.Request(
        "https://onesignal.com/api/v1/notifications",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Basic " + key},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            resp = json.loads(raw)
        except Exception:
            resp = {"raw": raw}
        return True, ST_SENT, {"id": resp.get("id") if isinstance(resp, dict) else None,
                               "response": resp}, None
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return False, ST_FAILED, None, "onesignal http %s: %s" % (e.code, raw[:300])
    except Exception as e:
        return False, ST_FAILED, None, repr(e)


def send(channel, to, message):
    """Send `message` to `to` over `channel`. Returns a delivery record dict
    {id, channel, to, ok, status, sim, provider, error, ts} and appends it to
    the SENT log.

    Contract:
      - SIM mode (DEYSAFE_BROADCAST_SIM truthy): records a SENT entry flagged
        sim=1 / status="sim_delivered" and returns ok=True with a delivery id —
        for EVERY channel, so the broadcast/SOS/responder gates are testable
        with no accounts. This is never a real send.
      - Otherwise the channel is KEY-GATED: a real send only happens when its
        credentials are present; with no key it returns ok=False /
        status="unconfigured" and does not raise.
    """
    ch = (channel or "").strip().lower()
    if ch not in CHANNELS:
        rec = _entry(ch, to, message, ok=False, status=ST_FAILED,
                     error="unknown channel %r" % channel)
        return record(rec)

    if not to:
        rec = _entry(ch, to, message, ok=False, status=ST_FAILED,
                     error="missing recipient")
        return record(rec)

    # --- SIM MODE: deliver to the in-process log, explicitly flagged ----------
    if sim_enabled():
        rec = _entry(ch, to, message, ok=True, status=ST_SIM,
                     ident=_new_id(), sim=True, provider="sim")
        return record(rec)

    # --- REAL SEND (key-gated per channel) -----------------------------------
    if ch == "sms":
        ok, status, resp, err = _send_sms_real(to, message)
        rec = _entry(ch, to, message, ok=ok, status=status,
                     ident=((resp or {}).get("id") or _new_id() if ok else None), sim=False,
                     provider=("africastalking" if ok else None), error=err)
        return record(rec)

    if ch == "whatsapp":
        ok, status, resp, err = _send_whatsapp_real(to, message)
        rec = _entry(ch, to, message, ok=ok, status=status,
                     ident=((resp or {}).get("id") or _new_id() if ok else None),
                     sim=False, provider=("whatsapp_cloud" if ok else None), error=err)
        return record(rec)

    if ch == "push":
        ok, status, resp, err = _send_push_real(to, message)
        rec = _entry(ch, to, message, ok=ok, status=status,
                     ident=((resp or {}).get("id") or _new_id() if ok else None),
                     sim=False, provider=("onesignal" if ok else None), error=err)
        return record(rec)

    rec = _entry(ch, to, message, ok=False, status=ST_FAILED, sim=False,
                 error="unknown channel %r" % ch)
    return record(rec)


def fan_out(targets, message, channel="sms"):
    """Send `message` to many `targets` over one `channel`.

    `targets` is an iterable of recipient addresses (phone/handle/token), or of
    dicts carrying at least an address under "to"/"address"/"phone". Returns a
    summary dict {sent, failed, sim, total, deliveries} where `deliveries` is the
    list of per-recipient records from send().
    """
    deliveries = []
    sent = failed = sim = 0
    for t in (targets or []):
        if isinstance(t, dict):
            to = t.get("to") or t.get("address") or t.get("phone")
            ch = (t.get("channel") or channel)
        else:
            to, ch = t, channel
        rec = send(ch, to, message)
        deliveries.append(rec)
        if rec.get("sim"):
            sim += 1
        if rec.get("ok"):
            sent += 1
        else:
            failed += 1
    return {
        "total": len(deliveries),
        "sent": sent,
        "failed": failed,
        "sim": sim,
        "deliveries": deliveries,
    }


# --- self-test ---------------------------------------------------------------
if __name__ == "__main__":
    # Exercise SIM mode end-to-end with no real accounts configured.
    os.environ["DEYSAFE_BROADCAST_SIM"] = "1"
    clear()
    assert sim_enabled() is True

    # every known channel "delivers" in SIM mode, explicitly flagged
    for ch in CHANNELS:
        r = send(ch, "+2348000000000", "RED: avoid Kaduna-Abuja road now.")
        assert r["ok"] is True, r
        assert r["status"] == ST_SIM, r
        assert r["sim"] == 1, r
        assert r["id"] and len(r["id"]) == 32, r
        assert r["channel"] == ch, r

    # SENT log captured all three; recent() returns newest-first
    assert len(SENT) == len(CHANNELS), SENT
    rec = recent(2)
    assert len(rec) == 2 and rec[0]["ts"] >= rec[1]["ts"], rec

    # fan_out to a mixed list (bare address + dict-with-channel)
    summary = fan_out(["+2348111111111", {"to": "+2348222222222", "channel": "whatsapp"}],
                      "ORANGE: heightened risk near Birnin Gwari.", channel="sms")
    assert summary["total"] == 2 and summary["sent"] == 2 and summary["sim"] == 2, summary
    assert summary["deliveries"][1]["channel"] == "whatsapp", summary

    # unknown channel / missing recipient fail cleanly (recorded, ok False)
    bad = send("carrier-pigeon", "+2348000000000", "x")
    assert bad["ok"] is False and bad["status"] == ST_FAILED, bad
    nodest = send("sms", "", "x")
    assert nodest["ok"] is False and nodest["status"] == ST_FAILED, nodest

    # record() accepts a hand-built dict; clear() empties the log
    record(_entry("sms", "+10", "hi", ok=True, status=ST_SENT, ident=_new_id()))
    assert len(SENT) > 0
    clear()
    assert SENT == []

    # KEY-GATED with SIM OFF: real channels degrade to unconfigured, never raise,
    # never fabricate a delivery (no key in this test environment).
    os.environ["DEYSAFE_BROADCAST_SIM"] = "0"
    assert sim_enabled() is False
    clear()
    s = send("sms", "+2348000000000", "no-key path")
    # With no AT credentials, sms.send no-ops -> unconfigured, ok False, no id.
    if available("sms"):
        # If AT keys happen to be set in this env, we won't actually hit the wire
        # in a self-test; just assert we didn't crash and got a record.
        assert s["channel"] == "sms"
    else:
        assert s["ok"] is False and s["status"] == ST_UNCONFIGURED and not s["id"], s
    # whatsapp / push stubs are unconfigured with no keys
    if not available("whatsapp"):
        w = send("whatsapp", "+2348000000000", "no-key path")
        assert w["ok"] is False and w["status"] == ST_UNCONFIGURED, w
    if not available("push"):
        p = send("push", "player-id", "no-key path")
        assert p["ok"] is False and p["status"] == ST_UNCONFIGURED, p

    print("broadcast.py self-test OK")
