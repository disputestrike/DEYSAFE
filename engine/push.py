"""Web Push (VAPID) sender — the path that reaches an INSTALLED PWA on iOS 16.4+.

Pure stdlib cannot encrypt a Web Push payload (no AES-128-GCM / ECDH), so the
RFC 8291 encryption + VAPID signing is delegated to the optional `pywebpush`
package (see requirements.txt). Everything degrades gracefully: if the library
or the VAPID keys are absent, available() is False and send_one() returns an
"unconfigured" status instead of raising — real alerts still go out over SMS and
in-app, never blocked on push.

Env:
  DEYSAFE_VAPID_PUBLIC_KEY   base64url VAPID public key (also handed to the browser)
  DEYSAFE_VAPID_PRIVATE_KEY  base64url VAPID private key (secret)
  DEYSAFE_VAPID_SUBJECT      contact, e.g. mailto:safety@deysafe.app (has a default)

Generate a keypair once (locally, with py-vapid installed):
    pip install py-vapid && vapid --gen && vapid --applicationServerKey
The applicationServerKey value is DEYSAFE_VAPID_PUBLIC_KEY; the private key in
private_key.pem (or the base64url it prints) is DEYSAFE_VAPID_PRIVATE_KEY.
"""
import json
import os

ST_SENT = "sent"
ST_UNCONFIGURED = "unconfigured"
ST_FAILED = "failed"
ST_GONE = "expired"  # 404/410 from the push service -> subscription is dead


def _keys():
    return (os.environ.get("DEYSAFE_VAPID_PRIVATE_KEY", "").strip(),
            os.environ.get("DEYSAFE_VAPID_PUBLIC_KEY", "").strip())


def _subject():
    return os.environ.get("DEYSAFE_VAPID_SUBJECT", "").strip() or "mailto:safety@deysafe.app"


def _lib():
    try:
        from pywebpush import webpush  # type: ignore
        return webpush
    except Exception:
        return None


def library_present():
    return bool(_lib())


def configured_keys():
    priv, pub = _keys()
    return bool(priv and pub)


def available():
    """True only when BOTH the library and a VAPID keypair are present, i.e. we
    can actually deliver an encrypted push to a device right now."""
    return bool(_lib() and configured_keys())


def _is_real_endpoint(sub):
    ep = str((sub or {}).get("endpoint", ""))
    return bool(ep) and not ep.startswith("local-permission://") and not (sub or {}).get("permission_only")


def send_one(subscription, title, body, url="/", ttl=900):
    """Send ONE encrypted Web Push. `subscription` is the dict the browser produced
    ({endpoint, keys:{p256dh, auth}}) or its JSON string. Returns (ok, status, error).
    Never raises — the caller's alert path must not depend on push succeeding."""
    if isinstance(subscription, str):
        try:
            subscription = json.loads(subscription)
        except Exception:
            return False, ST_FAILED, "bad subscription json"
    if not _is_real_endpoint(subscription):
        return False, ST_UNCONFIGURED, "permission-only subscription (no push endpoint)"
    webpush = _lib()
    priv, pub = _keys()
    if not webpush:
        return False, ST_UNCONFIGURED, "pywebpush not installed"
    if not (priv and pub):
        return False, ST_UNCONFIGURED, "VAPID keys not configured"
    payload = json.dumps({"title": str(title)[:120], "body": str(body)[:400], "url": url})
    try:
        webpush(subscription_info=subscription, data=payload,
                vapid_private_key=priv, vapid_claims={"sub": _subject()}, ttl=ttl)
        return True, ST_SENT, None
    except Exception as e:
        code = getattr(getattr(e, "response", None), "status_code", None)
        if code in (404, 410):
            return False, ST_GONE, "subscription expired"
        return False, ST_FAILED, ("%s" % e)[:300]


def broadcast(subscriptions, title, body, url="/"):
    """Best-effort fan-out to many subscriptions. Returns {sent, failed, expired,
    skipped, expired_ids}. Expired ids let the caller prune dead subscriptions."""
    stats = {"sent": 0, "failed": 0, "expired": 0, "skipped": 0, "expired_ids": []}
    if not available():
        stats["skipped"] = len(subscriptions or [])
        return stats
    for s in (subscriptions or []):
        sub = s.get("subscription_json") if isinstance(s, dict) else s
        ok, status, _err = send_one(sub, title, body, url=url)
        if ok:
            stats["sent"] += 1
        elif status == ST_GONE:
            stats["expired"] += 1
            if isinstance(s, dict) and s.get("sub_uuid"):
                stats["expired_ids"].append(s.get("sub_uuid"))
        elif status == ST_UNCONFIGURED:
            stats["skipped"] += 1
        else:
            stats["failed"] += 1
    return stats
