"""Signal ingestion: synthetic samples (default) + optional live public RSS.

Live ingestion uses only PUBLIC news feeds. No private channels, no telecom,
no individual tracking. Failures per feed are skipped, not fatal.
"""
import json
import os
import re
import html
import datetime
import time
import urllib.request
import xml.etree.ElementTree as ET

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(BASE, "config")


def _iso_hours_ago(h):
    return (datetime.datetime.now() - datetime.timedelta(hours=h)).isoformat(timespec="seconds")


def load_samples():
    with open(os.path.join(CONFIG, "sample_signals.json"), encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for s in data["signals"]:
        out.append({
            "source_name": s["source"],
            "kind": "sample",
            "title": s.get("title", ""),
            "text": s.get("text", ""),
            "url": "",
            "lang": s.get("lang", "en"),
            "published_at": _iso_hours_ago(s.get("hours_ago", 1)),
        })
    return out


def _clean(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def _parse_date(s):
    s = (s or "").strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M %z"):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return dt.astimezone().replace(tzinfo=None).isoformat(timespec="seconds")
        except Exception:
            pass
    return datetime.datetime.now().isoformat(timespec="seconds")


def _env_int(name, default, floor=1, ceiling=1000):
    try:
        value = int(float(os.environ.get(name, "") or default))
    except Exception:
        value = default
    return max(floor, min(ceiling, value))


def fetch_rss(url, name, limit=25, timeout=8):
    out = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "deysafe/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            root = ET.fromstring(r.read())
        for it in root.findall(".//item")[:limit]:
            def g(tag):
                e = it.find(tag)
                return e.text if e is not None else ""
            out.append({
                "source_name": name, "kind": "rss",
                "title": _clean(g("title")), "text": _clean(g("description")),
                "url": g("link") or "", "lang": "en",
                "published_at": _parse_date(g("pubDate")),
            })
    except Exception as e:
        print("  [ingest] feed failed:", name, "->", repr(e))
    return out


def load_live(max_feeds=None, per_feed_timeout=None, limit_per_feed=None, deadline_seconds=None):
    """Fetch public RSS feeds with a hard practical budget.

    RSS is a best-effort public signal rail. It must never make an operator
    request hang just because one publisher is slow, so defaults are intentionally
    bounded and can be tuned in Railway with DEYSAFE_RSS_* environment variables.
    """
    with open(os.path.join(CONFIG, "sources.json"), encoding="utf-8") as f:
        srcs = json.load(f)["rss"]
    if max_feeds is None:
        max_feeds = _env_int("DEYSAFE_RSS_MAX_FEEDS", len(srcs), floor=1, ceiling=len(srcs))
    if per_feed_timeout is None:
        per_feed_timeout = _env_int("DEYSAFE_RSS_TIMEOUT_SECONDS", 3, floor=1, ceiling=20)
    if limit_per_feed is None:
        limit_per_feed = _env_int("DEYSAFE_RSS_LIMIT_PER_FEED", 12, floor=1, ceiling=50)
    if deadline_seconds is None:
        deadline_seconds = _env_int("DEYSAFE_RSS_DEADLINE_SECONDS", 30, floor=5, ceiling=120)

    start = time.monotonic()
    out = []
    for s in srcs[:max_feeds]:
        if time.monotonic() - start > deadline_seconds:
            print("  [ingest] deadline reached; skipping remaining feeds")
            break
        got = fetch_rss(s["url"], s["name"], limit=limit_per_feed, timeout=per_feed_timeout)
        print("  [ingest] {}: {} items".format(s["name"], len(got)))
        out.extend(got)
    return out


def gather(use_live=False, use_sample=True):
    sigs = []
    if use_sample:
        sigs += load_samples()
    if use_live:
        sigs += load_live()
    return sigs
