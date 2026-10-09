"""Threat-intelligence correlation.

Matches extracted IOCs against:
  1. a bundled starter feed (data/ti_feed.json),
  2. the analyst-maintained custom watchlist (SQLite),
  3. optionally AbuseIPDB for IP reputation when an API key is supplied.

The feed is intentionally small and documented — drop in a larger feed
(OpenPhish, PhishTank, URLhaus, AlienVault OTX exports) using the same JSON
shape and everything below picks it up automatically.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from storage import custom_ioc_set

FEED_PATH = Path(__file__).parent.parent / "data" / "ti_feed.json"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
USER_AGENT = "phishing-detection-system/1.0"

_feed_cache: list[dict] | None = None


def load_feed() -> list[dict]:
    global _feed_cache
    if _feed_cache is None:
        try:
            _feed_cache = json.loads(FEED_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _feed_cache = []
    return _feed_cache


def reload_feed() -> list[dict]:
    global _feed_cache
    _feed_cache = None
    return load_feed()


def _type_of(ioc: str) -> str:
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if "://" in ioc:
        return "url"
    if "@" in ioc and "." in ioc.rsplit("@", 1)[-1]:
        return "email"
    if ioc.count(".") >= 1:
        return "domain"
    return "other"


def _matches_domain(ioc: str, entry_val: str) -> bool:
    """Subdomain / parent-domain tolerant match for domains and URLs."""
    host = ioc
    if "://" in ioc:
        host = urllib.parse.urlparse(ioc).hostname or ioc
    host = host.lower().strip(".")
    entry = entry_val.lower().strip(".")
    return host == entry or host.endswith("." + entry) or entry.endswith("." + host)


def check_indicators(indicators: list[str], abuseipdb_key: str = "") -> dict:
    """Return matches for a list of indicator strings."""
    feed = load_feed()
    custom = custom_ioc_set()
    matches: list[dict] = []
    checked: list[str] = []
    ip_reputations: list[dict] = []

    for raw in indicators:
        ioc = (raw or "").strip()
        if not ioc or ioc in checked:
            continue
        checked.append(ioc)
        ioc_type = _type_of(ioc)

        for entry in feed:
            val = entry.get("indicator", "")
            entry_type = entry.get("type", "")
            hit = False
            if ioc_type == "ip" and entry_type == "ip" and "/" in val:
                try:
                    hit = ipaddress.ip_address(ioc) in ipaddress.ip_network(val, strict=False)
                except ValueError:
                    hit = False
            elif ioc_type == "ip" and entry_type == "ip":
                hit = ioc.lower() == val.lower()
            elif ioc_type == "url" and val.startswith("http"):
                hit = _matches_domain(ioc, val)
            elif ioc_type in ("url", "domain", "email") and ioc_type == entry_type:
                hit = _matches_domain(ioc, val)
            if hit:
                matches.append({
                    "indicator": ioc, "type": ioc_type,
                    "category": entry.get("category", "malicious"),
                    "confidence": entry.get("confidence", "medium"),
                    "source": entry.get("source", "bundled feed"),
                    "note": entry.get("note", ""),
                })

        if ioc_type in ("url", "domain", "email"):
            matched_custom = next(
                (w for w in custom if _matches_domain(ioc, w)), None)
            if matched_custom and not any(m["indicator"] == ioc for m in matches):
                matches.append({
                    "indicator": ioc, "type": ioc_type,
                    "category": "watchlist", "confidence": "high",
                    "source": "custom watchlist",
                    "note": f"Matched analyst watchlist entry '{matched_custom}'.",
                })

    # optional enrichment: AbuseIPDB reputation for IPv4 indicators
    if abuseipdb_key:
        for ioc in checked:
            try:
                ipaddress.ip_address(ioc)
            except ValueError:
                continue
            ip_reputations.append(_abuseipdb_check(ioc, abuseipdb_key))

    return {
        "checked": len(checked),
        "matches": matches,
        "feed_size": len(feed),
        "watchlist_size": len(custom),
        "ip_reputation": ip_reputations,
        "clean": not matches and not any(r.get("abusive") for r in ip_reputations),
    }


def _abuseipdb_check(ip: str, key: str) -> dict:
    qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 30})
    req = urllib.request.Request(
        f"{ABUSEIPDB_URL}?{qs}",
        headers={"Key": key, "Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))["data"]
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
        return {"ip": ip, "error": str(exc)}

    score = data.get("abuseConfidenceScore", 0)
    return {
        "ip": ip,
        "score": score,
        "abusive": score >= 25,
        "reports": data.get("totalReports", 0),
        "country": data.get("countryCode", "?"),
        "isp": data.get("isp", "?"),
        "source": "AbuseIPDB",
    }
