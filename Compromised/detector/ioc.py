"""Indicator-of-Compromise (IOC) extraction.

Pulls actionable observables out of a message so they can be correlated with
threat intelligence, exported, or pasted into another tool:

    URLs · domains · IP addresses · email addresses · file hashes · phone nums?
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.I)
SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.I)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
URL_RE = re.compile(r"(?xi)\b((?:https?|ftp)://[^\s<>\"']+)")

EXCLUDE_DOMAINS = {"example.com", "example.org", "example.net", "w3.org", "schemas",
                   "microsoft.com", "purl.org", "openxmlformats.org",
                   "googleapis.com", "gstatic.com", "json-schema.org"}


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)}]\"'")


def extract_iocs(payload: dict, attachment_hashes: list[dict] | None = None) -> dict:
    """payload: {sender, subject, body, headers}."""
    text = "\n".join([
        payload.get("sender") or "",
        payload.get("subject") or "",
        payload.get("body") or "",
        payload.get("headers") or "",
    ])

    urls = sorted({_clean_url(u) for u in URL_RE.findall(text)})

    def _is_ip(value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    domains: set[str] = set()
    for u in urls:
        try:
            host = urlparse(u if "://" in u else "http://" + u).hostname
        except ValueError:
            host = None
        if host and not _is_ip(host):
            domains.add(host.lower().strip("."))
    for d in DOMAIN_RE.findall(text):
        dl = d.lower()
        if _is_ip(dl):
            continue
        if dl not in EXCLUDE_DOMAINS and not any(dl.endswith("." + x) for x in EXCLUDE_DOMAINS):
            domains.add(dl)

    ips = sorted({ip for ip in IP_RE.findall(text)
                  if all(0 <= int(part) <= 255 for part in ip.split("."))})
    emails = sorted({e.lower() for e in EMAIL_RE.findall(text)
                     if not any(x in e.lower() for x in ("example.", "sentry.", "w3.org"))})

    hashes: list[dict] = []
    seen: set[str] = set()
    for kind, pattern in (("sha256", SHA256_RE), ("sha1", SHA1_RE), ("md5", MD5_RE)):
        for h in pattern.findall(text):
            hl = h.lower()
            if hl not in seen and not (kind == "md5" and hl in {x["value"] for x in hashes}):
                seen.add(hl)
                hashes.append({"type": kind, "value": hl, "source": "message body"})
    for ah in (attachment_hashes or []):
        val = (ah.get("sha256") or "").lower()
        if val and val not in seen:
            seen.add(val)
            hashes.append({"type": "sha256", "value": val,
                           "source": f"attachment {ah.get('name', '?')}"})

    return {
        "urls": urls,
        "domains": sorted(domains),
        "ips": ips,
        "emails": emails,
        "hashes": hashes,
        "counts": {
            "urls": len(urls), "domains": len(domains), "ips": len(ips),
            "emails": len(emails), "hashes": len(hashes),
        },
    }
