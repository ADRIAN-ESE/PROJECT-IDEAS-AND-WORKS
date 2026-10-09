"""Analysis pipeline: composes the engine, header forensics, IOC extraction
and threat-intelligence correlation into a single report, plus .eml parsing."""

from __future__ import annotations

import email
import email.header
import email.utils
import hashlib
import re
from email import policy
from email.message import Message

from .engine import Finding, analyze_email
from .header_analysis import analyse_headers
from .ioc import extract_iocs
from .threat_intel import check_indicators

TI_POINTS = {"high": 18, "medium": 10, "low": 4}


# ------------------------------- .eml parsing ------------------------------

def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    parts = []
    for chunk, enc in email.header.decode_header(value):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(enc or "utf-8", "replace"))
        else:
            parts.append(chunk)
    return "".join(parts).strip()


def _body_of(msg: Message) -> str:
    plain, html = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        try:
            payload = part.get_content()
        except Exception:
            raw = part.get_payload(decode=True) or b""
            payload = raw.decode(part.get_content_charset() or "utf-8", "replace")
        if not isinstance(payload, str):
            continue
        if ctype == "text/plain" and not plain:
            plain = payload
        elif ctype == "text/html" and not html:
            html = payload
    return (plain or html).strip()


def parse_eml(raw: bytes) -> dict:
    """Parse a raw .eml file into analyzer fields + attachment hashes."""
    msg = email.message_from_bytes(raw, policy=policy.default)

    sender = _decode_header(msg.get("From"))
    to = _decode_header(msg.get("To"))
    subject = _decode_header(msg.get("Subject"))

    # keep the header block the analyzer can reason about
    header_names = ["From", "To", "Reply-To", "Return-Path", "Subject", "Date",
                    "Message-ID", "DKIM-Signature", "Authentication-Results",
                    "Received", "X-Originating-IP", "X-Mailer", "X-Priority"]
    header_lines = []
    for name in header_names:
        for value in msg.get_all(name, []):
            unfolded = re.sub(r"\n[ \t]+", " ", str(value))
            header_lines.append(f"{name}: {unfolded}")
    # include every Received hop (ordering preserved)
    headers = "\n".join(header_lines)

    body = _body_of(msg)

    attachments, hashes = [], []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        filename = _decode_header(filename)
        attachments.append(filename)
        data = part.get_payload(decode=True) or b""
        hashes.append({
            "name": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "content_type": part.get_content_type(),
        })

    return {
        "sender": sender,
        "subject": subject,
        "body": body,
        "headers": headers,
        "attachments": ", ".join(attachments),
        "attachment_hashes": hashes,
        "meta": {
            "to": to,
            "date": _decode_header(msg.get("Date")),
            "message_id": _decode_header(msg.get("Message-ID")),
            "attachment_count": len(attachments),
            "bytes": len(raw),
        },
    }


# ------------------------------ full report --------------------------------

def _ti_findings(matches: list[dict]) -> list[Finding]:
    if not matches:
        return []
    high = [m for m in matches if m.get("confidence") == "high"]
    medium = [m for m in matches if m.get("confidence") == "medium"]
    low = [m for m in matches if m.get("confidence") == "low"]
    out: list[Finding] = []

    def chunk(items, severity, label, extra=""):
        if not items:
            return
        sample = ", ".join(i["indicator"] for i in items[:3])
        out.append(Finding(
            "threatintel", severity, TI_POINTS.get(severity, 6),
            f"Threat intel match ({label}): {len(items)} indicator(s)",
            f"{sample}{'…' if len(items) > 3 else ''} matched the {label} feed. {extra}".strip()))

    chunk(high, "high", "known-malicious")
    chunk(medium, "medium", "suspicious")
    chunk(low, "low", "low-confidence")
    return out


def analyse_full(payload: dict, abuseipdb_key: str = "") -> dict:
    """Run every detection stage and return the complete report."""
    headers = payload.get("headers") or ""
    sender = payload.get("sender") or ""

    # stage 1: engine (sender, urls, content, attachments, auth headers)
    #          + header identity/routing forensics folded into the same scoring
    header_findings = analyse_headers(headers, sender, payload.get("body") or "")
    base = analyze_email(payload, extra_findings=header_findings)

    # stage 2: IOC extraction
    iocs = extract_iocs(payload, payload.get("attachment_hashes"))

    # stage 3: threat-intelligence correlation
    ti_input = iocs["urls"] + iocs["domains"] + iocs["ips"] + iocs["emails"]
    ti_input += [h["value"] for h in iocs["hashes"]]
    ti = check_indicators(ti_input, abuseipdb_key=abuseipdb_key)

    report = base.to_dict()

    # stage 4: fold TI matches into the score with their own category
    if ti["matches"]:
        ti_findings = _ti_findings(ti["matches"])
        existing_titles = {f["title"] for f in report["findings"]}
        added = [f for f in ti_findings if f.title not in existing_titles]
        if added:
            combined = analyze_email(payload, extra_findings=header_findings + added)
            report = combined.to_dict()

    report["iocs"] = iocs
    report["threat_intel"] = ti
    return report
