"""Deep email-header forensics.

Where the engine checks authentication results (SPF/DKIM/DMARC), this module
performs identity and routing forensics on the raw headers:

    * From / Reply-To / Return-Path / DKIM d= divergence
    * display-name vs. domain mismatch
    * origin (first public) IP extraction from the Received chain
    * suspicious routing / relaying patterns
    * missing or malformed standard headers
"""

from __future__ import annotations

import ipaddress
import re

from .engine import Finding, _domain_of, _display_name

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RECEIVED_RE = re.compile(r"^Received:\s*(.+)$", re.I | re.M | re.S)
PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "172.16.", "172.17.", "172.18.",
                    "169.254.", "0.", "::1", "fe80:", "fc", "fd")

MAILERS = {
    "phpmailer": "low", "pear mail": "low", "swift mailer": "low",
    "massmailer": "high", "ultimate bulk": "high", "atompark": "high",
    "sendblaster": "high", "gophish": "high", "setoutnow": "high",
}


def _header(headers: str, name: str) -> str:
    """Return a header value with continuation lines unfolded, '' when absent."""
    text = headers.replace("\r\n", "\n").replace("\r", "\n")
    match = re.search(rf"^{re.escape(name)}:[ \t]*(.*)$", text, re.I | re.M)
    if not match:
        return ""
    value = match.group(1)
    for line in text[match.end():].split("\n"):
        if line[:1] in (" ", "\t"):
            value += " " + line.strip()
        else:
            break
    return value.strip()


def _extract_ips(headers: str) -> list[str]:
    """All IPv4 addresses appearing in Received lines, origin-first."""
    ips: list[str] = []
    for line in headers.splitlines():
        if not line.lower().startswith("received:"):
            continue
        for ip in IP_RE.findall(line):
            if ip not in ips:
                ips.append(ip)
    # plus anything in X-Originating-IP /Authentication-Results
    for name in ("X-Originating-IP", "X-Source-IP"):
        m = re.search(rf"{name}:\s*\[?({IP_RE.pattern})\]?", headers, re.I)
        if m and m.group(1) not in ips:
            ips.append(m.group(1))
    return ips


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def analyse_headers(headers: str, sender: str, body: str) -> list[Finding]:
    findings: list[Finding] = []
    if not headers.strip():
        return findings

    from_addr = _header(headers, "From") or sender
    reply_to = _header(headers, "Reply-To")
    return_path = _header(headers, "Return-Path")
    x_mailer = _header(headers, "X-Mailer") or _header(headers, "X-Mailer")
    message_id = _header(headers, "Message-ID") or _header(headers, "Message-Id")
    date = _header(headers, "Date")
    received = _header(headers, "Received")

    from_dom = _domain_of(from_addr)
    from_name = _display_name(from_addr)

    # ---------------- identity divergence ----------------
    if reply_to:
        rt_dom = _domain_of(reply_to)
        if from_dom and rt_dom and rt_dom != from_dom:
            findings.append(Finding(
                "headers", "high", 15, "Reply-To differs from From domain",
                f"Replies go to '{reply_to}' while the message claims to come from "
                f"'{from_dom}'. This silently redirects your response to the attacker."))

    if return_path:
        rp = return_path.strip().strip("<>")
        rp_dom = _domain_of(rp) if "@" in rp else ""
        if from_dom and rp_dom and rp_dom != from_dom:
            findings.append(Finding(
                "headers", "medium", 8, "Return-Path differs from From domain",
                f"Bounces are routed to '{rp}' instead of '{from_dom}' — common in "
                "spoofed and look-alike-domain campaigns."))

    # DKIM d= tag vs From domain
    dkim = _header(headers, "DKIM-Signature")
    m = re.search(r"(?:^|\s)d=([^;\s]+)", dkim)
    if m and from_dom:
        dkim_dom = m.group(1).lower().strip(".")
        if dkim_dom != from_dom and not from_dom.endswith("." + dkim_dom):
            findings.append(Finding(
                "headers", "high", 10, "DKIM signing domain does not match From",
                f"Message signed by d={dkim_dom} but From claims {from_dom}."))

    # display name impersonation inside the header From
    if from_name and from_dom:
        name_tokens = set(re.findall(r"[a-z]{3,}", from_name.lower()))
        for brand in ("paypal", "apple", "microsoft", "google", "amazon",
                      "netflix", "facebook", "linkedin", "coinbase", "binance"):
            if any(brand in t or t in brand for t in name_tokens):
                findings.append(Finding(
                    "headers", "medium", 6, "Display name references a major brand",
                    f"'{from_name}' in the raw From header advertises {brand.title()} "
                    f"while the header domain is '{from_dom}'."))
                break

    # ---------------- routing forensics ----------------
    ips = _extract_ips(headers)
    public_ips = [ip for ip in ips if _is_public(ip)]
    if received and public_ips:
        origin = public_ips[-1]  # earliest hop listed last
        # private→public bounce suggests relaying through a local agent
        if any(ip.startswith(_PRIVATE_PREFIXES) for ip in ips):
            findings.append(Finding(
                "headers", "low", 4, "Mixed private/public relay chain",
                "The Received chain mixes RFC1918 and public addresses — often seen "
                "when forged mail is injected through a local relay."))
        if len(public_ips) >= 4:
            findings.append(Finding(
                "headers", "low", 3, "Long relay chain",
                f"{len(public_ips)} public hops — while not proof of abuse, deep chains "
                "are typical of bulk-sent mail."))

    if not received:
        findings.append(Finding(
            "headers", "medium", 6, "No Received headers",
            "Legitimate mail always records its routing path; absent Received lines "
            "suggest the headers were stripped or fabricated."))

    # ---------------- missing / odd standard headers ----------------
    missing = []
    if not message_id:
        missing.append("Message-ID")
    if not date:
        missing.append("Date")
    if missing:
        findings.append(Finding(
            "headers", "low", 3, "Missing standard header(s): " + ", ".join(missing),
            "Automated forgery kits frequently omit these headers."))

    if message_id:
        mid_dom = (re.search(r"@([a-z0-9.-]+)", message_id, re.I) or [None, ""])[1] \
            if re.search(r"@([a-z0-9.-]+)", message_id, re.I) else ""
        mid_dom = mid_dom.lower()
        if mid_dom and from_dom and mid_dom != from_dom and not from_dom.endswith("." + mid_dom):
            findings.append(Finding(
                "headers", "low", 3, "Message-ID domain differs from From",
                f"Message-ID @{mid_dom} vs From {from_dom}."))

    # ---------------- client / bulk-sender signals ----------------
    if x_mailer:
        low = x_mailer.lower()
        for token, severity in MAILERS.items():
            if token in low:
                pts = 12 if severity == "high" else 6
                findings.append(Finding(
                    "headers", "high" if severity == "high" else "medium", pts,
                    f"Bulk/malicious mailer: {x_mailer}",
                    f"X-Mailer identifies '{x_mailer}', a tool associated with "
                    "bulk outreach or phishing campaigns."))
                break

    return findings
