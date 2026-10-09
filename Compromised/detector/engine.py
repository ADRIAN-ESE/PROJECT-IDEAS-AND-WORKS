"""Rule-based phishing analysis engine.

The engine inspects five areas of an email and accumulates a risk score
(0-100). Each area contributes capped sub-scores so a single noisy section
cannot dominate the verdict.

    sender     - who it claims to come from
    urls       - links found in the body / subject
    content    - wording, tone, and social-engineering patterns
    attachments- risky file types
    headers    - SPF / DKIM / DMARC authentication results (raw headers)

Verdicts:  0-24 clean | 25-49 low risk | 50-74 suspicious | 75-100 phishing
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

from . import rules

URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?|ftp)://[^\s<>"'()]+      # fully qualified URL
      | (?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>"'()]+  # domain followed by a path
      | (?:[a-z0-9-]+\.)+[a-z]{2,}\?[^\s<>"'']+  # domain with query string
    )"""
)

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.I)

CATEGORY_CAPS = {"sender": 30, "urls": 35, "content": 30, "attachments": 15, "headers": 25}


@dataclass
class Finding:
    category: str
    severity: str          # high | medium | low
    points: int
    title: str
    detail: str


@dataclass
class AnalysisResult:
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    categories: dict[str, int] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    keywords_found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _host(url: str) -> str:
    raw = url.strip().rstrip(".,;:!?")
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urlparse(raw).hostname or ""
    except ValueError:
        return ""
    return host.lower().strip(".")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _domain_of(address: str) -> str:
    """Extract the domain from a 'Name <user@dom>' or plain address."""
    match = re.search(r"<([^>]+)>", address)
    if match:
        address = match.group(1)
    match = re.search(r"([a-z0-9._%+-]+)@([a-z0-9.-]+)", address, re.I)
    if match:
        return match.group(2).lower()
    return ""


def _display_name(address: str) -> str:
    match = re.match(r"\s*(.*?)\s*<", address)
    return match.group(1).strip('"\' ') if match else address.strip()


def _extract_urls(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;:!?") for m in URL_RE.finditer(text or "")]


def _match_keywords(text: str, keywords: list[str]) -> list[str]:
    lower = text.lower()
    return [kw for kw in keywords if kw in lower]


# ---------------------------------------------------------------------------
# category analysers
# ---------------------------------------------------------------------------

def _analyse_sender(sender: str, subject: str, urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if not sender.strip():
        findings.append(Finding("sender", "medium", 6, "No sender address",
                                "The email has no visible From address, which is common in forgeries."))
        return findings

    domain = _domain_of(sender)
    name = _display_name(sender)
    name_l = name.lower()
    blob = f"{name} {subject}".lower()

    # brand claimed in display name / subject but sending domain is unrelated
    for brand, official in rules.KNOWN_BRANDS.items():
        if brand in blob or brand in name_l.replace(" ", ""):
            if not any(domain == d or domain.endswith("." + d) for d in official):
                findings.append(Finding(
                    "sender", "high", 20,
                    f"Brand spoof: claims to be {brand.title()}",
                    f"Display name or subject mentions {brand.title()}, but the message "
                    f"comes from '{domain or 'an unknown domain'}' instead of "
                    f"{sorted(official)[0]}."))
            break  # one brand finding is enough

    if domain:
        if _is_ip(domain):
            findings.append(Finding("sender", "high", 14, "Sender uses a raw IP address",
                                    f"Legitimate organisations never send from an IP literal like {domain}."))
        elif domain in rules.DISPOSABLE_DOMAINS:
            findings.append(Finding("sender", "high", 14, "Disposable email provider",
                                    f"'{domain}' is a throwaway inbox service commonly used to mass-register accounts."))
        else:
            labels = domain.split(".")
            tld = labels[-1]
            if tld in rules.SUSPICIOUS_TLDS:
                findings.append(Finding("sender", "medium", 8, f"Risk-prone top-level domain '.{tld}'",
                                        f"'{domain}' uses a TLD frequently abused by phishing kits."))
            if len(labels) > 3:
                findings.append(Finding("sender", "medium", 6, "Deeply nested subdomain",
                                        f"'{domain}' has {len(labels) - 2} subdomain levels — a common "
                                        "trick to hide the real domain (e.g. paypal.secure-login.xyz)."))
            if sum(1 for l in labels[:-1] if "-" in l) >= 2:
                findings.append(Finding("sender", "low", 4, "Hyphen-heavy domain",
                                        f"'{domain}' contains multiple hyphenated labels, typical of look-alike domains."))

    # reply-to divergence
    return findings


def _analyse_urls(urls: list[str], blob: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for url in urls:
        host = _host(url)
        if not host or host in seen:
            continue
        seen.add(host)
        labels = host.split(".")

        if _is_ip(host):
            findings.append(Finding("urls", "high", 15, "Link points to a raw IP address",
                                    f"'{url[:80]}' resolves to a bare IP instead of a domain name."))
            continue

        if url.lower().startswith("http://"):
            findings.append(Finding("urls", "medium", 5, "Unencrypted http:// link",
                                    f"'{url[:80]}' sends data in plain text."))

        if "@" in url.split("://", 1)[-1].split("/", 1)[0] or re.search(r"https?://[^/]*@", url):
            findings.append(Finding("urls", "high", 12, "'@' sign hides the real destination",
                                    f"In '{url[:80]}' everything before '@' is ignored by the browser."))

        if any(host == s or host.endswith("." + s) for s in rules.URL_SHORTENERS):
            findings.append(Finding("urls", "medium", 8, "Shortened link",
                                    f"'{host}' hides the final destination of '{url[:60]}'."))

        if "xn--" in host or re.search(r"[^\x00-\x7f]", host):
            findings.append(Finding("urls", "high", 14, "Punycode / internationalised domain",
                                    f"'{host}' uses look-alike characters to imitate a trusted brand."))

        if len(labels) > 3:
            findings.append(Finding("urls", "medium", 7, "Overly deep subdomains",
                                    f"'{host}' buries the real registered domain behind "
                                    f"{len(labels) - 2} subdomain levels."))

        if labels[-1] in rules.SUSPICIOUS_TLDS:
            findings.append(Finding("urls", "medium", 6, f"Risk-prone '.{labels[-1]}' link domain",
                                    f"'{host}' uses a TLD commonly used by bulk phishing campaigns."))

        if len(url) > 120:
            findings.append(Finding("urls", "low", 4, "Extremely long link",
                                    "Long obfuscated URLs are used to hide the true destination."))

        if re.search(r"[a-z0-9+/]{30,}={0,2}", url, re.I):
            findings.append(Finding("urls", "medium", 6, "Base64-like blob in link",
                                    f"'{url[:70]}...' contains an encoded payload segment."))

        # brand referenced somewhere, but link host is not the brand's domain
        path_and_query = url.lower()
        for brand, official in rules.KNOWN_BRANDS.items():
            if brand in path_and_query and not any(
                host == d or host.endswith("." + d) for d in official
            ):
                findings.append(Finding(
                    "urls", "high", 15,
                    f"Link mentions {brand.title()} but points elsewhere",
                    f"'{url[:90]}' is not hosted on an official {brand.title()} domain."))
                break

        # near-miss domain names (paypa1, netfIix, account-verification.com style)
        root = labels[-2] if len(labels) >= 2 else host
        for brand in rules.KNOWN_BRANDS:
            if brand in ("google", "apple", "amazon"):
                continue  # too short / generic, causes noise
            if root != brand and _edit_distance(root, brand) <= 2 and len(brand) > 4:
                findings.append(Finding(
                    "urls", "high", 16, f"Look-alike domain of {brand.title()}",
                    f"'{host}' is a near-miss spelling of {brand.title()}."))
                break

    # brand mentioned in text with no matching brand link
    return findings


def _analyse_content(subject: str, body: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    found: list[str] = []
    text = f"{subject}\n{body}"
    lower = text.lower()

    buckets = [
        ("Urgency / pressure tactics", rules.URGENCY_KEYWORDS, 8,
         "Scammers manufacture panic so you act before thinking."),
        ("Credential harvesting language", rules.CREDENTIAL_KEYWORDS, 12,
         "The email asks you to confirm or re-enter account credentials."),
        ("Financial / reward bait", rules.FINANCIAL_KEYWORDS, 8,
         "Money, prizes, or payment requests are classic phishing lures."),
        ("Personal data request", rules.DATA_HARVEST_KEYWORDS, 10,
         "The sender asks for sensitive personal information over email."),
    ]

    for title, keywords, weight, detail in buckets:
        hits = _match_keywords(text, keywords)
        if hits:
            found.extend(hits)
            severity = "high" if weight >= 10 else "medium"
            findings.append(Finding(
                "content", severity, weight, title,
                f"{detail} Matched: {', '.join(hits[:4])}{'…' if len(hits) > 4 else ''}."))

    generic = _match_keywords(lower, rules.GENERIC_GREETINGS)
    if generic:
        found.extend(generic)
        findings.append(Finding("content", "low", 4, "Generic greeting",
                                "Mass-mailed phishing uses vague salutations instead of your name."))

    # link text vs anchor mismatch:  <a href="evil">paypal.com</a>
    for match in re.finditer(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", text, re.I | re.S):
        href, label = match.group(1), re.sub(r"<[^>]+>", "", match.group(2)).strip()
        if label and _host(href) and _host(label) and _host(href) != _host(label):
            findings.append(Finding(
                "urls", "high", 14, "Link text does not match its destination",
                f"'{label[:40]}' actually leads to '{_host(href)}'."))
            found.append(label)

    if "-----BEGIN" in text or "message id:" in lower:
        pass  # raw headers supplied; handled by header analysis

    return findings, found


def _analyse_attachments(attachments: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for name in attachments:
        name = name.strip()
        if not name:
            continue
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in rules.DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                "attachments", "high", rules.DANGEROUS_EXTENSIONS[ext],
                f"Dangerous attachment: {name}",
                f"'{ext}' files can execute code on your machine. Never open one you weren't expecting."))
        elif ext in rules.SUSPICIOUS_EXTENSIONS:
            findings.append(Finding(
                "attachments", "medium", rules.SUSPICIOUS_EXTENSIONS[ext],
                f"Unexpected attachment: {name}",
                f"'{ext}' files are commonly used to deliver malware or macro payloads."))
        else:
            findings.append(Finding(
                "attachments", "low", 3, f"Attachment present: {name}",
                "Attachments from unverified senders should always be treated with care."))
    return findings


def _analyse_headers(headers: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = headers.lower()
    if not lower.strip():
        return findings

    checks = [
        ("spf=fail", "high", 15, "SPF check failed",
         "The sending server is not authorised to send for this domain."),
        ("dkim=fail", "high", 12, "DKIM signature invalid",
         "The cryptographic signature does not match — the message was altered or forged."),
        ("dmarc=fail", "high", 12, "DMARC policy failed",
         "The domain owner explicitly rejects this message as unauthenticated."),
        ("dmarc=none", "low", 3, "DMARC set to 'none'",
         "The domain does not yet enforce authentication, so spoofing is easy."),
        ("received: from localhost", "medium", 6, "Relayed through localhost",
         "Message trace shows local relaying, which forged mail often exhibits."),
    ]
    for needle, severity, points, title, detail in checks:
        if needle in lower:
            findings.append(Finding("headers", severity, points, title, detail))

    auth = re.search(r"authentication-results:.*", headers, re.I)
    if auth and "spf=pass" not in auth.group(0).lower() and "dkim=pass" not in auth.group(0).lower():
        findings.append(Finding("headers", "medium", 6, "No passing authentication results",
                                "Neither SPF nor DKIM passed for this message."))
    return findings


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def analyze_email(payload: dict, extra_findings: list[Finding] | None = None) -> AnalysisResult:
    """Analyse a dict with keys: sender, subject, body, headers, attachments.

    ``extra_findings`` lets sibling modules (e.g. header forensics, threat
    intelligence) contribute findings that are scored and capped together
    with the engine's own.
    """
    sender = (payload.get("sender") or "").strip()
    subject = (payload.get("subject") or "").strip()
    body = (payload.get("body") or "").strip()
    headers = (payload.get("headers") or "").strip()
    attachments = payload.get("attachments") or []

    urls = _extract_urls(f"{subject}\n{body}\n{headers}")
    blob = f"{subject}\n{body}".lower()

    findings: list[Finding] = []
    findings += _analyse_sender(sender, subject, urls)
    findings += _analyse_urls(urls, blob)
    content_findings, keywords = _analyse_content(subject, body)
    findings += content_findings
    findings += _analyse_attachments(attachments)
    findings += _analyse_headers(headers)
    if extra_findings:
        findings += list(extra_findings)

    # deduplicate identical titles
    unique: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        key = (f.category, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    categories: dict[str, int] = {}
    for f in unique:
        cap = CATEGORY_CAPS.get(f.category, 25)
        categories[f.category] = min(cap, categories.get(f.category, 0) + f.points)

    score = min(100, sum(categories.values()))

    if score >= 75:
        verdict = "phishing"
    elif score >= 50:
        verdict = "suspicious"
    elif score >= 25:
        verdict = "low risk"
    else:
        verdict = "clean"

    unique.sort(key=lambda f: -f.points)
    return AnalysisResult(
        score=score,
        verdict=verdict,
        findings=unique,
        categories=categories,
        urls=urls,
        keywords_found=sorted(set(keywords)),
    )
