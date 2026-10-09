"""Static rules, word lists, and brand data used by the detection engine."""

# ---------------------------------------------------------------------------
# Phishing keyword buckets: (regex-free keyword, weight, message template)
# ---------------------------------------------------------------------------

URGENCY_KEYWORDS = [
    "immediately",
    "urgent",
    "act now",
    "within 24 hours",
    "expires today",
    "last warning",
    "final notice",
    "suspend",
    "suspended",
    "restrict",
    "limited time",
    "don't delay",
    "do not delay",
    "failure to respond",
    "unusual activity",
    "suspicious activity",
]

CREDENTIAL_KEYWORDS = [
    "verify your account",
    "confirm your password",
    "update your payment",
    "validate your identity",
    "click here to verify",
    "re-enter your password",
    "login details",
    "sign in immediately",
    "account will be closed",
    "password expires",
    "unlock your account",
    "confirm your identity",
]

FINANCIAL_KEYWORDS = [
    "wire transfer",
    "gift card",
    "bitcoin",
    "crypto",
    "tax refund",
    "unclaimed funds",
    "inheritance",
    "prize",
    "you have won",
    "lottery",
    "bank account",
    "credit card number",
    "social security",
    "ssn",
    "pin code",
]

DATA_HARVEST_KEYWORDS = [
    "reply with your",
    "send us your",
    "provide your full",
    "date of birth",
    "mother's maiden name",
    "security question",
    "backup email",
    "id document",
    "passport number",
]

GENERIC_GREETINGS = [
    "dear customer",
    "dear user",
    "dear sir",
    "dear member",
    "dear account holder",
    "to whom it may concern",
    "dear valued customer",
    "hi there",
]

# ---------------------------------------------------------------------------
# URL / domain intelligence
# ---------------------------------------------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "lnkd.in",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "temp-mail.org",
    "10minutemail.com", "yopmail.com", "sharklasers.com", "trashmail.com",
    "throwawaymail.com", "getnada.com", "dispostable.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "click", "link", "work", "loan", "country",
    "stream", "gq", "cf", "tk", "ml", "ga", "zip", "mov", "rest",
    "buzz", "monster", "cfd", "sbs", "quest", "night", "mom",
}

FREE_MAIL_PROVIDERS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
    "aol.com", "protonmail.com", "proton.me", "mail.com", "gmx.com",
    "zoho.com", "yandex.com", "live.com", "msn.com", "me.com",
}

# brand name -> set of official domains (used for spoof detection)
KNOWN_BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "apple": {"apple.com", "icloud.com", "itunes.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "windows.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonpay.com", "ssl-images-amazon.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "kraken": {"kraken.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com", "usps.gov"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steam.com"},
    "spotify": {"spotify.com"},
    "docuSign": {"docusign.com", "docusign.net"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
}

# ---------------------------------------------------------------------------
# Attachment risk
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS = {
    ".exe": 25, ".scr": 25, ".bat": 22, ".cmd": 22, ".ps1": 22,
    ".vbs": 22, ".js": 18, ".jse": 20, ".wsf": 20, ".jar": 18,
    ".msi": 25, ".dll": 22, ".iso": 18, ".img": 18, ".lnk": 22,
    ".reg": 20, ".hta": 20, ".apk": 18, ".pif": 22,
}

SUSPICIOUS_EXTENSIONS = {
    ".zip": 8, ".rar": 8, ".7z": 8, ".gz": 6,
    ".doc": 6, ".docm": 12, ".xls": 6, ".xlsm": 12, ".pptm": 12,
    ".pdf": 4, ".html": 8, ".htm": 8,
}

# ---------------------------------------------------------------------------
# Header authentication failure patterns (matched against raw headers)
# ---------------------------------------------------------------------------

HEADER_FAIL_PATTERNS = [
    ("spf", "spf=fail"),
    ("spf", "spf=hardfail"),
    ("dkim", "dkim=fail"),
    ("dmarc", "dmarc=fail"),
    ("dmarc", "dmarc=none"),  # no policy enforcement is still notable when combined
]

SUPPORT_PHRASES = [
    "contact our support team",
    "helpdesk",
    "technical support",
    "customer care",
]
