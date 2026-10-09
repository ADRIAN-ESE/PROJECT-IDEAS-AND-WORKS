"""Flask backend for the PhishGuard Compromised Email & Phishing Detection System.

Run:
    python app.py
then open http://127.0.0.1:5000

Core detection
    POST /api/analyze            full email analysis (engine + forensics + IOCs + TI)
    POST /api/parse-eml          upload a raw .eml / message file
    POST /api/activity           login & send-activity anomaly analysis
    POST /api/takeover           compromised-account assessment
    GET  /api/indicators         takeover-indicator catalogue

Investigation
    GET  /api/incidents          incident history (server-side)
    GET  /api/incidents/<id>     one incident with its full report
    POST /api/feedback           analyst true/false-positive verdict
    GET  /api/alerts             generated alerts
    PATCH /api/alerts/<id>       update alert status
    GET  /api/stats              dashboard statistics
    GET  /api/iocs               aggregated indicators from recent incidents

Threat intelligence
    GET  /api/ti/feed            bundled feed info
    POST /api/ti/check           check indicators against feed + watchlist
    POST /api/ti/add             add an indicator to the watchlist
    GET  /api/watchlist          analyst watchlist

Account exposure
    POST /api/password-check     k-anonymity HIBP password lookup
    POST /api/breach-check       HIBP account breach lookup (API key)

    GET  /api/health             liveness probe
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, request, send_from_directory, session
from werkzeug.exceptions import BadRequest, HTTPException

import storage
from detector import analyse_full, analyze_email, parse_eml
from detector.activity import analyse_activity
from detector.takeover import INDICATORS, assess_takeover
from detector.threat_intel import check_indicators, load_feed, reload_feed

app = Flask(__name__, static_folder="static", static_url_path="")
app.config.update(
    DEBUG=os.getenv("PHISHGUARD_DEBUG", "0").lower() in {"1", "true", "yes", "on"},
    HOST=os.getenv("PHISHGUARD_HOST", "127.0.0.1"),
    PORT=int(os.getenv("PHISHGUARD_PORT", "5000")),
    JSON_SORT_KEYS=False,
    SECRET_KEY=os.getenv("PHISHGUARD_SECRET_KEY", "change-me-in-production"),
)

APP_VERSION = "2.0.0"
ADMIN_USERNAME = os.getenv("PHISHGUARD_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("PHISHGUARD_ADMIN_PASSWORD", "phishguard")
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
BREACH_FALLBACK_URL = os.getenv("PHISHGUARD_BREACH_URL", "").strip()
BREACH_FALLBACK_API_KEY = os.getenv("PHISHGUARD_BREACH_API_KEY", "").strip()
USER_AGENT = f"phishing-detection-system/{APP_VERSION}"

storage.init_db()


def _json_payload(required: bool = False, *, allow_empty: bool = True):
    """Safely parse JSON with consistent validation for API routes."""
    if request.method in {"GET", "DELETE"}:
        if required:
            raise BadRequest("This endpoint requires a JSON body.")
        return {}

    if not request.data:
        if required:
            raise BadRequest("Request body is required.")
        return {}

    try:
        payload = request.get_json(force=False, silent=False)
    except BadRequest as exc:
        raise BadRequest("Invalid JSON payload.") from exc

    if payload is None:
        if required:
            raise BadRequest("JSON body is required.")
        if allow_empty:
            return {}
        return None

    if not isinstance(payload, dict):
        raise BadRequest("JSON body must be an object.")
    return payload


def _limit_arg(name: str, default: int, minimum: int = 1, maximum: int = 500) -> int:
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _admin_login_required(view_func):
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect("/admin/login")
        return view_func(*args, **kwargs)
    wrapped.__name__ = view_func.__name__
    return wrapped


def _breach_lookup_fallback(email_addr: str):
    if not BREACH_FALLBACK_URL:
        return {
            "provider": "offline-demo",
            "message": "No external breach provider configured. Configure PHISHGUARD_BREACH_URL to enable live lookups.",
            "breaches": [],
            "demo": True,
        }

    url = BREACH_FALLBACK_URL.format(account=urllib.parse.quote(email_addr))
    headers = {"User-Agent": USER_AGENT}
    if BREACH_FALLBACK_API_KEY:
        headers["Authorization"] = f"Bearer {BREACH_FALLBACK_API_KEY}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return {
            "provider": "fallback",
            "message": f"External breach provider lookup failed: {exc}",
            "breaches": [],
            "demo": False,
            "error": str(exc),
        }

    breaches = data if isinstance(data, list) else data.get("breaches", [])
    return {
        "provider": "fallback",
        "message": "Fallback breach provider returned records.",
        "breaches": breaches,
        "demo": False,
    }


@app.errorhandler(HTTPException)
def handle_http_exception(err: HTTPException):
    if err.code is not None and err.code >= 500:
        return jsonify({"error": "An unexpected server error occurred."}), 500
    return jsonify({"error": err.description or "Request failed."}), err.code or 400


@app.errorhandler(Exception)
def handle_unexpected_error(err: Exception):
    if app.debug:
        raise err
    return jsonify({"error": "An unexpected server error occurred."}), 500


@app.after_request
def security_headers(resp):
    """Baseline hardening headers for every response."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "connect-src 'self'"
    )
    return resp


def _new_id() -> str:
    return uuid.uuid4().hex[:12].upper()


def _raise_incident(incident_id: str, kind: str, title: str, score: int,
                    verdict: str, report: dict, inputs: dict | None = None,
                    alert_threshold: int = 50) -> bool:
    """Persist an incident and open an alert when the score crosses the bar."""
    storage.save_incident(incident_id, kind, title, score, verdict, report, inputs)
    if score >= alert_threshold and not storage.has_open_alert(incident_id):
        severity = "critical" if score >= 75 else "high" if score >= 60 else "medium"
        storage.create_alert(incident_id, severity, f"[{kind}] {title} — score {score}")
        return True
    return False


# ------------------------------- static UI ---------------------------------

@app.get("/")
def landing_page():
    return send_from_directory(app.static_folder, "landing.html")


@app.get("/app")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/dashboard")
def dashboard_redirect():
    return redirect("/app")


@app.get("/admin/login")
def admin_login_page():
    return send_from_directory(app.static_folder, "admin-login.html")


@app.get("/admin")
@_admin_login_required
def admin_console_page():
    return send_from_directory(app.static_folder, "admin-console.html")


@app.post("/api/admin/login")
def admin_login():
    data = _json_payload(required=False)
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["admin_authenticated"] = True
        session.permanent = True
        return jsonify({"ok": True, "redirect": "/admin"})
    return jsonify({"error": "Invalid administrator credentials."}), 401


@app.post("/api/admin/logout")
def admin_logout():
    session.pop("admin_authenticated", None)
    return jsonify({"ok": True})


@app.get("/api/admin/session")
def admin_session():
    return jsonify({"authenticated": bool(session.get("admin_authenticated"))})


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "version": APP_VERSION, "engine": "rule-based/6-stage"})


# ---------------------------- email analysis -------------------------------

@app.post("/api/analyze")
def analyze():
    payload = _json_payload(required=False)
    provided = [
        (payload.get(k) or "").strip()
        for k in ("sender", "subject", "body", "headers")
        if isinstance(payload.get(k), str)
    ]
    if not any(provided):
        return jsonify({"error": "Provide at least a sender, subject, body, or headers to analyse."}), 400

    attachments = payload.get("attachments") or []
    if isinstance(attachments, str):
        attachments = [a for a in (part.strip() for part in attachments.split(",")) if a]

    clean = {
        "sender": payload.get("sender", ""),
        "subject": payload.get("subject", ""),
        "body": payload.get("body", ""),
        "headers": payload.get("headers", ""),
        "attachments": attachments,
        "attachment_hashes": payload.get("attachment_hashes") or [],
    }

    report = analyse_full(clean)
    report["scan_id"] = _new_id()
    report["analyzed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["engine_version"] = APP_VERSION

    subject = clean["subject"] or "(no subject)"
    _raise_incident(report["scan_id"], "email", subject,
                    report["score"], report["verdict"], report, clean)
    return jsonify(report)


@app.post("/api/parse-eml")
def upload_eml():
    """Accept a raw .eml / message file and return analyzer-ready fields."""
    file = request.files.get("file") or (request.files and next(iter(request.files.values()), None))
    if file is None:
        return jsonify({"error": "No file uploaded."}), 400

    name = (file.filename or "message.eml").lower()
    if not any(name.endswith(ext) for ext in (".eml", ".msg", ".txt", ".eml.txt")):
        if file.mimetype not in ("message/rfc822", "text/plain", "text/html"):
            return jsonify({"error": "Upload an .eml (RFC 822) message file."}), 400

    raw = file.read()
    if len(raw) > 5 * 1024 * 1024:
        return jsonify({"error": "File too large (5 MB max)."}), 400

    try:
        parsed = parse_eml(raw)
    except Exception as exc:  # malformed messages should not 500
        return jsonify({"error": f"Could not parse message: {exc}"}), 422

    if not any([parsed["sender"], parsed["subject"], parsed["body"], parsed["headers"]]):
        return jsonify({"error": "The file contains no recognisable message content."}), 422

    parsed["filename"] = file.filename
    return jsonify(parsed)


# --------------------------- activity monitor ------------------------------

@app.post("/api/activity")
def activity():
    payload = _json_payload(required=True)
    logins = payload.get("logins") or []
    emails = payload.get("emails") or []
    if not isinstance(logins, list) or not isinstance(emails, list):
        return jsonify({"error": "'logins' and 'emails' must be arrays."}), 400
    if not logins and not emails:
        return jsonify({"error": "Provide login events, email events, or both."}), 400

    report = analyse_activity(payload)
    report["scan_id"] = _new_id()
    report["analyzed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["engine_version"] = APP_VERSION

    title = f"Activity review: {len(logins)} logins / {len(emails)} messages"
    _raise_incident(report["scan_id"], "activity", title,
                    report["score"], report["verdict"], report,
                    {"logins": logins, "emails": emails}, alert_threshold=60)
    return jsonify(report)


# ------------------------ compromised account ------------------------------

@app.get("/api/indicators")
def indicator_catalogue():
    return jsonify([
        {"key": k, "severity": v[1], "points": v[0], "title": v[2], "detail": v[3]}
        for k, v in INDICATORS.items()
    ])


@app.post("/api/takeover")
def takeover():
    payload = _json_payload(required=False)
    report = assess_takeover(payload)
    if not report["findings"] and not payload.get("indicators"):
        return jsonify({"error": "Select at least one indicator."}), 400

    report["scan_id"] = _new_id()
    report["analyzed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["engine_version"] = APP_VERSION

    _raise_incident(report["scan_id"], "takeover", "Account takeover assessment",
                    report["score"], report["verdict"], report,
                    {"indicators": payload.get("indicators")}, alert_threshold=50)
    return jsonify(report)


# ------------------------ incidents / alerts / stats -----------------------

@app.get("/api/incidents")
def incidents():
    limit = _limit_arg("limit", 50, minimum=1, maximum=500)
    return jsonify(storage.list_incidents(limit=limit))


@app.get("/api/incidents/<incident_id>")
def incident_detail(incident_id):
    row = storage.get_incident(incident_id)
    if not row:
        return jsonify({"error": "Incident not found."}), 404
    return jsonify(row)


@app.post("/api/feedback")
def feedback():
    data = _json_payload(required=False)
    incident_id = (data.get("incident_id") or "").strip()
    label = data.get("label")
    row = storage.set_feedback(incident_id, label)
    if not row:
        return jsonify({"error": "Unknown incident or invalid label (use 'tp' or 'fp')."}), 400
    return jsonify(row)


@app.get("/api/alerts")
def alerts():
    limit = _limit_arg("limit", 50, minimum=1, maximum=500)
    return jsonify(storage.list_alerts(limit=limit))


@app.patch("/api/alerts/<int:alert_id>")
def alert_status(alert_id):
    data = _json_payload(required=False)
    status = (data or {}).get("status", "")
    row = storage.update_alert(alert_id, status)
    if not row:
        return jsonify({"error": "Unknown alert or invalid status."}), 400
    return jsonify(row)


@app.get("/api/stats")
def stats():
    s = storage.stats()
    s["version"] = APP_VERSION
    return jsonify(s)


@app.get("/api/iocs")
def iocs():
    """Aggregate indicators across recent incidents of the email kind."""
    limit = _limit_arg("limit", 50, minimum=1, maximum=500)
    aggregated: dict[str, dict] = {}
    for row in storage.list_incidents(limit=limit):
        if row["kind"] != "email":
            continue
        detail = storage.get_incident(row["id"]) or {}
        report = detail.get("report") or {}
        for group in ("urls", "domains", "ips", "emails"):
            for value in (report.get("iocs") or {}).get(group, []):
                item = aggregated.setdefault(value, {"value": value, "type": group[:-1], "count": 0, "incidents": []})
                item["count"] += 1
                item["incidents"].append(row["id"])
        for h in (report.get("iocs") or {}).get("hashes", []):
            value = h["value"]
            item = aggregated.setdefault(value, {"value": value, "type": h["type"], "count": 0, "incidents": []})
            item["count"] += 1
            item["incidents"].append(row["id"])

    ordered = sorted(aggregated.values(), key=lambda x: -x["count"])[:200]

    # flag watchlist / feed hits
    ti = check_indicators([i["value"] for i in ordered])
    flagged = {m["indicator"]: m for m in ti["matches"]}
    for item in ordered:
        hit = flagged.get(item["value"])
        item["flagged"] = bool(hit)
        item["category"] = hit.get("category") if hit else None
    return jsonify({"iocs": ordered, "threat_intel": ti})


# ---------------------------- threat intelligence --------------------------

@app.get("/api/ti/feed")
def ti_feed():
    feed = load_feed()
    return jsonify({
        "size": len(feed),
        "categories": sorted({e.get("category", "?") for e in feed}),
        "entries": feed,
    })


@app.post("/api/ti/reload")
def ti_reload():
    return jsonify({"size": len(reload_feed())})


@app.post("/api/ti/check")
def ti_check():
    data = _json_payload(required=False)
    indicators = data.get("indicators") or []
    if isinstance(indicators, str):
        indicators = [x.strip() for x in indicators.replace("\n", ",").split(",") if x.strip()]
    elif not isinstance(indicators, list):
        indicators = [str(indicators)] if indicators else []
    indicators = [str(item).strip() for item in indicators if str(item).strip()]
    if not indicators:
        return jsonify({"error": "Provide at least one indicator."}), 400
    return jsonify(check_indicators(indicators, abuseipdb_key=(data.get("api_key") or "").strip()))


@app.post("/api/ti/add")
def ti_add():
    data = _json_payload(required=True)
    indicator = (data.get("indicator") or "").strip()
    if not indicator:
        return jsonify({"error": "Indicator required."}), 400
    from detector.threat_intel import _type_of
    storage.add_custom_ioc(indicator, data.get("type") or _type_of(indicator),
                           data.get("note") or "")
    return jsonify({"ok": True, "watchlist_size": len(storage.list_custom_iocs())})


@app.get("/api/watchlist")
def watchlist():
    return jsonify(storage.list_custom_iocs())


# ------------------------------ exposure -----------------------------------

@app.post("/api/password-check")
def password_check():
    """Check a password against HIBP using the k-anonymity range API.

    Only the first 5 characters of the SHA-1 hash ever leave this machine.
    """
    data = _json_payload(required=True)
    password = (data.get("password") or "")
    if not password:
        return jsonify({"error": "No password supplied."}), 400
    if len(password) < 8:
        return jsonify({"error": "Use a password of at least 8 characters."}), 400

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    req = urllib.request.Request(
        HIBP_PASSWORD_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        return jsonify({"error": f"Could not reach the breach corpus: {exc}"}), 502

    count = 0
    for line in body.splitlines():
        hash_suffix, _, occurrences = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            count = int(occurrences.strip() or 0)
            break

    return jsonify({
        "count": count,
        "exposed": count > 0,
        "note": "Only the first 5 characters of the hash were transmitted (k-anonymity).",
    })


@app.post("/api/breach-check")
def breach_check():
    """Check an email address against HIBP or a configured fallback provider."""
    data = _json_payload(required=True)
    email_addr = (data.get("email") or "").strip().lower()
    api_key = (data.get("api_key") or "").strip()

    if "@" not in email_addr:
        return jsonify({"error": "Enter a valid email address."}), 400

    provider_name = "HIBP"
    if api_key:
        url = HIBP_BREACH_URL.format(account=urllib.parse.quote(email_addr)) + "?truncateResponse=false"
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "hibp-api-key": api_key,
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                breaches = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return jsonify({"breaches": [], "message": "No breaches found for this address."})
            if exc.code == 401:
                return jsonify({"error": "The API key was rejected."}), 401
            return jsonify({"error": f"HIBP returned HTTP {exc.code}."}), 502
        except (urllib.error.URLError, TimeoutError) as exc:
            return jsonify({"error": f"Could not reach HIBP: {exc}"}), 502

        summary = [{
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain", ""),
            "breach_date": b.get("BreachDate", ""),
            "data_classes": b.get("DataClasses", []),
            "verified": b.get("IsVerified", False),
            "description": (b.get("Description") or "")[:400],
        } for b in breaches]

        return jsonify({"breaches": summary, "message": f"{len(summary)} breach(es) found.", "provider": provider_name})

    fallback = _breach_lookup_fallback(email_addr)
    if fallback.get("demo"):
        return jsonify({
            "breaches": [],
            "message": fallback["message"],
            "provider": fallback["provider"],
            "hint": "Set PHISHGUARD_BREACH_URL to a live breach provider such as a BreachDirectory-compatible endpoint.",
        })

    return jsonify({
        "breaches": fallback.get("breaches", []),
        "message": fallback.get("message", "No breaches found for this address."),
        "provider": fallback.get("provider", "fallback"),
    })


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"], host=app.config["HOST"], port=app.config["PORT"], use_reloader=False)
