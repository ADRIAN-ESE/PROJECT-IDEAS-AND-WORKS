"""SecureShare – encrypted file sharing with TOTP two-factor authentication."""
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import click
from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

import core
import crypto
import db as database

BASE_DIR = Path(__file__).resolve().parent


def _env_bool(name, default=False):
    v = os.environ.get(name)
    return default if v is None else v.lower() in ("1", "true", "yes", "on")


def create_app(overrides=None):
    app = Flask(__name__)
    instance = Path(os.environ.get("SS_INSTANCE_DIR", BASE_DIR / "instance"))
    app.config.update(
        INSTANCE_DIR=instance, ISSUER="SecureShare", BASE_URL=os.environ.get("SS_BASE_URL", ""),
        COOKIE_SECURE=_env_bool("SS_COOKIE_SECURE"), TRUST_PROXY=_env_bool("SS_TRUST_PROXY"),
        MAX_UPLOAD_BYTES=int(os.environ.get("SS_MAX_UPLOAD_MB", 25)) * 1024 * 1024,
        USER_QUOTA_BYTES=int(os.environ.get("SS_USER_QUOTA_MB", 500)) * 1024 * 1024,
        SESSION_IDLE_SECONDS=30 * 60, SESSION_ABSOLUTE_SECONDS=12 * 3600, MAX_FAILED=5, TRUST_DEVICE_DAYS=30,
        ALLOW_PUBLIC_LINKS=_env_bool("SS_ALLOW_PUBLIC_LINKS", True), PUBLIC_LINK_MAX_DAYS=30,
        CLAMD_HOST=os.environ.get("SS_CLAMD_HOST"), CLAMD_PORT=int(os.environ.get("SS_CLAMD_PORT", 3310)),
        CLAMD_SOCKET=os.environ.get("SS_CLAMD_SOCKET"), REQUIRE_AV=_env_bool("SS_REQUIRE_AV"),
        SMTP_HOST=os.environ.get("SS_SMTP_HOST"), SMTP_PORT=int(os.environ.get("SS_SMTP_PORT", 587)),
        SMTP_USER=os.environ.get("SS_SMTP_USER"), SMTP_PASSWORD=os.environ.get("SS_SMTP_PASSWORD"),
        MAIL_FROM=os.environ.get("SS_MAIL_FROM", "SecureShare <no-reply@localhost>"),
    )
    if overrides:
        app.config.update(overrides)
    cfg = app.config
    cfg["INSTANCE_DIR"] = Path(cfg["INSTANCE_DIR"])
    cfg["INSTANCE_DIR"].mkdir(parents=True, exist_ok=True)
    cfg.setdefault("DB_PATH", cfg["INSTANCE_DIR"] / "secureshare.db")
    cfg.setdefault("STORAGE_DIR", cfg["INSTANCE_DIR"] / "vault")
    Path(cfg["STORAGE_DIR"]).mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg["MAX_CONTENT_LENGTH"] = cfg["MAX_UPLOAD_BYTES"] + 64 * 1024

    app.extensions["keyring"] = crypto.KeyRing(crypto.load_master_key(cfg["INSTANCE_DIR"]))
    app.secret_key = app.extensions["keyring"].get("flask-session")
    cfg.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=cfg["COOKIE_SECURE"])
    app.extensions["dummy_hash"] = generate_password_hash("dummy-password-for-timing", method="scrypt")
    database.init_db(cfg["DB_PATH"])

    if cfg["TRUST_PROXY"]:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.before_request
    def _before():
        if request.endpoint == "static":
            return
        core.load_session()
        core.init_csrf()

    @app.after_request
    def _after(resp):
        csp = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
               "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        resp.headers.update({
            "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin"})
        if cfg["COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return core.apply_cookies(resp)

    app.teardown_appcontext(database.close_db)

    @app.template_filter("dt")
    def _dt(ts):
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "—"

    @app.template_filter("iso")
    def _iso(ts):
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else ""

    app.jinja_env.filters["size"] = core.human_size
    app.jinja_env.globals.update(csrf_token=lambda: g.csrf, now=core.now)

    @app.context_processor
    def _ctx():
        return {"current_user": g.get("user"), "config": cfg}

    from views_admin import bp as admin_bp
    from views_auth import bp as auth_bp
    from views_files import bp as files_bp
    for bp in (auth_bp, files_bp, admin_bp):
        app.register_blueprint(bp)

    @app.errorhandler(HTTPException)
    def _http_error(e):
        if core.wants_json():
            return jsonify(error=e.description), e.code
        return render_template("error.html", code=e.code, message=e.description), e.code

    @app.errorhandler(Exception)
    def _crash(e):
        app.logger.exception("Unhandled error")
        if core.wants_json():
            return jsonify(error="Something went wrong on our side."), 500
        return render_template("error.html", code=500, message="Something went wrong on our side."), 500

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.argument("email")
    @click.password_option()
    def create_admin(username, email, password):
        """Create an administrator account (admins can't self-register)."""
        problem = core.password_problem(password, username, email)
        if problem or not core.USERNAME_RE.match(username) or not core.EMAIL_RE.match(email):
            raise click.ClickException(problem or "Invalid username or email.")
        t = int(time.time())
        database.run("INSERT INTO users(username,email,display_name,pw_hash,role,created_at,pw_changed_at) VALUES(?,?,?,?,?,?,?)",
                     (username, email.lower(), username, generate_password_hash(password, method="scrypt"), "admin", t, t))
        click.echo(f"Administrator '{username}' created. Sign in and enable 2FA to reach the admin area.")

    return app


if __name__ == "__main__":
    create_app().run(host=os.environ.get("SS_HOST", "127.0.0.1"), port=int(os.environ.get("SS_PORT", 5000)))
