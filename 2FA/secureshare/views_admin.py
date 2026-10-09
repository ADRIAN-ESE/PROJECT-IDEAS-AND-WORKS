"""Administrator area: users, alerts, audit trail, storage overview."""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

import core
from core import admin_required, audit, now
from db import many, one, run

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def index():
    users = many("SELECT u.*, (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id AND f.deleted=0) nfiles, "
                 "(SELECT IFNULL(SUM(size),0) FROM files f WHERE f.owner_id=u.id AND f.deleted=0) bytes FROM users u ORDER BY u.id")
    alerts = many("SELECT a.*, u.username FROM alerts a LEFT JOIN users u ON u.id=a.user_id WHERE a.resolved=0 ORDER BY a.id DESC LIMIT 50")
    totals = one("SELECT COUNT(*) n, IFNULL(SUM(size),0) bytes FROM files WHERE deleted=0")
    fails = one("SELECT COUNT(*) c FROM audit WHERE action IN ('login_failed','2fa_failed','device_code_failed') AND ts>?", (now() - 86400,))["c"]
    return render_template("admin.html", users=users, alerts=alerts, totals=totals, fails=fails, now=now())


@bp.route("/audit")
@admin_required
def audit_log():
    page = max(1, request.args.get("page", 1, type=int))
    sev, action, uname = request.args.get("severity", ""), request.args.get("action", "").strip(), request.args.get("user", "").strip()
    where, args = ["1=1"], []
    if sev in ("info", "warning", "critical"):
        where.append("a.severity=?"); args.append(sev)
    if action:
        where.append("a.action LIKE ?"); args.append(action + "%")
    if uname:
        where.append("u.username=?"); args.append(uname)
    rows = many(f"SELECT a.*, u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id WHERE {' AND '.join(where)} ORDER BY a.id DESC LIMIT 101 OFFSET ?", (*args, (page - 1) * 100))
    return render_template("audit.html", rows=rows[:100], more=len(rows) > 100, page=page, sev=sev, action=action, uname=uname)


@bp.route("/audit/verify", methods=["POST"])
@admin_required
def verify_chain():
    ok, info = core.verify_audit_chain()
    flash(f"Audit log intact: {info} entries verified." if ok else f"Audit log TAMPERING detected at entry #{info}.", "ok" if ok else "error")
    return redirect(url_for("admin.audit_log"))


@bp.route("/alerts/<int:aid>/resolve", methods=["POST"])
@admin_required
def resolve_alert(aid):
    run("UPDATE alerts SET resolved=1 WHERE id=?", (aid,))
    audit("alert_resolved", g.user["id"], detail=f"alert={aid}")
    return redirect(url_for("admin.index"))


@bp.route("/users/<int:uid>/<action>", methods=["POST"])
@admin_required
def user_action(uid, action):
    u = one("SELECT * FROM users WHERE id=?", (uid,))
    if not u:
        abort(404)
    if u["id"] == g.user["id"] and action in ("disable", "reset-2fa"):
        flash("You can't do that to your own account.", "error")
        return redirect(url_for("admin.index"))
    if action == "disable":
        run("UPDATE users SET is_active=0 WHERE id=?", (uid,)); core.revoke_user_sessions(uid)
    elif action == "enable":
        run("UPDATE users SET is_active=1 WHERE id=?", (uid,))
    elif action == "unlock":
        run("UPDATE users SET failed_count=0, locked_until=0 WHERE id=?", (uid,))
    elif action == "revoke-sessions":
        core.revoke_user_sessions(uid)
    elif action == "reset-2fa":
        run("UPDATE users SET totp_enabled=0, totp_secret_enc=NULL, totp_pending_enc=NULL, totp_last_step=0 WHERE id=?", (uid,))
        run("DELETE FROM backup_codes WHERE user_id=?", (uid,))
        run("UPDATE devices SET trusted_until=NULL WHERE user_id=?", (uid,))
        core.revoke_user_sessions(uid)
        core.send_mail(u["email"], "Two-factor authentication was reset", "An administrator reset 2FA on your account. Sign in and set it up again.")
    else:
        abort(404)
    audit(f"admin_{action.replace('-', '_')}", g.user["id"], detail=f"target={u['username']}", severity="warning")
    flash(f"Done: {action} for {u['username']}.", "ok")
    return redirect(url_for("admin.index"))
