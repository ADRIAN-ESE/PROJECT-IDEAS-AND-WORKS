"""Dashboard, encrypted upload/download, sharing and share links."""
import os
import uuid
from datetime import datetime, timezone, timedelta
from io import BytesIO
from pathlib import Path

from flask import (Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template,
                   request, send_file, url_for)

import core
import crypto
import scanner
from core import audit, login_required, now
from db import many, one, run

bp = Blueprint("files", __name__)

LIVE = "s.revoked=0 AND (s.expires_at IS NULL OR s.expires_at>?)"
CAN_DL = "s.allow_download=1 AND (s.max_downloads IS NULL OR s.download_count<s.max_downloads)"


# ---------------------------------------------------------------- storage helpers
def _blob_path(fid):
    return Path(current_app.config["STORAGE_DIR"]) / f"{fid}.bin"


def _aad(fid):
    return f"file:{fid}".encode()


def store_encrypted(fid, data):
    """AES-256-GCM: random per-file key, itself wrapped (AES-256-GCM) by the vault key."""
    kr, dek = core.keyring(), os.urandom(32)
    blob = crypto.seal(dek, data, _aad(fid))
    tmp = _blob_path(fid).with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, _blob_path(fid))
    return crypto.seal(kr.get("file-kek"), dek, _aad(fid))


def read_decrypted(frow):
    """Decrypt and verify SHA-256 integrity. Raises ValueError if anything is off."""
    try:
        dek = crypto.unseal(core.keyring().get("file-kek"), frow["wrapped_key"], _aad(frow["id"]))
        data = crypto.unseal(dek, _blob_path(frow["id"]).read_bytes(), _aad(frow["id"]))
    except Exception as exc:  # bad tag, missing blob, truncated file
        raise ValueError("decryption failed") from exc
    if not crypto.hmac.compare_digest(crypto.sha256_hex(data), frow["sha256"]):
        raise ValueError("checksum mismatch")
    return data


# ---------------------------------------------------------------- access control
def get_access(file_id):
    """Return (file_row, role, shares) for the current user, or abort 404 (never reveal existence)."""
    f = one("SELECT f.*, u.username owner_name, u.display_name owner_display FROM files f JOIN users u ON u.id=f.owner_id WHERE f.id=? AND f.deleted=0", (file_id,))
    if not f:
        abort(404)
    if f["owner_id"] == g.user["id"]:
        return f, "owner", []
    shares = many(f"SELECT s.* FROM shares s WHERE s.file_id=? AND s.recipient_id=? AND {LIVE} ORDER BY s.id", (file_id, g.user["id"], now()))
    if not shares:
        abort(404)
    return f, ("collaborator" if any(s["permission"] == "collaborator" for s in shares) else "viewer"), shares


def _send(f, data):
    resp = send_file(BytesIO(data), mimetype="application/octet-stream", as_attachment=True, download_name=f["safe_name"])
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-SHA256"] = f["sha256"]
    return resp


def _deliver(f, share_id, who_id, via):
    """Decrypt, verify, count the download atomically, audit, send."""
    try:
        data = read_decrypted(f)
    except ValueError:
        audit("integrity_failure", who_id, obj=f["id"], detail=f"{f['safe_name']}: stored file failed verification", severity="critical")
        abort(500, "This file failed its integrity check and has been blocked. The owner and administrators were alerted.")
    if share_id is not None:
        if not run(f"UPDATE shares SET download_count=download_count+1 WHERE id=? AND revoked=0 AND (expires_at IS NULL OR expires_at>?) AND (max_downloads IS NULL OR download_count<max_downloads) AND allow_download=1",
                   (share_id, now())).rowcount:
            audit("download_denied", who_id, obj=f["id"], detail="limit reached or expired", severity="warning")
            abort(410, "This share has expired or reached its download limit.")
    audit("download", who_id, obj=f["id"], detail=f"{f['safe_name']} via {via}")
    return _send(f, data)


# ---------------------------------------------------------------- pages
@bp.route("/")
@login_required
def dashboard():
    uid = g.user["id"]
    stats = one("SELECT COUNT(*) n, IFNULL(SUM(size),0) bytes FROM files WHERE owner_id=? AND deleted=0", (uid,))
    shared_with_me = one(f"SELECT COUNT(*) c FROM shares s JOIN files f ON f.id=s.file_id AND f.deleted=0 WHERE s.recipient_id=? AND {LIVE}", (uid, now()))["c"]
    shared_by_me = one(f"SELECT COUNT(*) c FROM shares s JOIN files f ON f.id=s.file_id AND f.deleted=0 WHERE s.creator_id=? AND {LIVE}", (uid, now()))["c"]
    recent = many("SELECT * FROM files WHERE owner_id=? AND deleted=0 ORDER BY created_at DESC LIMIT 5", (uid,))
    activity = many("SELECT * FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 6", (uid,))
    alerts = many("SELECT * FROM alerts WHERE user_id=? AND resolved=0 ORDER BY id DESC LIMIT 5", (uid,))
    return render_template("dashboard.html", stats=stats, shared_with_me=shared_with_me, shared_by_me=shared_by_me,
                           recent=recent, activity=activity, alerts=alerts, quota=current_app.config["USER_QUOTA_BYTES"])


@bp.route("/files")
@login_required
def my_files():
    q = request.args.get("q", "").strip()
    rows = many("SELECT f.*, (SELECT COUNT(*) FROM shares s WHERE s.file_id=f.id AND s.revoked=0 AND (s.expires_at IS NULL OR s.expires_at>?)) shares "
                "FROM files f WHERE owner_id=? AND deleted=0 AND safe_name LIKE ? ESCAPE '\\' ORDER BY created_at DESC",
                (now(), g.user["id"], "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"))
    return render_template("files.html", files=rows, q=q, max_mb=current_app.config["MAX_UPLOAD_BYTES"] // 1048576,
                           types=", ".join(sorted(scanner.ALLOWED)))


@bp.route("/shared")
@login_required
def shared():
    uid, t = g.user["id"], now()
    with_me = many("SELECT s.*, f.safe_name, f.size, f.owner_id, u.display_name sharer FROM shares s JOIN files f ON f.id=s.file_id AND f.deleted=0 "
                   "JOIN users u ON u.id=s.creator_id WHERE s.recipient_id=? ORDER BY s.id DESC", (uid,))
    by_me = many("SELECT s.*, f.safe_name, r.username recipient FROM shares s JOIN files f ON f.id=s.file_id AND f.deleted=0 "
                 "LEFT JOIN users r ON r.id=s.recipient_id WHERE s.creator_id=? ORDER BY s.id DESC", (uid,))
    return render_template("shared.html", with_me=with_me, by_me=by_me, t=t)


@bp.route("/files/<fid>")
@login_required
def detail(fid):
    f, role, my_shares = get_access(fid)
    can_download = role == "owner" or any(s["allow_download"] and (s["max_downloads"] is None or s["download_count"] < s["max_downloads"]) for s in my_shares)
    can_reshare = role == "owner" or any(s["allow_reshare"] for s in my_shares)
    shares = []
    if role == "owner":
        shares = many("SELECT s.*, r.username recipient, c.username creator FROM shares s LEFT JOIN users r ON r.id=s.recipient_id JOIN users c ON c.id=s.creator_id WHERE s.file_id=? ORDER BY s.id DESC", (fid,))
    log = many("SELECT a.*, u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id WHERE a.object=? ORDER BY a.id DESC LIMIT 25", (fid,)) if role in ("owner", "collaborator") else []
    new_link = request.args.get("link_token")
    return render_template("detail.html", f=f, role=role, my_shares=my_shares, can_download=can_download, can_reshare=can_reshare,
                           shares=shares, log=log, t=now(), public_ok=current_app.config["ALLOW_PUBLIC_LINKS"] and role == "owner",
                           new_link=(core.base_url() + "/s/" + new_link) if new_link and role == "owner" else None)


# ---------------------------------------------------------------- upload
def _json_error(msg, code, **extra):
    return jsonify(error=msg, **extra), code


@bp.route("/api/upload", methods=["POST"])
@login_required
def upload():
    cfg, uid = current_app.config, g.user["id"]
    if core.count_attempts(f"upload:{uid}", 60) >= 20:
        return _json_error("You're uploading too quickly. Wait a minute and retry.", 429)
    core.record_attempt(f"upload:{uid}")
    up = request.files.get("file")
    if not up or not up.filename:
        return _json_error("Choose a file to upload.", 400)
    data = up.read(cfg["MAX_UPLOAD_BYTES"] + 1)
    if len(data) > cfg["MAX_UPLOAD_BYTES"]:
        return _json_error(f"File is larger than the {cfg['MAX_UPLOAD_BYTES'] // 1048576} MB limit.", 413)
    if not data:
        return _json_error("That file is empty.", 400)
    used = one("SELECT IFNULL(SUM(size),0) s FROM files WHERE owner_id=? AND deleted=0", (uid,))["s"]
    if used + len(data) > cfg["USER_QUOTA_BYTES"]:
        return _json_error("This upload would exceed your storage quota.", 413)
    safe, ext = scanner.sanitize_filename(up.filename)
    err, mime = scanner.validate_content(safe, ext, data)
    if err:
        audit("upload_rejected", uid, detail=f"{safe}: {err}", severity="warning")
        return _json_error(err, 415)
    digest = crypto.sha256_hex(data)
    dup = one("SELECT id, safe_name FROM files WHERE owner_id=? AND sha256=? AND deleted=0", (uid, digest))
    if dup:
        return _json_error(f"You already uploaded this exact file as “{dup['safe_name']}”.", 409, existing=url_for("files.detail", fid=dup["id"]))
    scan = scanner.scan_bytes(data, cfg)
    if scan["status"] == "infected":
        audit("malware_blocked", uid, detail=f"{safe}: {scan['signature']} ({scan['engine']})", severity="critical")
        return _json_error("This file was blocked because it was flagged as malware.", 422)
    if scan["status"] != "clean":
        audit("scan_unavailable", uid, detail=f"{safe}: {scan['signature']}", severity="warning")
        return _json_error("Virus scanning is unavailable right now, so the upload was refused. Try again later.", 503)
    fid = uuid.uuid4().hex
    wrapped = store_encrypted(fid, data)
    run("INSERT INTO files(id,owner_id,orig_name,safe_name,mime,size,sha256,wrapped_key,scan_engine,scan_status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (fid, uid, (up.filename or "")[:255], safe, mime, len(data), digest, wrapped, scan["engine"], "clean", now()))
    audit("upload", uid, obj=fid, detail=f"{safe}, {len(data)} bytes, sha256={digest[:16]}…")
    return jsonify(id=fid, name=safe, size=len(data), sha256=digest, url=url_for("files.detail", fid=fid)), 201


# ---------------------------------------------------------------- download / delete
@bp.route("/files/<fid>/download", methods=["POST"])
@login_required
def download(fid):
    f, role, shares = get_access(fid)
    if role == "owner":
        return _deliver(f, None, g.user["id"], "owner")
    usable = [s for s in shares if s["allow_download"] and (s["max_downloads"] is None or s["download_count"] < s["max_downloads"])]
    if not usable:
        audit("download_denied", g.user["id"], obj=fid, detail="not permitted or limit reached", severity="warning")
        abort(403, "You don't have permission to download this file, or its download limit is used up.")
    return _deliver(f, usable[0]["id"], g.user["id"], f"share {usable[0]['id']}")


@bp.route("/files/<fid>/delete", methods=["POST"])
@login_required
def delete(fid):
    f, role, _ = get_access(fid)
    if role != "owner":
        abort(403)
    run("UPDATE files SET deleted=1 WHERE id=?", (fid,))
    run("UPDATE shares SET revoked=1 WHERE file_id=?", (fid,))
    try:
        _blob_path(fid).unlink()
    except FileNotFoundError:
        pass
    audit("file_deleted", g.user["id"], obj=fid, detail=f["safe_name"], severity="warning")
    flash(f"Deleted “{f['safe_name']}” and revoked its shares.", "ok")
    return redirect(url_for("files.my_files"))


# ---------------------------------------------------------------- sharing
def _parse_expiry(form):
    raw = form.get("expires_at", "").strip()
    if not raw:
        return None, None
    try:
        local = datetime.strptime(raw, "%Y-%m-%dT%H:%M")
        offset = int(form.get("tz_offset", "0") or 0)  # minutes, as JS getTimezoneOffset()
        ts = int((local.replace(tzinfo=timezone.utc) + timedelta(minutes=offset)).timestamp())
    except ValueError:
        return None, "Enter a valid expiry date."
    if ts <= now():
        return None, "The expiry date must be in the future."
    return ts, None


@bp.route("/files/<fid>/share", methods=["POST"])
@login_required
def create_share(fid):
    cfg, form = current_app.config, request.form
    f, role, my_shares = get_access(fid)
    parent = None
    if role != "owner":
        parent = next((s for s in my_shares if s["allow_reshare"]), None)
        if not parent:
            abort(403, "You aren't allowed to reshare this file.")
    back = redirect(url_for("files.detail", fid=fid))
    expires, err = _parse_expiry(form)
    recipient_name = form.get("recipient", "").strip()
    recipient = one("SELECT * FROM users WHERE username=? AND is_active=1", (recipient_name,)) if recipient_name else None
    perm = form.get("permission", "viewer")
    allow_dl, allow_re = form.get("allow_download") == "1", form.get("allow_reshare") == "1"
    max_dl = form.get("max_downloads", "").strip()
    try:
        max_dl = int(max_dl) if max_dl else None
        if max_dl is not None and not 1 <= max_dl <= 10000:
            raise ValueError
    except ValueError:
        err, max_dl = "Download limit must be a number between 1 and 10,000.", None
    if perm not in ("viewer", "collaborator"):
        err = "Choose a valid permission."
    if recipient_name and (not recipient or recipient["id"] == g.user["id"]):
        err = "We couldn't find that user. Check the username."  # same message for missing/inactive/self
    if not recipient_name:
        if parent or not cfg["ALLOW_PUBLIC_LINKS"]:
            err = "Choose who to share with."
        elif not expires or expires > now() + cfg["PUBLIC_LINK_MAX_DAYS"] * 86400:
            err = f"Link shares need an expiry within {cfg['PUBLIC_LINK_MAX_DAYS']} days."
        allow_re = False
    if parent:  # resharing can only narrow what the sender received
        perm = "viewer" if parent["permission"] == "viewer" else perm
        allow_dl, allow_re = allow_dl and bool(parent["allow_download"]), False
        if parent["expires_at"]:
            expires = min(expires or parent["expires_at"], parent["expires_at"])
        if parent["max_downloads"] is not None:
            left = max(parent["max_downloads"] - parent["download_count"], 0)
            max_dl = min(max_dl or left, left)
            if left == 0 and allow_dl:
                err = "No downloads remain on your share, so you can't pass any on."
    if err:
        flash(err, "error")
        return back
    token = crypto.new_token()
    cur = run("INSERT INTO shares(file_id,creator_id,recipient_id,parent_share_id,token_hash,permission,allow_download,allow_reshare,expires_at,max_downloads,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (fid, g.user["id"], recipient["id"] if recipient else None, parent["id"] if parent else None, crypto.token_hash(token),
               perm, int(allow_dl), int(allow_re), expires, max_dl, now()))
    audit("share_created", g.user["id"], obj=fid, detail=f"share={cur.lastrowid} to={recipient['username'] if recipient else 'link'} perm={perm} dl={int(allow_dl)} reshare={int(allow_re)}")
    if recipient:
        core.send_mail(recipient["email"], f"{g.user['display_name']} shared a file with you", f"“{f['safe_name']}” was shared with you. Sign in to open it: {core.base_url()}/shared")
        flash(f"Shared with {recipient['username']}.", "ok")
        return back
    flash("Link created. Copy it now — for security it can't be shown again.", "ok")
    return redirect(url_for("files.detail", fid=fid, link_token=token))


def _revoke_tree(share_id):
    run("UPDATE shares SET revoked=1 WHERE id=?", (share_id,))
    for child in many("SELECT id FROM shares WHERE parent_share_id=? AND revoked=0", (share_id,)):
        _revoke_tree(child["id"])


@bp.route("/shares/<int:sid>/revoke", methods=["POST"])
@login_required
def revoke_share(sid):
    s = one("SELECT s.*, f.owner_id FROM shares s JOIN files f ON f.id=s.file_id WHERE s.id=?", (sid,))
    if not s or g.user["id"] not in (s["owner_id"], s["creator_id"]):
        abort(404)
    _revoke_tree(sid)
    audit("share_revoked", g.user["id"], obj=s["file_id"], detail=f"share={sid}")
    flash("Share revoked.", "ok")
    return redirect(request.form.get("back") if (request.form.get("back") or "").startswith("/") and not request.form.get("back").startswith("//") else url_for("files.shared"))


# ---------------------------------------------------------------- share links
def _link_share(token):
    s = one("SELECT s.*, f.safe_name, f.size, f.sha256, f.id fid, f.owner_id, f.deleted, f.mime, f.created_at f_created, f.scan_status, f.wrapped_key, u.display_name sharer "
            "FROM shares s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.creator_id WHERE s.token_hash=?", (crypto.token_hash(token),))
    if not s or s["revoked"] or s["deleted"] or (s["expires_at"] and s["expires_at"] <= now()):
        return None
    return s


@bp.route("/s/<token>")
def link_page(token):
    s = _link_share(token)
    if not s:
        return render_template("link.html", s=None), 404
    if s["recipient_id"]:
        if not g.user:
            return redirect(url_for("auth.login", next=request.path))
        if g.user["id"] != s["recipient_id"]:
            audit("link_wrong_user", g.user["id"], obj=s["fid"], severity="warning")
            return render_template("link.html", s=None), 404
    left = None if s["max_downloads"] is None else max(s["max_downloads"] - s["download_count"], 0)
    audit("link_opened", g.user["id"] if g.user else None, obj=s["fid"], detail=f"share={s['id']}")
    return render_template("link.html", s=s, left=left, token=token)


@bp.route("/s/<token>/download", methods=["POST"])
def link_download(token):
    s = _link_share(token)
    if not s or not s["allow_download"]:
        abort(404)
    if s["recipient_id"] and (not g.user or g.user["id"] != s["recipient_id"]):
        abort(404)
    if core.count_attempts(f"linkdl:{core.client_ip()}", 60) >= 30:
        abort(429, "Too many downloads. Wait a minute.")
    core.record_attempt(f"linkdl:{core.client_ip()}")
    f = one("SELECT * FROM files WHERE id=?", (s["fid"],))
    return _deliver(f, s["id"], g.user["id"] if g.user else None, f"link {s['id']}")
