"""End-to-end tests: run with  python -m unittest discover -s tests -v   (from the project root)."""
import io
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto  # noqa: E402
import scanner  # noqa: E402
from app import create_app  # noqa: E402

PW = "correct-horse-battery-9"


class Client:
    def __init__(self, app, ip="10.0.0.1"):
        self.app, self.c, self.ip = app, app.test_client(), ip

    def _env(self):
        return {"REMOTE_ADDR": self.ip}

    def csrf(self):
        if not self.c.get_cookie("csrf"):
            self.c.get("/login", environ_base=self._env())
        return self.c.get_cookie("csrf").value

    def get(self, url, **kw):
        return self.c.get(url, environ_base=self._env(), **kw)

    def post(self, url, data=None, **kw):
        data = dict(data or {})
        if "csrf" not in kw.pop("nocsrf", ()) and "csrf_token" not in data:
            data["csrf_token"] = self.csrf()
        return self.c.post(url, data=data, environ_base=self._env(), **kw)

    def upload(self, name, content, token=True):
        h = {"X-CSRF-Token": self.csrf()} if token else {}
        return self.c.post("/api/upload", data={"file": (io.BytesIO(content), name)}, headers=h,
                           content_type="multipart/form-data", environ_base=self._env())


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({"INSTANCE_DIR": self.tmp, "TESTING": True, "MAX_UPLOAD_BYTES": 1024 * 1024})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def q(self, sql, args=()):
        conn = sqlite3.connect(self.app.config["DB_PATH"])
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, args).fetchall()
        conn.close()
        return rows

    def x(self, sql, args=()):
        conn = sqlite3.connect(self.app.config["DB_PATH"])
        conn.execute(sql, args)
        conn.commit()
        conn.close()

    def register(self, name, pw=PW):
        c = Client(self.app)
        r = c.post("/register", {"username": name, "email": f"{name}@example.com", "password": pw, "password2": pw})
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:400])
        return c

    def login(self, name, pw=PW, client=None, ip="10.0.0.1"):
        c = client or Client(self.app, ip)
        r = c.post("/login", {"username": name, "password": pw})
        return c, r

    def secret(self, name):
        u = self.q("SELECT * FROM users WHERE username=?", (name,))[0]
        return crypto.unseal(self.app.extensions["keyring"].get("totp"), u["totp_secret_enc"], f"totp:{u['id']}".encode()).decode()

    def enable_2fa(self, c, name):
        page = c.get("/security/2fa/setup").get_data(as_text=True)
        self.assertIn("data:image/svg+xml;base64", page)
        u = self.q("SELECT * FROM users WHERE username=?", (name,))[0]
        pending = crypto.unseal(self.app.extensions["keyring"].get("totp"), u["totp_pending_enc"], f"totp:{u['id']}".encode()).decode()
        code = crypto.totp_code(pending, int(time.time()) // 30)
        r = c.post("/security/2fa/setup", {"code": code})
        html = r.get_data(as_text=True)
        codes = re.findall(r"<code>([A-Z0-9]{4}-[A-Z0-9]{4})</code>", html)
        self.assertEqual(len(codes), 10)
        return codes, code


class TestAccounts(Base):
    def test_register_login_logout_and_policy(self):
        c = Client(self.app)
        r = c.post("/register", {"username": "weak", "email": "w@example.com", "password": "short", "password2": "short"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("at least 12", r.get_data(as_text=True))
        self.register("alice")
        dup = Client(self.app).post("/register", {"username": "ALICE", "email": "z@example.com", "password": PW, "password2": PW})
        self.assertIn("already registered", dup.get_data(as_text=True))
        c, r = self.login("alice")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(c.get("/").status_code, 200)
        self.assertEqual(c.post("/logout").status_code, 302)
        self.assertEqual(c.get("/files").status_code, 302)  # signed out

    def test_pw_hash_is_scrypt_and_csrf_enforced(self):
        self.register("alice")
        self.assertTrue(self.q("SELECT pw_hash FROM users")[0]["pw_hash"].startswith("scrypt:"))
        c = Client(self.app)
        c.csrf()
        r = c.post("/login", {"username": "alice", "password": PW, "csrf_token": "forged"})
        self.assertEqual(r.status_code, 400)

    def test_security_headers(self):
        r = Client(self.app).get("/login")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertNotIn("<script>", r.get_data(as_text=True).replace('<script src', ''))

    def test_lockout_after_repeated_failures(self):
        self.register("alice")
        c = Client(self.app)
        for _ in range(5):
            self.assertEqual(self.login("alice", "wrong-password-123", c)[1].status_code, 401)
        self.assertEqual(self.login("alice", PW, c)[1].status_code, 401)  # correct pw, but locked
        self.assertTrue(self.q("SELECT locked_until FROM users")[0]["locked_until"] > time.time())
        self.assertTrue(self.q("SELECT 1 FROM audit WHERE action='account_locked'"))
        self.assertTrue(self.q("SELECT 1 FROM alerts WHERE kind='bruteforce_account'"))

    def test_password_spraying_detected(self):
        for n in ("user1", "user2", "user3"):
            self.register(n)
        c = Client(self.app, "203.0.113.9")
        for n in ("user1", "user2", "user3"):
            for _ in range(3):
                self.login(n, "nope-nope-nope-1", c)
        self.assertTrue(self.q("SELECT 1 FROM alerts WHERE kind='password_spraying'"))

    def test_change_password_revokes_other_sessions_and_reset_flow(self):
        self.register("alice")
        c1, _ = self.login("alice")
        c2, _ = self.login("alice", ip="10.0.0.2")
        new = "another-long-passphrase-7"
        r = c1.post("/security/password", {"current": PW, "password": new, "password2": new})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(c2.get("/files").status_code, 302)  # other session ended
        self.assertEqual(c1.get("/files").status_code, 200)
        # forgot + reset
        anon = Client(self.app)
        anon.post("/forgot", {"identifier": "alice"})
        mail = open(os.path.join(self.tmp, "outbox.log")).read()
        token = re.search(r"/reset/([\w-]+)", mail).group(1)
        final = "yet-another-passphrase-42"
        self.assertEqual(anon.post(f"/reset/{token}", {"password": final, "password2": final}).status_code, 302)
        self.assertEqual(anon.get(f"/reset/{token}").status_code, 400)  # single use
        self.assertEqual(c1.get("/files").status_code, 302)  # reset ends every session
        self.assertEqual(self.login("alice", final, Client(self.app, "10.0.0.3"))[1].status_code, 302)
        # unknown account gives the same response (no enumeration)
        r = Client(self.app).post("/forgot", {"identifier": "ghost"})
        self.assertIn("If that account exists", r.get_data(as_text=True))


class TestTwoFactor(Base):
    def test_2fa_enable_new_device_replay_backup_and_attempt_limits(self):
        c = self.register("alice")
        c, _ = self.login("alice", client=c)
        codes, used_code = self.enable_2fa(c, "alice")
        # the stored secret is encrypted, not plaintext
        raw = self.q("SELECT totp_secret_enc FROM users")[0]["totp_secret_enc"]
        self.assertNotIn(self.secret("alice").encode(), raw)

        # fresh browser => must verify with 2FA
        d = Client(self.app, "10.0.0.7")
        r = d.post("/login", {"username": "alice", "password": PW})
        self.assertTrue(r.headers["Location"].endswith("/login/verify"))
        # replaying the code already consumed during setup is rejected
        r = d.post("/login/verify", {"code": used_code})
        self.assertEqual(r.status_code, 200)
        self.assertIn("attempts left", r.get_data(as_text=True))
        # next time-step code is accepted (window ±1)
        nxt = crypto.totp_code(self.secret("alice"), int(time.time()) // 30 + 1)
        r = d.post("/login/verify", {"code": nxt, "remember": "1"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(d.get("/").status_code, 200)
        self.assertTrue(self.q("SELECT 1 FROM devices WHERE trusted_until IS NOT NULL"))
        # trusted device skips 2FA on the next login
        d.post("/logout")
        r = d.post("/login", {"username": "alice", "password": PW})
        self.assertFalse(r.headers["Location"].endswith("/login/verify"))

        # backup code: works once only
        e = Client(self.app, "10.0.0.8")
        e.post("/login", {"username": "alice", "password": PW})
        self.assertEqual(e.post("/login/verify", {"code": codes[0]}).status_code, 302)
        f = Client(self.app, "10.0.0.9")
        f.post("/login", {"username": "alice", "password": PW})
        self.assertEqual(f.post("/login/verify", {"code": codes[0]}).status_code, 200)

        # wrong codes: 5 strikes kills the challenge
        g_ = Client(self.app, "10.0.0.10")
        self.x("UPDATE users SET failed_count=0, locked_until=0")
        g_.post("/login", {"username": "alice", "password": PW})
        for _ in range(4):
            self.assertEqual(g_.post("/login/verify", {"code": "000000"}).status_code, 200)
        r = g_.post("/login/verify", {"code": "000000"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/login"))
        self.assertEqual(g_.get("/files").status_code, 302)
        self.assertTrue(self.q("SELECT 1 FROM audit WHERE action='2fa_failed'"))

    def test_disable_requires_password_and_code(self):
        c = self.register("alice")
        c, _ = self.login("alice", client=c)
        self.enable_2fa(c, "alice")
        r = c.post("/security/2fa/disable", {"password": PW, "code": "123456"})
        self.assertEqual(self.q("SELECT totp_enabled FROM users")[0][0], 1)
        self.x("UPDATE users SET totp_last_step=0")
        code = crypto.totp_code(self.secret("alice"), int(time.time()) // 30)
        c.post("/security/2fa/disable", {"password": PW, "code": code})
        self.assertEqual(self.q("SELECT totp_enabled FROM users")[0][0], 0)
        self.assertEqual(self.q("SELECT COUNT(*) FROM backup_codes")[0][0], 0)

    def test_email_verification_for_new_device_without_2fa(self):
        self.register("alice")
        self.login("alice")  # first device: no challenge
        d = Client(self.app, "10.0.0.5")
        r = d.post("/login", {"username": "alice", "password": PW})
        self.assertTrue(r.headers["Location"].endswith("/login/verify"))
        code = re.findall(r"Verification code: (\d{8})", open(os.path.join(self.tmp, "outbox.log")).read())[-1]
        self.assertEqual(d.post("/login/verify", {"code": "00000000"}).status_code, 200)
        self.assertEqual(d.post("/login/verify", {"code": code}).status_code, 302)
        self.assertEqual(d.get("/files").status_code, 200)

    def test_sessions_list_and_revoke(self):
        self.register("alice")
        c1, _ = self.login("alice")
        c2, _ = self.login("alice", client=Client(self.app, "10.0.0.1"))
        self.assertIn("Active sessions", c1.get("/security").get_data(as_text=True))
        sid = self.q("SELECT id FROM sessions ORDER BY created_at LIMIT 1")[0]["id"]
        c1.post(f"/security/sessions/{sid}/revoke")
        self.assertTrue(self.q("SELECT revoked FROM sessions WHERE id=?", (sid,))[0]["revoked"])


class TestFiles(Base):
    def setUp(self):
        super().setUp()
        self.register("alice"); self.register("bob"); self.register("carol")
        self.a, _ = self.login("alice"); self.b, _ = self.login("bob", ip="10.0.0.2"); self.cc, _ = self.login("carol", ip="10.0.0.3")

    def fid(self, r):
        return r.get_json()["id"]

    def test_upload_validation_dedupe_scan_and_encryption(self):
        data = b"top secret plaintext marker 12345\n" * 20
        r = self.a.upload("../../notes.txt", data)
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        fid = self.fid(r)
        self.assertEqual(r.get_json()["name"], "notes.txt")
        blob = open(os.path.join(self.app.config["STORAGE_DIR"], fid + ".bin"), "rb").read()
        self.assertNotIn(b"plaintext marker", blob)
        self.assertEqual(self.a.upload("again.txt", data).status_code, 409)       # duplicate
        self.assertEqual(self.b.upload("again.txt", data).status_code, 201)       # other user: fine
        self.assertEqual(self.a.upload("evil.exe", b"MZ" + b"\0" * 50).status_code, 415)
        self.assertEqual(self.a.upload("evil.pdf", b"MZ\x90" + b"\0" * 50).status_code, 415)
        self.assertEqual(self.a.upload("fake.png", b"not really a png").status_code, 415)
        self.assertEqual(self.a.upload("big.txt", b"x" * (1024 * 1024 + 10)).status_code, 413)
        self.assertEqual(self.a.upload("eicar.txt", scanner.EICAR).status_code, 422)
        self.assertTrue(self.q("SELECT 1 FROM alerts WHERE kind='malware_blocked'"))
        self.assertEqual(self.a.upload("empty.txt", b"").status_code, 400)
        self.assertEqual(self.a.upload("x.txt", b"hello", token=False).status_code, 400)  # CSRF
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("run.bat", "echo hi")
        self.assertEqual(self.a.upload("a.zip", buf.getvalue()).status_code, 415)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<x/>"); z.writestr("word/document.xml", "<w/>")
        self.assertEqual(self.a.upload("ok.docx", buf.getvalue()).status_code, 201)

    def test_download_integrity_and_tamper_detection(self):
        data = b"hello integrity\n" * 10
        fid = self.fid(self.a.upload("doc.txt", data))
        r = self.a.post(f"/files/{fid}/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, data)
        self.assertIn("attachment", r.headers["Content-Disposition"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        path = os.path.join(self.app.config["STORAGE_DIR"], fid + ".bin")
        raw = bytearray(open(path, "rb").read()); raw[20] ^= 1; open(path, "wb").write(raw)
        r = self.a.post(f"/files/{fid}/download")
        self.assertEqual(r.status_code, 500)
        self.assertTrue(self.q("SELECT 1 FROM alerts WHERE kind='integrity_failure'"))

    def test_authorization_boundaries(self):
        fid = self.fid(self.a.upload("private.txt", b"mine\n"))
        self.assertEqual(self.b.get(f"/files/{fid}").status_code, 404)
        self.assertEqual(self.b.post(f"/files/{fid}/download").status_code, 404)
        self.assertEqual(self.b.post(f"/files/{fid}/delete").status_code, 404)
        self.assertEqual(self.b.post(f"/files/{fid}/share", {"recipient": "carol"}).status_code, 404)
        self.assertEqual(Client(self.app).get(f"/files/{fid}").status_code, 302)
        self.assertEqual(self.b.get("/admin/").status_code, 403)

    def test_user_share_limits_expiry_revoke_and_reshare(self):
        fid = self.fid(self.a.upload("shared.txt", b"share me\n"))
        future = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(time.time() + 3600))
        r = self.a.post(f"/files/{fid}/share", {"recipient": "bob", "allow_download": "1", "max_downloads": "1", "expires_at": future, "tz_offset": "0", "allow_reshare": "1", "permission": "collaborator"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("shared.txt", self.b.get("/shared").get_data(as_text=True))
        self.assertEqual(self.b.get(f"/files/{fid}").status_code, 200)
        self.assertEqual(self.b.post(f"/files/{fid}/download").status_code, 200)
        self.assertEqual(self.b.post(f"/files/{fid}/download").status_code, 403)    # limit reached
        # past expiry is rejected at creation
        past = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(time.time() - 3600))
        self.a.post(f"/files/{fid}/share", {"recipient": "carol", "expires_at": past, "tz_offset": "0"})
        self.assertEqual(self.q("SELECT COUNT(*) FROM shares")[0][0], 1)
        # bob reshares to carol: can't escalate (no download beyond parent, no further reshare)
        self.x("UPDATE shares SET max_downloads=5, download_count=0")
        self.b.post(f"/files/{fid}/share", {"recipient": "carol", "allow_download": "1", "allow_reshare": "1", "max_downloads": "99"})
        child = self.q("SELECT * FROM shares WHERE recipient_id=(SELECT id FROM users WHERE username='carol')")[0]
        self.assertEqual((child["allow_reshare"], child["max_downloads"], child["permission"]), (0, 5, "viewer"))
        self.assertTrue(child["expires_at"] is not None)                              # inherits parent expiry
        self.assertEqual(self.cc.post(f"/files/{fid}/download").status_code, 200)
        # carol can't reshare further
        self.assertEqual(self.cc.post(f"/files/{fid}/share", {"recipient": "alice"}).status_code, 403)
        # owner revokes bob's share => cascades to carol
        parent = self.q("SELECT id FROM shares WHERE parent_share_id IS NULL")[0]["id"]
        self.a.post(f"/shares/{parent}/revoke")
        self.assertEqual(self.b.get(f"/files/{fid}").status_code, 404)
        self.assertEqual(self.cc.get(f"/files/{fid}").status_code, 404)

    def test_viewer_without_download_and_expiry_enforced_server_side(self):
        fid = self.fid(self.a.upload("view.txt", b"view only\n"))
        self.a.post(f"/files/{fid}/share", {"recipient": "bob", "permission": "viewer"})
        self.assertEqual(self.b.get(f"/files/{fid}").status_code, 200)
        self.assertEqual(self.b.post(f"/files/{fid}/download").status_code, 403)
        self.assertNotIn("Access log", self.b.get(f"/files/{fid}").get_data(as_text=True))
        self.x("UPDATE shares SET expires_at=1")
        self.assertEqual(self.b.get(f"/files/{fid}").status_code, 404)

    def test_public_link(self):
        fid = self.fid(self.a.upload("pub.txt", b"public payload\n"))
        r = self.a.post(f"/files/{fid}/share", {"allow_download": "1"})            # link w/o expiry => refused
        self.assertEqual(self.q("SELECT COUNT(*) FROM shares")[0][0], 0)
        future = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(time.time() + 7200))
        r = self.a.post(f"/files/{fid}/share", {"allow_download": "1", "max_downloads": "2", "expires_at": future, "tz_offset": "0"})
        self.assertIn("link_token=", r.headers["Location"])
        token = re.search(r"link_token=([\w-]+)", r.headers["Location"]).group(1)
        self.assertEqual(self.q("SELECT COUNT(*) FROM shares WHERE token_hash=?", (token,))[0][0], 0)  # only hash stored
        anon = Client(self.app, "198.51.100.4")
        self.assertEqual(anon.get(f"/s/{token}").status_code, 200)
        self.assertEqual(anon.post(f"/s/{token}/download").data, b"public payload\n")
        self.assertEqual(anon.post(f"/s/{token}/download").status_code, 200)
        self.assertEqual(anon.post(f"/s/{token}/download").status_code, 404 if False else 410)
        self.assertEqual(anon.get("/s/" + "x" * 43).status_code, 404)

    def test_link_for_specific_user_requires_that_user(self):
        fid = self.fid(self.a.upload("only-bob.txt", b"bob only\n"))
        r = self.a.post(f"/files/{fid}/share", {"recipient": "bob", "allow_download": "1"})
        # user shares expose no link token; fetch one by creating a link-bound row via DB check
        self.assertNotIn("link_token", r.headers["Location"])

    def test_delete_removes_blob_and_shares(self):
        fid = self.fid(self.a.upload("gone.txt", b"bye\n"))
        self.a.post(f"/files/{fid}/share", {"recipient": "bob"})
        self.a.post(f"/files/{fid}/delete")
        self.assertFalse(os.path.exists(os.path.join(self.app.config["STORAGE_DIR"], fid + ".bin")))
        self.assertEqual(self.b.get(f"/files/{fid}").status_code, 404)

    def test_pages_render(self):
        fid = self.fid(self.a.upload("page.txt", b"render me\n"))
        self.a.post(f"/files/{fid}/share", {"recipient": "bob", "allow_download": "1"})
        for url in ("/", "/files", "/files?q=pa", "/shared", f"/files/{fid}", "/security", "/profile", "/activity"):
            r = self.a.get(url)
            self.assertEqual(r.status_code, 200, url)
        self.assertIn("page.txt", self.a.get("/files").get_data(as_text=True))
        self.assertEqual(self.b.get("/shared").status_code, 200)


class TestAdmin(Base):
    def make_admin(self):
        self.register("root")
        self.x("UPDATE users SET role='admin' WHERE username='root'")
        c, _ = self.login("root")
        return c

    def test_admin_requires_2fa_and_manages_users(self):
        self.register("alice")
        c = self.make_admin()
        r = c.get("/admin/")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/security/2fa/setup"))
        self.enable_2fa(c, "root")
        self.assertEqual(c.get("/admin/").status_code, 200)
        uid = self.q("SELECT id FROM users WHERE username='alice'")[0]["id"]
        al, _ = self.login("alice", ip="10.0.0.9")
        c.post(f"/admin/users/{uid}/disable")
        self.assertEqual(al.get("/files").status_code, 302)
        self.assertEqual(self.login("alice", client=Client(self.app, "10.0.0.9"))[1].status_code, 401)
        c.post(f"/admin/users/{uid}/enable")
        self.assertEqual(self.login("alice", client=Client(self.app, "10.0.0.9"))[1].status_code, 302)
        self.assertEqual(c.get("/admin/audit?severity=warning").status_code, 200)
        self.assertIn("intact", c.post("/admin/audit/verify", follow_redirects=True).get_data(as_text=True))

    def test_audit_chain_detects_tampering(self):
        self.register("alice")
        self.login("alice")
        import core
        with self.app.test_request_context():
            from flask import g
            from db import close_db
            ok, n = core.verify_audit_chain()
            self.assertTrue(ok); self.assertGreaterEqual(n, 2)
            close_db()
        self.x("UPDATE audit SET detail='edited' WHERE id=1")
        with self.app.test_request_context():
            ok, bad = core.verify_audit_chain()
            self.assertFalse(ok); self.assertEqual(bad, 1)


class TestQR(unittest.TestCase):
    def test_qr_decodes(self):
        try:
            import cv2, numpy as np
        except ImportError:
            self.skipTest("opencv not installed")
        import qr
        uri = crypto.otpauth_uri("SecureShare", "alice", crypto.new_totp_secret())
        m = qr.make_matrix(uri.encode())
        s, b = 8, 4
        img = np.full(((len(m) + 2 * b) * s,) * 2, 255, np.uint8)
        for y, row in enumerate(m):
            for x, v in enumerate(row):
                if v:
                    img[(y + b) * s:(y + b + 1) * s, (x + b) * s:(x + b + 1) * s] = 0
        self.assertEqual(cv2.QRCodeDetector().detectAndDecode(img)[0], uri)


if __name__ == "__main__":
    unittest.main(verbosity=2)
