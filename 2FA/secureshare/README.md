# SecureShare — 2FA file sharing

Flask + SQLite + vanilla HTML/CSS/JS. Two runtime dependencies (Flask, cryptography). TOTP and the QR-code generator are implemented in-repo, so there is nothing else to install.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
flask --app app create-admin admin you@example.com    # prompts for a password (12+ chars)
python app.py                                         # http://127.0.0.1:5000
python -m unittest discover -s tests -v               # 22 end-to-end tests
```

Anyone can register as a normal user. Administrators can only be created with the command above, and must turn on 2FA before the admin area opens.

**Emails** (reset links, new-device codes, security notices) are written to `instance/outbox.log` and the console until you set `SS_SMTP_HOST` (plus `SS_SMTP_PORT`, `SS_SMTP_USER`, `SS_SMTP_PASSWORD`, `SS_MAIL_FROM`).

## Features → where they live

| Area | What you get | Code |
|---|---|---|
| Accounts | Register, sign in/out, change password, forgot/reset password (single-use, 30 min), profile, admin & user roles | `views_auth.py` |
| 2FA | QR setup, 6-digit TOTP (RFC 6238, ±1 step, replay-blocked), 10 single-use backup codes, enable/disable (needs password + code), regenerate codes | `views_auth.py`, `crypto.py`, `qr.py` |
| Devices | Active-session list with revoke, known-device list, new-device verification (TOTP, or an emailed 8-digit code when 2FA is off), "trust this device 30 days" | `views_auth.py`, `core.py` |
| Brute-force defence | 5 wrong codes kill a challenge; 5 consecutive failures lock the account with escalating timeouts (15 min → 24 h); per-IP throttle | `core.py` |
| Upload | Extension allow-list + magic-byte check, size limit, per-user quota, filename sanitisation, SHA-256 duplicate detection, malware scan, progress bar, timestamps, owner | `scanner.py`, `views_files.py`, `static/js/app.js` |
| Encryption | Random AES-256-GCM key per file, wrapped by a vault key (HKDF from the master key); file id bound as AAD; SHA-256 verified on every download | `views_files.py`, `crypto.py` |
| Sharing | Recipient, viewer/collaborator permission, expiry, max downloads, download on/off, reshare on/off, random 256-bit link tokens (only hashes stored), cascade revoke | `views_files.py` |
| Monitoring | HMAC-chained audit log, alerts for password spraying, brute force, mass download, malware, integrity failure, new-IP sign-in; admin dashboard | `core.py`, `views_admin.py` |

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `SS_COOKIE_SECURE` | `0` | **Set `1` behind HTTPS** (adds Secure cookies + HSTS) |
| `SS_TRUST_PROXY` | `0` | Set `1` behind a reverse proxy so client IPs are correct |
| `SS_MASTER_KEY` | file `instance/master.key` | 32 random bytes, base64. Prefer this (or a KMS) in production |
| `SS_MAX_UPLOAD_MB` / `SS_USER_QUOTA_MB` | `25` / `500` | Limits |
| `SS_CLAMD_HOST`, `SS_CLAMD_PORT` or `SS_CLAMD_SOCKET` | unset | ClamAV daemon for real malware scanning |
| `SS_REQUIRE_AV` | `0` | `1` = refuse uploads when no scanner is reachable |
| `SS_ALLOW_PUBLIC_LINKS` | `1` | `0` = only user-to-user sharing |
| `SS_BASE_URL` | request host | Used in emailed links |

## Know the limits

- **Back up `instance/master.key`** (or `SS_MASTER_KEY`). Without it every file and 2FA secret is unrecoverable. Keep it off the same disk as the vault in production.
- Files are encrypted in one piece, so they're held in memory during upload/download. That's why the default cap is 25 MB; larger files need chunked encryption.
- Without ClamAV the scanner only has built-in checks (EICAR signature, executables, macros, scripted PDFs, zip bombs). That is a safety net, not antivirus.
- Registration doesn't verify the email address, and the same reset/verification mail goes to whatever address is on file.
- Run behind HTTPS (e.g. gunicorn + nginx/Caddy) for anything beyond local use. A security review is worthwhile before holding sensitive data.
