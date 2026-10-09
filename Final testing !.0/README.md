# CyberAware — Minimal Cyber Awareness App

A full-featured, visually stunning cybersecurity awareness web application built with **Python (Flask)**, **HTML**, **CSS**, and **JavaScript**.

Designed for everyone — employees, students, and the general public.

## Features

- **🎯 Interactive Quizzes & Comprehensive Exam** — 495+ questions across 11 topics; the 55-question, 60-minute all-topics exam is server-scored, requires 70% to pass, and awards a Foundation, Developing, Proficient, or Advanced proficiency level
- **📚 Educational Content** — Topic cards with best practices and "Did You Know?" facts
- **🎣 Spot the Phish** — Realistic email mockups; click to find red flags
- **🔐 Password Strength Checker** — Real-time entropy, crack-time estimates, and improvement tips
- **📊 11-Topic Defense Radar & Mastery** — Multi-axis radar, domain proficiency tiers, streaks, and achievements
- **🏆 Verified Training Certificate** — Generates official cryptographic credential with high-resolution PNG download and print layout
- **📑 Compliance & Progress Reports** — Exportable structured training audit report (PDF / JSON format)
- **🛡️ Two-Factor Authentication (2FA / TOTP)** — RFC 6238 authenticator app integration with one-time emergency backup codes
- **👥 Multi-user accounts** — Registration, administrator approval, secure password hashing, sessions, user-specific progress, and protected administrator overview
- **🔒 Progressive account security** — Newly registered users can complete two quizzes after approval; 2FA setup is required before further training and progress features, while existing accounts keep their current access

## Design

Professional dark security-console theme with lime and coral accents, structured learning flows, accessible quiz controls, floating toast notifications, and responsive layouts for desktop and mobile.

## Quick Start

### Requirements

- Python 3.8+
- pip

### Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5002** in your browser. Set the `PORT` environment variable to use another available port.

### Email configuration

Registration and administrator approval do not send email. SMTP is optional and is used for password-reset messages. Configure it before starting Flask if password-reset email is needed:

```powershell
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_PORT = "587"
$env:SMTP_USERNAME = "your-smtp-user"
$env:SMTP_PASSWORD = "your-smtp-password"
$env:SMTP_FROM = "CyberAware <no-reply@example.com>"
$env:SMTP_USE_TLS = "true"
python app.py
```

For implicit SSL SMTP services, set `SMTP_USE_SSL=true` and `SMTP_USE_TLS=false` (commonly port `465`). SMTP credentials are never sent to the browser. Registration and approval work without SMTP; password-reset emails require it.

### Production configuration

For production, set a stable secret key of at least 32 characters, enable secure cookies, and disable debug mode. The application fails at startup if these requirements are not met:

```powershell
$env:APP_ENV = "production"
$env:SECRET_KEY = "<a securely generated secret of at least 32 characters>"
$env:SESSION_COOKIE_SECURE = "true"
$env:FLASK_DEBUG = "false"
```

Forwarded client IPs are ignored unless the immediate peer is within `TRUSTED_PROXY_CIDRS`. Set this to the comma-separated IP addresses or CIDR ranges of the proxies that connect directly to Flask, and prevent clients from reaching Flask except through those proxies. Rate-limit counters are stored in SQLite, so workers on the same host that share the app database also share limits. Use a networked shared store before deploying multiple hosts.

### API Endpoints

| Method | Endpoint                    | Description                                           |
| ------ | --------------------------- | ----------------------------------------------------- |
| GET    | `/api/topics`               | List quiz topics                                      |
| GET    | `/api/learning?topic=<id>`  | Learning resources for a topic                        |
| GET    | `/api/quiz/<topic>`         | Start a quiz attempt and fetch questions (`?difficulty=`, `?limit=`); answer keys are not returned |
| POST   | `/api/progress/quiz`        | Submit `attempt_id` and selected answers for server-side scoring |
| GET    | `/api/exam`                 | Start a randomized 55-question exam covering all 11 topics      |
| POST   | `/api/exam/submit`          | Submit answers for server-side exam scoring and proficiency    |
| GET    | `/api/phishing-examples`    | Phishing email examples                               |
| POST   | `/api/check-password`       | Analyze password strength (`{"password": "..."}`)     |
| POST   | `/api/auth/register`        | Create a user account                                 |
| POST   | `/api/auth/login`           | Sign in (returns 2FA challenge if active)             |
| POST   | `/api/auth/login/2fa`       | Verify TOTP / backup code during login                |
| POST   | `/api/admin/users/<id>/approve` | Approve a pending user (administrator only)       |
| POST   | `/api/auth/2fa/setup`       | Generate TOTP secret & QR code data                   |
| POST   | `/api/auth/2fa/enable`      | Activate 2FA and receive 6 backup codes               |
| POST   | `/api/auth/2fa/disable`     | Disable 2FA                                           |
| GET    | `/api/certificate`          | Fetch certificate metadata after passing the comprehensive exam |
| GET    | `/api/progress/report`      | Generate structured training audit report             |
| DELETE | `/api/progress`              | Request a progress reset (learners); administrators reset their own progress immediately |
| GET    | `/api/progress/reset-request` | Check the signed-in learner's reset request status    |
| POST   | `/api/admin/progress-reset-requests/<id>` | Approve or reject a learner's progress reset request (administrator only) |
| GET    | `/health`                   | Health check                                          |

## Project Structure

```
Minimal_Cyber_Awareness/
├── app.py                 # Flask server + API
├── quiz_data.py           # Question bank (495+ questions across 11 topics)
├── phishing_data.py       # Phishing email examples
├── requirements.txt
├── templates/
│   └── index.html         # SPA shell
└── static/
    ├── css/
    │   └── style.css      # Design system
    └── js/
        ├── app.js         # Router & core
        ├── quiz.js        # Quiz engine
        ├── phishing.js    # Phishing simulator
        ├── password.js    # Password checker
        └── dashboard.js   # Progress (localStorage)
```

## Notes

- User accounts and progress are stored in the local `cyberaware.db` SQLite database. The first registered account is given administrator access; later accounts need administrator approval before training.
- Passwords entered in the strength checker are analyzed and never stored or logged.
- All phishing scenarios are simulated and educational only.
- Works offline for previously loaded content once the page has been visited (static assets + localStorage).

## License

Educational / demonstration use.
