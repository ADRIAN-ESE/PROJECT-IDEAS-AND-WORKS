import hashlib
import json
import uuid
import app as app_module
from app import app, generate_totp, generate_totp_secret, verify_totp


def test_totp_generation_and_verification():
    secret = generate_totp_secret()
    assert len(secret) == 32
    code = generate_totp(secret)
    assert len(code) == 6
    assert code.isdigit()
    assert verify_totp(secret, code) is True
    assert verify_totp(secret, "999999" if code != "999999" else "000000") is False


def test_2fa_setup_enable_and_login_flow():
    client = app.test_client()
    unique = uuid.uuid4().hex[:8]
    username = f"user2fa_{unique}"
    email = f"user2fa_{unique}@example.com"
    password = "StrongPassword123!"

    # Register user
    import app as app_module
    reg_res = client.post('/api/auth/register', json={
        'username': username,
        'email': email,
        'password': password
    })
    assert reg_res.status_code == 201
    with app_module.get_db() as db:
        db.execute("UPDATE users SET approved = 1 WHERE username = ?", (username,))

    # Setup 2FA
    setup_res = client.post('/api/auth/2fa/setup')
    assert setup_res.status_code == 200
    setup_data = setup_res.get_json()
    secret = setup_data['secret']
    assert 'otpauth_url' in setup_data

    # Enable 2FA with valid TOTP code
    valid_code = generate_totp(secret)
    enable_res = client.post('/api/auth/2fa/enable', json={
        'secret': secret,
        'code': valid_code
    })
    assert enable_res.status_code == 200
    enable_data = enable_res.get_json()
    assert enable_data['user']['two_factor_enabled'] is True
    assert len(enable_data['backup_codes']) == 6
    backup_code = enable_data['backup_codes'][0]

    # Logout
    client.post('/api/auth/logout')

    # Try login -> should require 2FA
    login_res = client.post('/api/auth/login', json={
        'identifier': username,
        'password': password
    })
    assert login_res.status_code == 200
    login_data = login_res.get_json()
    assert login_data.get('two_factor_required') is True

    # Complete 2FA login with backup code
    login_2fa_res = client.post('/api/auth/login/2fa', json={
        'code': backup_code
    })
    assert login_2fa_res.status_code == 200
    assert login_2fa_res.get_json()['user']['username'] == username

    # Complete each topic quiz before attempting the all-topics exam.
    with app_module.get_db() as db:
        for topic in app_module.get_topics():
            db.execute(
                "INSERT INTO quiz_results "
                "(user_id, topic, topic_name, score, total, percent, date) "
                "VALUES (?, ?, ?, 1, 1, 100, ?)",
                (reg_res.get_json()['user']['id'], topic["id"], topic["name"], app_module.utc_now()),
            )

    # Complete the all-topics exam before requesting the verified certificate.
    exam = client.get("/api/exam").get_json()
    exam_answers = []
    for question in exam["questions"]:
        topic_id, question_id = question["id"].split(":", 1)
        bank_question = next(
            item for item in app_module.get_questions(topic_id)
            if item["id"] == question_id
        )
        exam_answers.append({
            "question_id": question["id"],
            "selected": bank_question["correct"],
        })
    exam_result = client.post("/api/exam/submit", json={
        "attempt_id": exam["attempt_id"],
        "answers": exam_answers,
    })
    assert exam_result.status_code == 200
    assert exam_result.get_json()["passed"] is True

    # Fetch certificate
    cert_res = client.get('/api/certificate')
    assert cert_res.status_code == 200
    cert_data = cert_res.get_json()
    assert cert_data['cert_id'].startswith('CYBER-')
    assert cert_data['username'] == username
    assert cert_data['proficiency_level'] == 'Advanced'

    # Fetch progress report
    report_res = client.get('/api/progress/report')
    assert report_res.status_code == 200
    report_data = report_res.get_json()
    assert 'metrics' in report_data
    assert 'topics' in report_data
