import io
import csv
import ipaddress
import uuid
from datetime import datetime, timezone

import pytest
import app as app_module
from app import app, validate_password_strength, generate_totp


@pytest.fixture(autouse=True)
def no_email(monkeypatch):
    monkeypatch.setattr(app_module, "send_password_reset_email", lambda r, c: None)


def _register(client, suffix=None):
    suffix = suffix or uuid.uuid4().hex[:8]
    res = client.post("/api/auth/register", json={
        "username": f"alice_{suffix}",
        "email": f"alice_{suffix}@example.com",
        "password": "CyberAware-2026!",
    })
    assert res.status_code == 201
    user_id = res.get_json()["user"]["id"]
    with app_module.get_db() as db:
        db.execute("UPDATE users SET approved = 1 WHERE id = ?", (user_id,))
    return res.get_json()["user"]


def _submit_quiz(client, topic, score, **extra):
    attempt = client.get(f"/api/quiz/{topic}").get_json()
    bank = {
        question["id"]: question
        for question in app_module.get_questions(topic)
    }
    answers = []
    for index, question in enumerate(attempt["questions"]):
        correct = bank[question["id"]]["correct"]
        selected = correct if index < score else (correct + 1) % len(question["options"])
        answers.append({"question_id": question["id"], "selected": selected})
    return client.post(
        "/api/progress/quiz",
        json={"attempt_id": attempt["attempt_id"], "answers": answers, **extra},
    )


def test_validate_password_strength_rejects_short_and_common():
    ok, feedback = validate_password_strength("abc")
    assert ok is False
    assert len(feedback) >= 2

    ok, feedback = validate_password_strength("password")
    assert ok is False
    assert any("common" in f.lower() for f in feedback)


def test_validate_password_strength_accepts_strong():
    ok, _ = validate_password_strength("Correct-Horse-Battery-Staple-9!")
    assert ok is True


@pytest.mark.parametrize("value", [1.5, -0.5, float("inf"), float("-inf"), float("nan")])
def test_normalize_int_rejects_non_integer_numbers(value):
    with pytest.raises(ValueError, match="must be an integer"):
        app_module.normalize_int(value, "score")


def test_normalize_int_accepts_integer_inputs():
    assert app_module.normalize_int(2, "score") == 2
    assert app_module.normalize_int(2.0, "score") == 2
    assert app_module.normalize_int("2", "score") == 2


def test_progress_endpoints_reject_fractional_counts():
    client = app.test_client()
    _register(client)
    attempt = client.get("/api/quiz/phishing").get_json()
    answers = [
        {"question_id": question["id"], "selected": 1}
        for question in attempt["questions"]
    ]
    answers[0]["selected"] = 1.5

    quiz = client.post("/api/progress/quiz", json={
        "attempt_id": attempt["attempt_id"],
        "answers": answers,
    })
    assert quiz.status_code == 400
    assert "selected option must be an integer" in quiz.get_json()["error"]

    phishing = client.post("/api/progress/phishing", json={
        "id": "example-1",
        "found": 1.5,
        "total": 2,
    })
    assert phishing.status_code == 400
    assert phishing.get_json()["error"] == "Incomplete phishing result."


def test_quiz_score_is_computed_from_server_answers_and_attempt_is_one_time():
    client = app.test_client()
    _register(client)
    attempt_response = client.get("/api/quiz/phishing?difficulty=beginner")
    attempt = attempt_response.get_json()
    assert attempt_response.status_code == 200
    assert attempt["time_limit_seconds"] == 10 * 60
    seconds_remaining = (
        datetime.fromisoformat(attempt["expires_at"]) - datetime.now(timezone.utc)
    ).total_seconds()
    assert 9 * 60 <= seconds_remaining <= 10 * 60
    assert all("correct" not in question for question in attempt["questions"])
    assert all("explanation" not in question for question in attempt["questions"])

    bank = {
        question["id"]: question
        for question in app_module.get_questions("phishing")
    }
    answers = [
        {
            "question_id": question["id"],
            "selected": bank[question["id"]]["correct"],
        }
        for question in attempt["questions"]
    ]
    submitted = client.post("/api/progress/quiz", json={
        "attempt_id": attempt["attempt_id"],
        "answers": answers,
        "topic": "governance",
        "score": 0,
        "total": 1,
        "percent": 0,
    })
    assert submitted.status_code == 200
    assert submitted.get_json()["score"] == len(answers)
    assert submitted.get_json()["percent"] == 100

    replay = client.post("/api/progress/quiz", json={
        "attempt_id": attempt["attempt_id"],
        "answers": answers,
    })
    assert replay.status_code == 409


@pytest.mark.parametrize(
    ("difficulty", "expected_seconds"),
    [("beginner", 10 * 60), ("intermediate", 15 * 60), ("advanced", 20 * 60)],
)
def test_quiz_attempt_uses_difficulty_specific_time_limit(difficulty, expected_seconds):
    client = app.test_client()
    _register(client)

    response = client.get(f"/api/quiz/phishing?difficulty={difficulty}")
    attempt = response.get_json()

    assert response.status_code == 200
    assert attempt["time_limit_minutes"] * 60 == expected_seconds
    assert attempt["time_limit_seconds"] == expected_seconds
    assert {question["difficulty"] for question in attempt["questions"]} == {difficulty}
    seconds_remaining = (
        datetime.fromisoformat(attempt["expires_at"]) - datetime.now(timezone.utc)
    ).total_seconds()
    assert expected_seconds - 60 <= seconds_remaining <= expected_seconds


def test_all_levels_quiz_time_limit_is_weighted_by_question_mix():
    client = app.test_client()
    _register(client)

    response = client.get("/api/quiz/phishing")
    attempt = response.get_json()
    questions = app_module.get_questions("phishing")
    expected_minutes = round(
        sum(
            app_module.QUIZ_TIME_LIMIT_MINUTES[question["difficulty"]]
            for question in questions
        ) / len(questions)
    )

    assert response.status_code == 200
    assert attempt["time_limit_minutes"] == expected_minutes
    assert attempt["time_limit_seconds"] == expected_minutes * 60


def test_quiz_submission_is_rejected_after_server_deadline():
    client = app.test_client()
    _register(client)
    attempt = client.get("/api/quiz/phishing").get_json()
    with app_module.get_db() as db:
        db.execute(
            "UPDATE quiz_attempts SET expires_at = ? WHERE attempt_id = ?",
            ("2000-01-01T00:00:00+00:00", attempt["attempt_id"]),
        )

    response = client.post("/api/progress/quiz", json={
        "attempt_id": attempt["attempt_id"],
        "answers": [
            {"question_id": question["id"], "selected": -1}
            for question in attempt["questions"]
        ],
    })
    assert response.status_code == 410


def test_all_quiz_catalog_does_not_expose_answer_keys():
    client = app.test_client()
    _register(client)

    response = client.get("/api/quiz")
    assert response.status_code == 200
    questions = [
        question
        for topic_questions in response.get_json().values()
        for question in topic_questions
    ]
    assert len(questions) >= 495
    assert all("correct" not in question for question in questions)
    assert all("explanation" not in question for question in questions)


def test_cyber_threat_management_quiz_and_learning_route_are_available():
    client = app.test_client()
    _register(client)

    quiz_response = client.get("/api/quiz/cyber-threat-management")
    assert quiz_response.status_code == 200
    quiz = quiz_response.get_json()
    assert quiz["count"] == 45
    assert {
        question["difficulty"] for question in quiz["questions"]
    } == {"beginner", "intermediate", "advanced"}
    assert all("correct" not in question for question in quiz["questions"])

    learning_response = client.get("/api/learning?topic=cyber-threat-management")
    assert learning_response.status_code == 200
    learning = learning_response.get_json()
    assert learning["topic"] == "cyber-threat-management"
    assert len(learning["resources"]) >= 3


def test_forwarded_ip_is_used_only_for_configured_trusted_proxies():
    trusted = (ipaddress.ip_network("10.0.0.0/8"),)
    assert app_module._resolve_client_identifier(
        "203.0.113.9",
        "198.51.100.7",
        trusted,
    ) == "203.0.113.9"
    assert app_module._resolve_client_identifier(
        "10.0.0.2",
        "198.51.100.7, 10.0.0.1",
        trusted,
    ) == "198.51.100.7"
    assert app_module._resolve_client_identifier(
        "10.0.0.2",
        "not-an-ip",
        trusted,
    ) == "10.0.0.2"


def test_rate_limits_are_stored_in_shared_database():
    identifier = f"rate-test-{uuid.uuid4().hex}"
    assert app_module._check_rate_limit(identifier, per_minute=2)
    assert app_module._check_rate_limit(identifier, per_minute=2)
    assert not app_module._check_rate_limit(identifier, per_minute=2)


def test_production_runtime_requires_secure_session_configuration():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        app_module._validate_runtime_settings("production", "", True, False)
    with pytest.raises(RuntimeError, match="SESSION_COOKIE_SECURE"):
        app_module._validate_runtime_settings("production", "x" * 32, False, False)
    with pytest.raises(RuntimeError, match="FLASK_DEBUG"):
        app_module._validate_runtime_settings("production", "x" * 32, True, True)
    app_module._validate_runtime_settings("production", "x" * 32, True, False)


def test_register_rejects_weak_password_with_details():
    client = app.test_client()
    res = client.post("/api/auth/register", json={
        "username": "weakpw_user",
        "email": "weakpw@example.com",
        "password": "abc",
    })
    assert res.status_code == 400
    data = res.get_json()
    assert "details" in data
    assert isinstance(data["details"], list)
    assert len(data["details"]) >= 1


def test_login_then_logout_flows_session():
    client = app.test_client()
    user = _register(client)
    logout_res = client.post("/api/auth/logout")
    assert logout_res.status_code == 200

    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 401


def test_health_endpoint_returns_status():
    client = app.test_client()
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "healthy"


def test_api_returns_security_headers():
    client = app.test_client()
    res = client.get("/health")
    assert "X-Content-Type-Options" in res.headers
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert "X-Frame-Options" in res.headers
    assert "Content-Security-Policy" in res.headers
    assert "Referrer-Policy" in res.headers


def test_password_reset_round_trip():
    client = app.test_client()
    suffix = uuid.uuid4().hex[:8]
    email = f"reset_{suffix}@example.com"
    client.post("/api/auth/register", json={
        "username": f"reset_{suffix}",
        "email": email,
        "password": "CyberAware-2026!",
    })
    with app_module.get_db() as db:
        db.execute("UPDATE users SET approved = 1 WHERE email = ?", (email,))

    req_res = client.post("/api/auth/password/reset-request", json={"email": email})
    assert req_res.status_code == 200
    assert "message" in req_res.get_json()

    with app.app_context():
        from app import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT password_reset_code FROM users WHERE email = ?", (email,)
            ).fetchone()
            reset_code = row["password_reset_code"]

    confirm_res = client.post("/api/auth/password/reset-confirm", json={
        "email": email,
        "code": reset_code,
        "new_password": "CyberAware-Refreshed-2026!",
    })
    assert confirm_res.status_code == 200, confirm_res.get_json()

    login_res = client.post("/api/auth/login", json={
        "identifier": email,
        "password": "CyberAware-Refreshed-2026!",
    })
    assert login_res.status_code == 200
    assert login_res.get_json()["user"]["email"] == email


def test_password_reset_confirm_rejects_weak_password():
    client = app.test_client()
    suffix = uuid.uuid4().hex[:8]
    email = f"reset2_{suffix}@example.com"
    client.post("/api/auth/register", json={
        "username": f"reset2_{suffix}",
        "email": email,
        "password": "CyberAware-2026!",
    })

    client.post("/api/auth/password/reset-request", json={"email": email})

    with app.app_context():
        from app import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT password_reset_code FROM users WHERE email = ?", (email,)
            ).fetchone()
            reset_code = row["password_reset_code"]

    confirm_res = client.post("/api/auth/password/reset-confirm", json={
        "email": email,
        "code": reset_code,
        "new_password": "weak",
    })
    assert confirm_res.status_code == 400
    assert "details" in confirm_res.get_json()


def test_change_password_requires_current_password():
    client = app.test_client()
    _register(client)

    bad_res = client.post("/api/auth/password/change", json={
        "current_password": "definitely-wrong",
        "new_password": "CyberAware-New-99!",
    })
    assert bad_res.status_code == 401


def test_change_password_succeeds_with_correct_current():
    client = app.test_client()
    _register(client)

    res = client.post("/api/auth/password/change", json={
        "current_password": "CyberAware-2026!",
        "new_password": "CyberAware-Updated-1!",
    })
    assert res.status_code == 200, res.get_json()

    client.post("/api/auth/logout")
    login_res = client.post("/api/auth/login", json={
        "identifier": "email",
        "password": "CyberAware-Updated-1!",
    })


def test_change_password_with_2fa_requires_code():
    client = app.test_client()
    user = _register(client)

    setup_res = client.post("/api/auth/2fa/setup")
    assert setup_res.status_code == 200
    secret = setup_res.get_json()["secret"]
    enable_res = client.post("/api/auth/2fa/enable", json={
        "secret": secret,
        "code": generate_totp(secret),
    })
    assert enable_res.status_code == 200

    missing = client.post("/api/auth/password/change", json={
        "current_password": "CyberAware-2026!",
        "new_password": "CyberAware-Updated-2!",
    })
    assert missing.status_code == 401

    good = client.post("/api/auth/password/change", json={
        "current_password": "CyberAware-2026!",
        "new_password": "CyberAware-Updated-2!",
        "two_factor_code": generate_totp(secret),
    })
    assert good.status_code == 200, good.get_json()


def test_account_delete_requires_password_and_wipes_data():
    client = app.test_client()
    user = _register(client)

    _submit_quiz(client, "phishing", 5)

    bad = client.delete("/api/auth/account", json={"password": "wrong"})
    assert bad.status_code == 401

    good = client.delete("/api/auth/account", json={"password": "CyberAware-2026!"})
    assert good.status_code == 200

    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 401

    with app.app_context():
        from app import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT COUNT(*) AS n FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            assert row["n"] == 0


def test_progress_csv_export_requires_auth_and_returns_rows():
    client = app.test_client()
    missing = client.get("/api/export/progress.csv")
    assert missing.status_code == 401

    _register(client)

    _submit_quiz(client, "passwords", 4)

    export_res = client.get("/api/export/progress.csv")
    assert export_res.status_code == 200
    assert export_res.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in export_res.headers["Content-Disposition"]

    content = export_res.get_data(as_text=True)
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    assert rows[0][0] == "category"
    assert any("quiz" in r[0] for r in rows[1:])


def test_leaderboard_and_topics_are_public():
    client = app.test_client()
    lb = client.get("/api/leaderboard")
    assert lb.status_code == 200
    assert "leaderboard" in lb.get_json()

    topics = client.get("/api/topics")
    assert topics.status_code == 200
    assert isinstance(topics.get_json(), list)
    assert len(topics.get_json()) >= 8


def test_json_error_handlers_return_json_for_404_and_405():
    client = app.test_client()
    res = client.get("/this-route-does-not-exist")
    assert res.status_code == 404
    assert res.is_json
    assert "error" in res.get_json()

    res2 = client.delete("/api/topics")
    assert res2.status_code == 405
    assert res2.is_json
