import uuid

import app as app_module
from app import app
import pytest


def test_guest_cannot_access_quiz_api():
    client = app.test_client()
    response = client.get('/api/quiz/phishing')
    assert response.status_code == 401


@pytest.fixture
def reset_test_clients():
    suffix = uuid.uuid4().hex[:10]
    user_client = app.test_client()
    user_response = user_client.post("/api/auth/register", json={
        "username": f"resetuser{suffix}",
        "email": f"resetuser{suffix}@example.com",
        "password": "StrongPass123!",
    })
    assert user_response.status_code == 201
    user_id = user_response.get_json()["user"]["id"]

    admin_client = app.test_client()
    admin_response = admin_client.post("/api/auth/register", json={
        "username": f"resetadmin{suffix}",
        "email": f"resetadmin{suffix}@example.com",
        "password": "StrongPass123!",
    })
    assert admin_response.status_code == 201
    admin_id = admin_response.get_json()["user"]["id"]

    with app_module.get_db() as db:
        db.execute(
            "UPDATE users SET role = 'user', approved = 1, progressive_2fa_required = 0 "
            "WHERE id = ?",
            (user_id,),
        )
        db.execute("UPDATE users SET role = 'admin', approved = 1 WHERE id = ?", (admin_id,))

    try:
        yield user_client, user_id, admin_client, admin_id
    finally:
        with app_module.get_db() as db:
            db.execute("DELETE FROM users WHERE id IN (?, ?)", (user_id, admin_id))


def test_user_progress_reset_waits_for_admin_approval_and_can_be_rejected(reset_test_clients):
    user_client, user_id, admin_client, admin_id = reset_test_clients
    with app_module.get_db() as db:
        db.execute(
            "INSERT INTO quiz_results (user_id, topic, topic_name, score, total, percent, date) "
            "VALUES (?, 'phishing', 'Phishing', 1, 1, 100, ?)",
            (user_id, app_module.utc_now()),
        )
        db.execute(
            "INSERT INTO phishing_results (user_id, example_id, found, total, date) "
            "VALUES (?, 'example-1', 1, 1, ?)",
            (user_id, app_module.utc_now()),
        )
        db.execute(
            "INSERT INTO user_progress (user_id, streak, last_active) VALUES (?, 3, ?)",
            (user_id, app_module.utc_now()),
        )
        db.execute(
            "INSERT INTO comprehensive_exam_results "
            "(user_id, score, total, percent, proficiency_level, passed, date) "
            "VALUES (?, 39, 55, 71, 'Developing', 1, ?)",
            (user_id, app_module.utc_now()),
        )

    request_response = user_client.delete("/api/progress")
    assert request_response.status_code == 202
    assert request_response.get_json()["status"] == "pending"
    assert user_client.delete("/api/progress").status_code == 409

    with app_module.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM phishing_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM comprehensive_exam_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 1
    pending = admin_client.get("/api/admin/summary").get_json()["progress_reset_requests"]
    with app_module.get_db() as db:
        request_id = db.execute(
            "SELECT id FROM progress_reset_requests WHERE user_id = ?", (user_id,)
        ).fetchone()["id"]
    assert any(row["id"] == request_id for row in pending)
    assert admin_client.post(
        f"/api/admin/progress-reset-requests/{request_id}",
        json={"action": "reject"},
    ).status_code == 200
    assert user_client.get("/api/progress/reset-request").get_json()["request"]["status"] == "rejected"

    with app_module.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM phishing_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 1

    assert user_client.delete("/api/progress").status_code == 202
    approval = admin_client.post(
        f"/api/admin/progress-reset-requests/{request_id}",
        json={"action": "approve"},
    )
    assert approval.status_code == 200
    assert approval.get_json()["status"] == "approved"
    assert user_client.get("/api/progress/reset-request").get_json()["request"]["status"] == "approved"
    with app_module.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM phishing_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM user_progress WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM comprehensive_exam_results WHERE user_id = ?", (user_id,)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT role FROM users WHERE id = ?", (admin_id,)
        ).fetchone()["role"] == "admin"


def test_only_admin_can_resolve_reset_requests_and_admin_can_reset_self(reset_test_clients):
    user_client, user_id, admin_client, admin_id = reset_test_clients
    assert user_client.post(
        "/api/admin/progress-reset-requests/1",
        json={"action": "approve"},
    ).status_code == 403
    assert app.test_client().get("/api/progress/reset-request").status_code == 401

    with app_module.get_db() as db:
        db.execute(
            "INSERT INTO quiz_results (user_id, topic, topic_name, score, total, percent, date) "
            "VALUES (?, 'phishing', 'Phishing', 1, 1, 100, ?)",
            (admin_id, app_module.utc_now()),
        )
        db.execute(
            "INSERT INTO user_progress (user_id, streak, last_active) VALUES (?, 2, ?)",
            (admin_id, app_module.utc_now()),
        )

    response = admin_client.delete("/api/progress")
    assert response.status_code == 200
    assert response.get_json()["reset"] is True
    with app_module.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = ?", (admin_id,)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM user_progress WHERE user_id = ?", (admin_id,)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()["role"] == "user"


def _comprehensive_exam_answers(attempt, correct_count=None):
    questions = attempt["questions"]
    correct_count = len(questions) if correct_count is None else correct_count
    answers = []
    for index, question in enumerate(questions):
        topic_id, question_id = question["id"].split(":", 1)
        bank_question = next(
            item
            for item in app_module.get_questions(topic_id)
            if item["id"] == question_id
        )
        selected = bank_question["correct"]
        if index >= correct_count:
            selected = (selected + 1) % len(question["options"])
        answers.append({"question_id": question["id"], "selected": selected})
    return answers


def _complete_all_topic_quizzes(user_id):
    with app_module.get_db() as db:
        for topic in app_module.get_topics():
            db.execute(
                "INSERT INTO quiz_results "
                "(user_id, topic, topic_name, score, total, percent, date) "
                "VALUES (?, ?, ?, 1, 1, 100, ?)",
                (user_id, topic["id"], topic["name"], app_module.utc_now()),
            )


def test_comprehensive_exam_requires_a_quiz_in_every_topic(reset_test_clients):
    user_client, user_id, _, _ = reset_test_clients
    response = user_client.get("/api/exam")
    assert response.status_code == 403
    assert response.get_json()["code"] == "quizzes_required"
    assert set(response.get_json()["missing_topics"]) == {
        topic["name"] for topic in app_module.get_topics()
    }

    with app_module.get_db() as db:
        for topic in app_module.get_topics()[:-1]:
            db.execute(
                "INSERT INTO quiz_results "
                "(user_id, topic, topic_name, score, total, percent, date) "
                "VALUES (?, ?, ?, 1, 1, 100, ?)",
                (user_id, topic["id"], topic["name"], app_module.utc_now()),
            )
        first_topic = app_module.get_topics()[0]
        db.execute(
            "INSERT INTO quiz_results "
            "(user_id, topic, topic_name, score, total, percent, date) "
            "VALUES (?, ?, ?, 1, 1, 100, ?)",
            (user_id, first_topic["id"], first_topic["name"], app_module.utc_now()),
        )

    incomplete = user_client.get("/api/exam")
    assert incomplete.status_code == 403
    assert incomplete.get_json()["missing_topics"] == [app_module.get_topics()[-1]["name"]]

    with app_module.get_db() as db:
        topic = app_module.get_topics()[-1]
        db.execute(
            "INSERT INTO quiz_results "
            "(user_id, topic, topic_name, score, total, percent, date) "
            "VALUES (?, ?, ?, 1, 1, 100, ?)",
            (user_id, topic["id"], topic["name"], app_module.utc_now()),
        )
    eligible_attempt = user_client.get("/api/exam")
    assert eligible_attempt.status_code == 200
    with app_module.get_db() as db:
        db.execute("DELETE FROM quiz_results WHERE user_id = ?", (user_id,))
    submit_without_prerequisites = user_client.post("/api/exam/submit", json={
        "attempt_id": eligible_attempt.get_json()["attempt_id"],
        "answers": _comprehensive_exam_answers(eligible_attempt.get_json()),
    })
    assert submit_without_prerequisites.status_code == 403
    assert submit_without_prerequisites.get_json()["code"] == "quizzes_required"


def test_comprehensive_exam_covers_every_topic_and_awards_certificate(reset_test_clients):
    user_client, user_id, _, _ = reset_test_clients
    assert app.test_client().get("/api/exam").status_code == 401

    _complete_all_topic_quizzes(user_id)
    attempt_response = user_client.get("/api/exam")
    assert attempt_response.status_code == 200
    attempt = attempt_response.get_json()
    questions = attempt["questions"]
    assert len(questions) == 55
    assert attempt["time_limit_seconds"] == 60 * 60
    assert attempt["pass_percent"] == 70
    assert all("correct" not in question for question in questions)
    counts_by_topic = {}
    for question in questions:
        counts_by_topic[question["topic"]] = counts_by_topic.get(question["topic"], 0) + 1
    assert counts_by_topic == {topic["id"]: 5 for topic in app_module.get_topics()}
    for question in questions:
        topic_id, question_id = question["id"].split(":", 1)
        bank_question = next(
            item for item in app_module.get_questions(topic_id)
            if item["id"] == question_id
        )
        assert bank_question["difficulty"] == question["difficulty"]

    submit_response = user_client.post("/api/exam/submit", json={
        "attempt_id": attempt["attempt_id"],
        "answers": _comprehensive_exam_answers(attempt),
    })
    assert submit_response.status_code == 200
    result = submit_response.get_json()
    assert result["percent"] == 100
    assert result["passed"] is True
    assert result["proficiency_level"] == "Advanced"
    assert len(result["results"]) == 55
    assert user_client.post("/api/exam/submit", json={
        "attempt_id": attempt["attempt_id"],
        "answers": _comprehensive_exam_answers(attempt),
    }).status_code == 409

    certificate_response = user_client.get("/api/certificate")
    assert certificate_response.status_code == 200
    certificate = certificate_response.get_json()
    assert certificate["exam_score"] == 100
    assert certificate["proficiency_level"] == "Advanced"
    assert certificate["badge_title"] == "Advanced"

    with app_module.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM comprehensive_exam_results WHERE user_id = ?",
            (user_id,),
        ).fetchone()[0] == 1


def test_failed_comprehensive_exam_records_proficiency_but_does_not_issue_certificate(reset_test_clients):
    user_client, user_id, _, _ = reset_test_clients
    _complete_all_topic_quizzes(user_id)
    attempt = user_client.get("/api/exam").get_json()
    response = user_client.post("/api/exam/submit", json={
        "attempt_id": attempt["attempt_id"],
        "answers": _comprehensive_exam_answers(attempt, correct_count=33),
    })
    assert response.status_code == 200
    result = response.get_json()
    assert result["percent"] == 60
    assert result["passed"] is False
    assert result["proficiency_level"] == "Developing"
    certificate = user_client.get("/api/certificate")
    assert certificate.status_code == 403
    assert certificate.get_json()["code"] == "comprehensive_exam_required"


def test_comprehensive_exam_proficiency_bands():
    assert app_module._proficiency_level(59) == "Foundation"
    assert app_module._proficiency_level(60) == "Developing"
    assert app_module._proficiency_level(74) == "Developing"
    assert app_module._proficiency_level(75) == "Proficient"
    assert app_module._proficiency_level(89) == "Proficient"
    assert app_module._proficiency_level(90) == "Advanced"


def test_guest_cannot_access_phishing_api():
    client = app.test_client()
    response = client.get('/api/phishing-examples')
    assert response.status_code == 401


def test_leaderboard_api_returns_ranking():
    client = app.test_client()
    response = client.get('/api/leaderboard')
    assert response.status_code == 200
    payload = response.get_json()
    assert 'leaderboard' in payload
    assert payload['leaderboard'][0]['points'] >= 0


def test_challenges_api_returns_training_tasks():
    client = app.test_client()
    unique = uuid.uuid4().hex[:10]
    response = client.post('/api/auth/register', json={
        'username': f'challenges{unique}',
        'email': f'challenges{unique}@example.com',
        'password': 'StrongPass123!'
    })
    assert response.status_code == 201
    with app_module.get_db() as db:
        db.execute("UPDATE users SET approved = 1 WHERE id = ?", (response.get_json()['user']['id'],))

    response = client.get('/api/challenges')
    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload['challenges']) >= 3


def test_register_creates_user_waiting_for_approval():
    client = app.test_client()
    unique = uuid.uuid4().hex[:10]
    response = client.post('/api/auth/register', json={
        'username': f'verifyuser{unique}',
        'email': f'verifyuser{unique}@example.com',
        'password': 'StrongPass123!'
    })
    assert response.status_code == 201
    payload = response.get_json()
    assert payload['user']['approved'] is False
    assert 'verification_code' not in payload


def test_registration_waits_for_admin_approval_without_email():
    client = app.test_client()
    unique = uuid.uuid4().hex[:10]
    email = f'approval{unique}@example.com'
    response = client.post('/api/auth/register', json={
        'username': f'approval{unique}',
        'email': email,
        'password': 'StrongPass123!'
    })
    assert response.status_code == 201
    assert response.get_json()['user']['approved'] is False
    assert client.get('/api/quiz/phishing').get_json()['code'] == 'approval_required'
    login_client = app.test_client()
    login_response = login_client.post('/api/auth/login', json={
        'identifier': f'approval{unique}',
        'password': 'StrongPass123!'
    })
    assert login_response.status_code == 403
    assert login_response.get_json()['code'] == 'approval_required'

    with app_module.get_db() as db:
        admin = db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1").fetchone()
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

    admin_client = app.test_client()
    with admin_client.session_transaction() as session:
        session['user_id'] = admin['id']
    approval = admin_client.post(f"/api/admin/users/{user['id']}/approve")
    assert approval.status_code == 200
    approved_login = login_client.post('/api/auth/login', json={
        'identifier': f'approval{unique}',
        'password': 'StrongPass123!'
    })
    assert approved_login.status_code == 200
    assert client.get('/api/quiz/phishing').status_code == 200


def test_two_factor_is_required_after_two_quizzes():
    client = app.test_client()
    unique = uuid.uuid4().hex[:10]
    response = client.post('/api/auth/register', json={
        'username': f'2faGate{unique}',
        'email': f'2fagate{unique}@example.com',
        'password': 'StrongPass123!'
    })
    assert response.status_code == 201
    user_id = response.get_json()['user']['id']
    with app_module.get_db() as db:
        db.execute("UPDATE users SET approved = 1 WHERE id = ?", (user_id,))
        for _ in range(2):
            db.execute(
                "INSERT INTO quiz_results (user_id, topic, topic_name, score, total, percent, date) VALUES (?, 'test', 'Test', 1, 1, 100, ?)",
                (user_id, app_module.utc_now())
            )

    blocked = client.get('/api/phishing-examples')
    assert blocked.status_code == 403
    assert blocked.get_json()['code'] == 'two_factor_setup_required'
    assert client.get('/api/progress').get_json()['code'] == 'two_factor_setup_required'
    password_check = client.post('/api/check-password', json={'password': 'not-stored'})
    assert password_check.status_code == 403
    assert password_check.get_json()['code'] == 'two_factor_setup_required'

    setup = client.post('/api/auth/2fa/setup')
    assert setup.status_code == 200
    secret = setup.get_json()['secret']
    enabled = client.post('/api/auth/2fa/enable', json={
        'secret': secret,
        'code': app_module.generate_totp(secret)
    })
    assert enabled.status_code == 200
    assert client.get('/api/phishing-examples').status_code == 200


def test_admin_can_remove_user_and_associated_progress():
    unique = uuid.uuid4().hex[:10]
    with app_module.get_db() as db:
        admin_cursor = db.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
            (f'admin{unique}', f'admin{unique}@example.com', 'unused', app_module.utc_now())
        )
        admin_id = admin_cursor.lastrowid
        user_cursor = db.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'user', ?)",
            (f'remove{unique}', f'remove{unique}@example.com', 'unused', app_module.utc_now())
        )
        user_id = user_cursor.lastrowid
        db.execute(
            "INSERT INTO user_progress (user_id, streak, last_active) VALUES (?, 1, ?)",
            (user_id, app_module.utc_now())
        )
        db.execute(
            "INSERT INTO quiz_results (user_id, topic, topic_name, score, total, percent, date) VALUES (?, 'test', 'Test', 1, 1, 100, ?)",
            (user_id, app_module.utc_now())
        )
        db.execute(
            "INSERT INTO phishing_results (user_id, example_id, found, total, date) VALUES (?, 'test', 1, 1, ?)",
            (user_id, app_module.utc_now())
        )

    client = app.test_client()
    try:
        with client.session_transaction() as session:
            session['user_id'] = admin_id

        response = client.delete(f'/api/admin/users/{user_id}')
        assert response.status_code == 200

        with app_module.get_db() as db:
            assert db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None
            for table in ('user_progress', 'quiz_results', 'phishing_results'):
                assert db.execute(f"SELECT 1 FROM {table} WHERE user_id = ?", (user_id,)).fetchone() is None

        admin_response = client.delete(f'/api/admin/users/{admin_id}')
        assert admin_response.status_code == 403
    finally:
        with app_module.get_db() as db:
            db.execute("DELETE FROM users WHERE id = ?", (admin_id,))


def test_admin_can_batch_remove_users_without_partial_deletion():
    unique = uuid.uuid4().hex[:10]
    with app_module.get_db() as db:
        admin_cursor = db.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) "
            "VALUES (?, ?, ?, 'admin', ?)",
            (f"batchadmin{unique}", f"batchadmin{unique}@example.com", "unused", app_module.utc_now()),
        )
        admin_id = admin_cursor.lastrowid
        user_ids = []
        for suffix in ("a", "b"):
            cursor = db.execute(
                "INSERT INTO users (username, email, password_hash, role, created_at) "
                "VALUES (?, ?, ?, 'user', ?)",
                (f"batch{suffix}{unique}", f"batch{suffix}{unique}@example.com", "unused", app_module.utc_now()),
            )
            user_id = cursor.lastrowid
            user_ids.append(user_id)
            db.execute(
                "INSERT INTO user_progress (user_id, streak, last_active) VALUES (?, 1, ?)",
                (user_id, app_module.utc_now()),
            )
            db.execute(
                "INSERT INTO quiz_results (user_id, topic, topic_name, score, total, percent, date) "
                "VALUES (?, 'test', 'Test', 1, 1, 100, ?)",
                (user_id, app_module.utc_now()),
            )

    client = app.test_client()
    try:
        with client.session_transaction() as session:
            session["user_id"] = admin_id

        protected = client.delete(
            "/api/admin/users/batch",
            json={"user_ids": [user_ids[0], admin_id]},
        )
        assert protected.status_code == 403
        with app_module.get_db() as db:
            assert db.execute("SELECT 1 FROM users WHERE id = ?", (user_ids[0],)).fetchone()

        removed = client.delete("/api/admin/users/batch", json={"user_ids": user_ids})
        assert removed.status_code == 200
        assert removed.get_json()["deleted_count"] == 2
        with app_module.get_db() as db:
            for user_id in user_ids:
                assert db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None
                assert db.execute("SELECT 1 FROM user_progress WHERE user_id = ?", (user_id,)).fetchone() is None
                assert db.execute("SELECT 1 FROM quiz_results WHERE user_id = ?", (user_id,)).fetchone() is None
            assert db.execute("SELECT 1 FROM users WHERE id = ?", (admin_id,)).fetchone()
    finally:
        with app_module.get_db() as db:
            db.execute("DELETE FROM users WHERE id = ?", (admin_id,))


def test_batch_user_removal_validates_ids_and_requires_admin():
    guest = app.test_client()
    assert guest.delete("/api/admin/users/batch", json={"user_ids": [1]}).status_code == 401

    unique = uuid.uuid4().hex[:10]
    with app_module.get_db() as db:
        admin = db.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) "
            "VALUES (?, ?, ?, 'admin', ?)",
            (f"batchvalid{unique}", f"batchvalid{unique}@example.com", "unused", app_module.utc_now()),
        )
        admin_id = admin.lastrowid

    client = app.test_client()
    try:
        with client.session_transaction() as session:
            session["user_id"] = admin_id
        assert client.delete("/api/admin/users/batch", json={"user_ids": []}).status_code == 400
        assert client.delete("/api/admin/users/batch", json={"user_ids": [True]}).status_code == 400
        assert client.delete("/api/admin/users/batch", json={"user_ids": [999999999]}).status_code == 404
        assert client.delete("/api/admin/users/batch", json={}).status_code == 400
    finally:
        with app_module.get_db() as db:
            db.execute("DELETE FROM users WHERE id = ?", (admin_id,))


def test_admin_page_includes_accessible_batch_user_controls():
    response = app.test_client().get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'id="adminSelectAllUsers"' in html
    assert 'id="adminRemoveSelectedUsers"' in html
    assert 'class="btn btn-threat btn-sm admin-bulk-delete"' in html
    assert "Delete selected users" in html
    assert "Select all eligible users" in html


def test_home_practical_guidance_card_links_to_learning_topics():
    response = app.test_client().get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    guidance_card = html.split("<h3>Practical Guidance</h3>", 1)[0].rsplit("<a ", 1)[-1]
    assert 'class="feature-card" href="#learn"' in guidance_card


def test_quiz_setup_shows_difficulty_based_time_limits():
    response = app.test_client().get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Beginner 10 min" in html
    assert "Intermediate 15 min" in html
    assert "Advanced 20 min" in html
    assert 'aria-label="Quiz timer">--:--</span>' in html
    assert 'id="quizBackBtn"' in html
    assert "30s per question" not in html
