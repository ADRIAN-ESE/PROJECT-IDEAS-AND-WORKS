from urllib.parse import urlparse
import uuid

import app as app_module
from app import app


def _approved_client():
    client = app.test_client()
    unique = uuid.uuid4().hex[:10]
    response = client.post("/api/auth/register", json={
        "username": f"learn{unique}",
        "email": f"learn{unique}@example.com",
        "password": "StrongPassword123!",
    })
    assert response.status_code == 201
    with app_module.get_db() as db:
        db.execute("UPDATE users SET approved = 1 WHERE id = ?", (response.get_json()["user"]["id"],))
    return client


def test_learning_resources_exist_for_every_topic():
    client = _approved_client()
    topics_response = client.get("/api/topics")
    assert topics_response.status_code == 200
    topic_ids = {topic["id"] for topic in topics_response.get_json()}

    assert topic_ids
    for topic_id in topic_ids:
        response = client.get("/api/learning", query_string={"topic": topic_id})
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["topic"] == topic_id
        assert len(payload["resources"]) >= 3


def test_learning_resources_use_https_and_exclude_us_government_sources():
    client = _approved_client()
    topic_ids = {
        topic["id"]
        for topic in client.get("/api/topics").get_json()
    }
    for topic_id in topic_ids:
        resources = client.get(
            "/api/learning", query_string={"topic": topic_id}
        ).get_json()["resources"]
        for resource in resources:
            parsed_url = urlparse(resource["url"])
            assert parsed_url.scheme == "https"
            assert parsed_url.hostname
            hostname = parsed_url.hostname.lower()
            assert not hostname.endswith(".gov") or hostname.endswith(".gov.uk")


def test_new_public_interest_learning_resources_are_available():
    expected_resources = {
        "phishing": {
            "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online",
            "https://stopthinkfraud.campaign.gov.uk/",
        },
        "passwords": {
            "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/use-a-strong-and-separate-password-for-email",
        },
        "social-engineering": {
            "https://stopthinkfraud.campaign.gov.uk/",
        },
        "safe-browsing": {
            "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online",
        },
    }
    client = _approved_client()

    for topic_id, expected_urls in expected_resources.items():
        response = client.get(
            "/api/learning", query_string={"topic": topic_id}
        )
        assert response.status_code == 200
        actual_urls = {resource["url"] for resource in response.get_json()["resources"]}
        assert expected_urls <= actual_urls


def test_quiz_review_keeps_relevant_source_links_without_recommendations():
    topic_ids = {
        topic["id"]
        for topic in app_module.get_topics()
    }

    for topic_id in topic_ids:
        client = _approved_client()
        attempt_response = client.get(f"/api/quiz/{topic_id}?limit=1")
        assert attempt_response.status_code == 200
        attempt = attempt_response.get_json()
        question = attempt["questions"][0]
        bank_question = next(
            item
            for item in app_module.get_questions(topic_id)
            if item["id"] == question["id"]
        )

        result_response = client.post("/api/progress/quiz", json={
            "attempt_id": attempt["attempt_id"],
            "answers": [{
                "question_id": question["id"],
                "selected": (bank_question["correct"] + 1) % len(question["options"]),
            }],
        })
        assert result_response.status_code == 200
        payload = result_response.get_json()
        result = payload["results"][0]
        assert result["explanation"]
        assert result["source"]
        assert result["source_label"]
        assert "study_recommendations" not in payload

        if result["source_is_related"]:
            topic_resource_urls = {
                resource["url"]
                for resource in app_module.LEARNING_RESOURCES[topic_id]
            }
            assert result["source"] in topic_resource_urls


def test_quiz_sources_exclude_us_government_websites():
    sources = (
        resource["url"]
        for resources in app_module.LEARNING_RESOURCES.values()
        for resource in resources
    )
    question_sources = (
        question["source"]
        for questions in app_module.get_all_questions().values()
        for question in questions
        if question.get("source")
    )

    for source in (*sources, *question_sources):
        hostname = urlparse(source).hostname
        assert hostname
        assert not hostname.lower().endswith(".gov") or hostname.lower().endswith(".gov.uk")
