from urllib.parse import urlparse

from quiz_data import QUESTIONS, QUIZ_TOPICS
from app import LEARNING_RESOURCES


def test_catalog_contains_cyber_law_and_governance_questions():
    topic_ids = {topic["id"] for topic in QUIZ_TOPICS}
    assert {"cyber-law", "governance", "cyber-threat-management"}.issubset(topic_ids)
    assert sum(len(questions) for questions in QUESTIONS.values()) >= 495


def test_every_topic_has_at_least_fifteen_questions_per_difficulty():
    for topic in QUIZ_TOPICS:
        for difficulty in ("beginner", "intermediate", "advanced"):
            assert sum(
                question["difficulty"] == difficulty
                for question in QUESTIONS[topic["id"]]
            ) >= 15, f"{topic['id']} is short of 15 {difficulty} questions"


def test_cyber_threat_management_has_learning_resources_and_questions():
    topic_id = "cyber-threat-management"
    assert len(LEARNING_RESOURCES[topic_id]) >= 3
    assert all(resource["url"].startswith("https://") for resource in LEARNING_RESOURCES[topic_id])
    assert len(QUESTIONS[topic_id]) >= 45


def test_questions_have_valid_answer_indexes_and_unique_ids():
    for questions in QUESTIONS.values():
        ids = [question["id"] for question in questions]
        assert len(ids) == len(set(ids))
        for question in questions:
            assert 0 <= question["correct"] < len(question["options"])
            assert question["difficulty"] in {"beginner", "intermediate", "advanced"}


def test_question_bank_has_distinct_prompts_and_choice_sets():
    prompts = set()
    choice_sets = set()
    for topic_id, questions in QUESTIONS.items():
        for question in questions:
            prompt = " ".join(question["question"].casefold().split())
            assert prompt not in prompts, f"Repeated prompt: {topic_id}/{question['id']}"
            prompts.add(prompt)

            normalized_options = {
                " ".join(option.casefold().split())
                for option in question["options"]
            }
            assert len(normalized_options) == len(question["options"]), (
                f"Repeated answer choices: {topic_id}/{question['id']}"
            )
            choice_set = tuple(sorted(normalized_options))
            assert choice_set not in choice_sets, (
                f"Repeated answer-choice set: {topic_id}/{question['id']}"
            )
            choice_sets.add(choice_set)
            assert question["explanation"].strip()

            if question["id"].startswith("extra-"):
                assert "stated risk" not in question["explanation"]
                assert "controlled security process" not in question["explanation"]


def test_question_sources_use_https_without_us_government_websites():
    for questions in QUESTIONS.values():
        for question in questions:
            source = question.get("source")
            if not source:
                continue
            parsed_url = urlparse(source)
            assert parsed_url.scheme == "https"
            assert parsed_url.hostname
            hostname = parsed_url.hostname.lower()
            assert not hostname.endswith(".gov") or hostname.endswith(".gov.uk")