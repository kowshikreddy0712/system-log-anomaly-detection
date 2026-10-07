import json

from urllib.error import HTTPError

from services.ai_assistant import (
    AIServiceError,
    generate_event_summary,
    generate_incident_report,
    triage_event,
)


def test_local_event_summary_and_triage(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    row = {
        "event_id": "EVT-1",
        "service": "sshd",
        "event_class": "AUTH_FAIL",
        "severity": "HIGH",
        "risk_score": 0.82,
        "message": "Failed password for root",
    }
    explanation = {
        "headline": "Repeated failed SSH authentication",
        "evidence": ["Repeated failures detected"],
        "actions": ["Review source host"],
    }

    summary, summary_used_ai = generate_event_summary(row, explanation)
    triage, triage_used_ai = triage_event(row, explanation)

    assert "Repeated failed SSH authentication" in summary
    assert "**Event context:**" in summary
    assert "**Why it was flagged:**" in summary
    assert "Repeated failures detected" in summary
    assert "**Recommended analyst actions:**" in summary
    assert "stale credentials" in summary
    assert "P2" in summary or "HIGH" in summary
    assert "P2" in triage
    assert not summary_used_ai
    assert not triage_used_ai


def test_remote_event_summary_requests_soc_triage_format(monkeypatch):
    from services import ai_assistant

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    prompts = []
    monkeypatch.setattr(ai_assistant, "_request", lambda prompt: prompts.append(prompt) or "SOC note")

    summary, used_ai = generate_event_summary(
        {
            "event_id": "EVT-7",
            "timestamp": "2026-01-01 12:00:00",
            "hostname": "sensitive-host",
            "src_host": "192.0.2.10",
            "service": "sshd",
            "event_class": "AUTH_FAIL",
            "severity": "HIGH",
            "risk_score": 0.8,
            "detection_method": "DBSCAN",
        },
        {
            "headline": "Repeated failed SSH authentication",
            "evidence": ["Failures from sensitive-host (192.0.2.10) in a short time window"],
            "actions": ["Check whether the source is authorized"],
        },
    )

    assert used_ai
    assert summary == "SOC note"
    assert "SOC analyst" in prompts[0]
    assert "Escalation criteria" in prompts[0]
    assert "Do not invent withheld host, account, source, or raw-log data." in prompts[0]
    assert "DBSCAN flagged the event" in prompts[0]
    assert "Isolation Forest flagged" not in prompts[0]
    assert "Detection method:" not in prompts[0]
    assert "[redacted]" in prompts[0]
    assert "sensitive-host" not in prompts[0]
    assert "192.0.2.10" not in prompts[0]


def test_local_event_summary_includes_only_relevant_detector_details(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    row = {
        "event_id": "EVT-2",
        "event_class": "SERVICE_ERROR",
        "severity": "HIGH",
        "risk_score": 0.8,
        "detection_method": "DBSCAN",
        "dbscan_noise": True,
        "iforest_noise": False,
        "tmpl_freq": 2,
    }
    explanation = {
        "headline": "A rare event pattern was flagged",
        "evidence": [
            "**DBSCAN:** outside common activity groups",
            "**Isolation Forest:** model score disagreed with the detector label",
        ],
        "actions": ["Review nearby service errors"],
    }

    summary, used_ai = generate_event_summary(row, explanation)

    assert "DBSCAN" in summary
    assert "message pattern appears only 2 time(s)" in summary
    assert "Isolation Forest" not in summary
    assert not used_ai


def test_local_incident_report_is_explicit(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    report, report_used_ai = generate_incident_report("3 anomalies")

    assert "AI is not configured" in report
    assert not report_used_ai


def test_gemini_key_enables_ai_and_takes_precedence(monkeypatch):
    from services.ai_assistant import ai_provider_name

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    assert ai_provider_name() == "Gemini"


def test_gemini_request_uses_key_header_and_extracts_response(monkeypatch):
    from services import ai_assistant

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({
                "candidates": [{"content": {"parts": [{"text": "Alert explanation"}]}}],
            }).encode("utf-8")

    def fake_urlopen(request, timeout):
        assert request.get_header("X-goog-api-key") == "test-gemini-key"
        assert timeout == 30
        assert request.full_url.endswith("/models/gemini-2.5-flash:generateContent")
        body = json.loads(request.data.decode("utf-8"))
        assert body["contents"][0]["parts"][0]["text"] == "Explain this alert"
        return FakeResponse()

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(ai_assistant, "urlopen", fake_urlopen)

    assert ai_assistant._request("Explain this alert") == "Alert explanation"


def test_gemini_http_error_is_reported_without_fallback(monkeypatch):
    from services import ai_assistant

    def fail_request(*_args, **_kwargs):
        raise HTTPError("https://example.invalid", 401, "Unauthorized", None, None)

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(ai_assistant, "urlopen", fail_request)

    try:
        ai_assistant._request("Explain this alert")
    except AIServiceError as exc:
        assert "HTTP 401" in str(exc)
    else:
        raise AssertionError("A Gemini API error should be shown to the user.")


def test_gemini_503_retries_then_returns_response(monkeypatch):
    from services import ai_assistant

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({
                "candidates": [{"content": {"parts": [{"text": "Recovered response"}]}}],
            }).encode("utf-8")

    calls = []

    def retry_then_succeed(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise HTTPError("https://example.invalid", 503, "Unavailable", None, None)
        return FakeResponse()

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(ai_assistant, "urlopen", retry_then_succeed)
    monkeypatch.setattr(ai_assistant.time, "sleep", lambda *_args: None)
    monkeypatch.setattr(ai_assistant.random, "uniform", lambda *_args: 0)

    assert ai_assistant._request("Retry transient failures") == "Recovered response"
    assert len(calls) == 2


def test_gemini_503_after_retries_has_actionable_message(monkeypatch):
    from services import ai_assistant

    calls = []

    def fail_request(*_args, **_kwargs):
        calls.append(1)
        raise HTTPError("https://example.invalid", 503, "Unavailable", None, None)

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(ai_assistant, "urlopen", fail_request)
    monkeypatch.setattr(ai_assistant.time, "sleep", lambda *_args: None)
    monkeypatch.setattr(ai_assistant.random, "uniform", lambda *_args: 0)

    try:
        ai_assistant._request("Temporary outage")
    except AIServiceError as exc:
        assert "temporarily unavailable" in str(exc)
        assert "wait a minute" in str(exc)
    else:
        raise AssertionError("A persistent Gemini 503 should be reported to the user.")
    assert len(calls) == ai_assistant._GEMINI_MAX_ATTEMPTS


def test_gemini_remote_disconnect_retries_then_returns_response(monkeypatch):
    from http.client import RemoteDisconnected

    from services import ai_assistant

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({
                "candidates": [{"content": {"parts": [{"text": "Recovered after disconnect"}]}}],
            }).encode("utf-8")

    calls = []

    def disconnect_then_succeed(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RemoteDisconnected("Remote end closed connection without response")
        return FakeResponse()

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(ai_assistant, "urlopen", disconnect_then_succeed)
    monkeypatch.setattr(ai_assistant.time, "sleep", lambda *_args: None)
    monkeypatch.setattr(ai_assistant.random, "uniform", lambda *_args: 0)

    assert ai_assistant._request("Retry dropped connection") == "Recovered after disconnect"
    assert len(calls) == 2


def test_gemini_persistent_remote_disconnect_is_reported(monkeypatch):
    from http.client import RemoteDisconnected

    from services import ai_assistant

    calls = []

    def fail_request(*_args, **_kwargs):
        calls.append(1)
        raise RemoteDisconnected("Remote end closed connection without response")

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(ai_assistant, "urlopen", fail_request)
    monkeypatch.setattr(ai_assistant.time, "sleep", lambda *_args: None)
    monkeypatch.setattr(ai_assistant.random, "uniform", lambda *_args: 0)

    try:
        ai_assistant._request("Disconnected request")
    except AIServiceError as exc:
        assert "closed the connection without responding" in str(exc)
    else:
        raise AssertionError("A persistent connection failure should be shown to the user.")
    assert len(calls) == ai_assistant._GEMINI_MAX_ATTEMPTS


def test_investigation_generates_alert_summary_once(monkeypatch):
    from views import investigation

    calls = []

    def fake_summary(row, explanation):
        calls.append((row, explanation))
        return "Explained alert", True

    monkeypatch.setattr(investigation, "generate_event_summary", fake_summary)
    cache = {}
    row = {"event_class": "AUTH_FAIL"}
    explanation = {"headline": "Repeated failed login"}

    investigation._ensure_event_summary("EVT-1", row, explanation, cache)
    investigation._ensure_event_summary("EVT-1", row, explanation, cache)

    assert len(calls) == 1
    assert cache["ai_summary_v3_EVT-1"] == "Explained alert"
    assert cache["ai_summary_v3_EVT-1_remote"] is True
