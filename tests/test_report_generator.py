from app.scanner.report_generator import _generate_with_fallback
from app.scanner import report_generator


class ServiceUnavailable(Exception):
    code = 503


def test_503_retries_then_uses_fallback_model():
    calls = []
    waits = []

    def generate(model):
        calls.append(model)
        if model == "gemini-3.5-flash-lite":
            raise ServiceUnavailable()
        return "summary from fallback model"

    result = _generate_with_fallback(
        generate,
        models=("gemini-3.5-flash-lite", "gemini-3.8-flash"),
        sleep_fn=waits.append,
    )

    assert result == "summary from fallback model"
    assert calls == [
        "gemini-3.5-flash-lite",
        "gemini-3.5-flash-lite",
        "gemini-3.5-flash-lite",
        "gemini-3.8-flash",
    ]
    assert waits == [1, 2, 4]


def test_gemini_client_uses_20_second_request_timeout(monkeypatch):
    captured = {}
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_client(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(report_generator.genai, "Client", fake_client)

    report_generator._client()

    assert captured["http_options"].timeout == 20_000
    assert captured["http_options"].retry_options.attempts == 1
