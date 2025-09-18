import os
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_fail_open_path(monkeypatch):
    # Force provider to look "down" and enable fail-open
    monkeypatch.setenv("LLM_PROVIDER", "OLLAMA")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:9999")  # dead endpoint
    monkeypatch.setenv("FAIL_OPEN", "true")

    r = client.post("/chat", json={"prompt": "Are you there?"})
    # With fail-open we should still get 200 + fallback marker
    assert r.status_code == 200
    body = r.json()
    assert body.get("upstream", {}).get("fallback") is True

def test_redaction_counters_increment():
    # include content that should be redacted (typical SSN/phone/email/card)
    prompt = "Contact me at 555-123-4567 or a@b.com. My SSN is 123-45-6789 and card 4242 4242 4242 4242."
    r = client.post("/chat", json={"prompt": prompt})
    assert r.status_code in (200, 403, 502)

    m = client.get("/metrics").json()
    reds = m.get("redactions", {})
    assert isinstance(reds, dict)
    # at least one category should have incremented
    assert any(reds.get(k, 0) > 0 for k in ("ssn", "email", "phone", "card")), reds
