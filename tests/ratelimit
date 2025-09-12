import os, time
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_rate_limit_headers_and_drop(monkeypatch):
    # Enable rate limit aggressively for test
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "5")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")

    # force app to read env by touching /debug/config (our middleware reads on import; tests share state)
    cfg = client.get("/debug/config").json()
    assert cfg["RATE_LIMIT_ENABLED"] is not None  # sanity

    drops = 0
    # send a burst that should overflow the bucket
    for _ in range(8):
        r = client.post("/chat", json={"prompt": "rate-limit test"})
        if r.status_code == 429:
            drops += 1
            assert r.headers.get("Retry-After") is not None
        else:
            # Should include remaining tokens headers on success path
            assert "X-RateLimit-Limit" in r.headers
            assert "X-RateLimit-Remaining" in r.headers

    # We expect at least one drop in this small window
    assert drops >= 1
    m = client.get("/metrics").json()
    assert m.get("rate_limit_dropped", 0) >= drops
