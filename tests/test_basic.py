from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_policy():
    r = client.get("/policy")
    assert r.status_code == 200
    assert "max_tokens" in r.json()

def test_chat_bad():
    r = client.post("/chat", json={})
    assert r.status_code == 400
