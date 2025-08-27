from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_dashboard_and_logs_endpoints():
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")

    r = client.get("/admin/logs")
    assert r.status_code == 200
    assert "text/plain" in r.headers.get("content-type", "")
