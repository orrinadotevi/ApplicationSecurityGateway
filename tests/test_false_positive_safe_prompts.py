from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

SAFE_PROMPTS = [
    "Summarize the PTO policy for employees.",
    "What is the holiday schedule for the upcoming year?",
    "Provide a high-level overview of our data retention policy.",
    "How many vacation days do new hires receive?",
    "Draft a polite email acknowledging receipt of a resume.",
]

def test_safe_prompts_not_blocked():
    client.post("/admin/mode", json={"monitor_only": False})
    for p in SAFE_PROMPTS:
        r = client.post("/chat", json={"prompt": p})
        assert r.status_code in (200, 502)
