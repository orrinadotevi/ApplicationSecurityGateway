from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import httpx, os, uuid, yaml
from pydantic import BaseModel

app = FastAPI(title="LLM-ASG (Step 1 Skeleton)")

class Policy(BaseModel):
    deny_patterns: list[str] = []
    max_tokens: int = 800

def load_policy(path: str) -> Policy:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return Policy(**data)
    except Exception as e:
        print(f"[policy] Warning: {e}")
        return Policy()

POLICY_PATH = os.getenv("POLICY_PATH", "/app/configs/policy.yaml")
policy = load_policy(POLICY_PATH)

LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://mock-llm:8001/echo")

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/policy")
async def get_policy():
    return policy.dict()

@app.post("/chat")
async def chat(payload: dict, request: Request):
    request_id = str(uuid.uuid4())
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise HTTPException(status_code=400, detail="Missing 'prompt'.")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(LLM_ENDPOINT, json={"prompt": prompt, "request_id": request_id})
            resp.raise_for_status()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Upstream error: {e}")
    return JSONResponse(content={"request_id": request_id, "upstream": resp.json()})
