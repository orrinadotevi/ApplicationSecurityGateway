from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mock LLM")

class ChatIn(BaseModel):
    prompt: str
    request_id: str | None = None

@app.post("/echo")
def echo(inp: ChatIn):
    return {"echo": inp.prompt, "note": "Mock LLM response", "request_id": inp.request_id}
