# server/api_chat.py (or wherever your /chat route lives)
from typing import List, Optional, Literal
from pydantic import BaseModel, field_validator
from fastapi import APIRouter, Header, HTTPException, Depends, Request

router = APIRouter()

class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str

class ChatPayloadFlexible(BaseModel):
    # Accept either messages[] or prompt/input
    messages: Optional[List[ChatMessage]] = None
    prompt: Optional[str] = None
    input: Optional[str] = None
    model: Optional[str] = None
    stream: Optional[bool] = False

    # unify into .text
    text: Optional[str] = None

    @field_validator("text", mode="before")
    @classmethod
    def fold_text(cls, v, values):
        if v:
            return v
        # Prefer messages if present
        msgs = values.get("messages")
        if msgs:
            # concatenate user contents (simple strategy)
            return "\n".join(m.content for m in msgs if m.role == "user")
        # else prompt/input
        return values.get("prompt") or values.get("input")

@router.post("/chat")
async def chat(payload: ChatPayloadFlexible, request: Request, x_admin_token: Optional[str] = Header(None)):
    # Auth (adjust to your project)
    expected = request.app.state.admin_token if hasattr(request.app.state, "admin_token") else "Africangoku23!"
    if expected and x_admin_token != expected:
        raise HTTPException(status_code=403, detail="Forbidden: bad admin token")

    if not payload.text:
        raise HTTPException(status_code=422, detail="'messages' or 'prompt' required")

    # --- your existing policy pipeline here ---
    # result = run_through_firewall(payload.text, model=payload.model, stream=payload.stream)
    # Return a uniform shape for the UI:
    return {
        "answer": f"Echo: {payload.text[:120]}",
        "added_latency_ms": 12,
        "request_id": "dbg-123",
        "policy_version": "v7",
    }
