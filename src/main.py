from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import httpx, os, uuid, yaml, re, time, threading, hashlib, logging
from logging.handlers import RotatingFileHandler
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="LLM-ASG (Step 2.5: Monitor Mode + Expanded Tests)" )

# ---- Logging setup (rotating file) ----
LOG_DIR = os.getenv("LOG_DIR", "/app/logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "asg.log")

logger = logging.getLogger("asg")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

MONITOR_ONLY = os.getenv("MONITOR_ONLY", "false").lower() in ("1","true","yes","on")

# ---- Policy models ----
class DenyPattern(BaseModel):
    id: str
    pattern: str
    description: Optional[str] = None
    category: Optional[str] = None

class Policy(BaseModel):
    deny_patterns: list[DenyPattern] = []
    max_tokens: int = 800
    version: Optional[str] = None

POLICY_PATH = os.getenv("POLICY_PATH", "/app/configs/policy.yaml")
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://mock-llm:8001/echo")

# ---- State ----
_state_lock = threading.Lock()
_policy: Policy
_policy_mtime: float = 0.0
_metrics = {
    "allow": 0,
    "block": 0,
    "monitor": 0,
    "rule_hits": {},
    "last_reload_epoch": None,
    "policy_version": None,
    "uptime_epoch": time.time(),
    "monitor_only": MONITOR_ONLY,
}

def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()[:12]

def _load_policy_locked() -> Policy:
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raw = {}
    dps = []
    for item in (raw.get("deny_patterns") or []):
        dps.append(DenyPattern(
            id=item["id"],
            pattern=item["pattern"],
            description=item.get("description"),
            category=item.get("category"),
        ))
    try:
        version = _file_hash(POLICY_PATH)
    except Exception:
        version = None
    return Policy(deny_patterns=dps, max_tokens=raw.get("max_tokens", 800), version=version)

def _maybe_reload_policy():
    global _policy, _policy_mtime
    try:
        mtime = os.path.getmtime(POLICY_PATH)
    except FileNotFoundError:
        mtime = 0.0
    with _state_lock:
        if mtime != _policy_mtime:
            _policy = _load_policy_locked()
            _policy_mtime = mtime
            _metrics["last_reload_epoch"] = time.time()
            _metrics["policy_version"] = _policy.version
            for dp in _policy.deny_patterns:
                _metrics["rule_hits"].setdefault(dp.id, 0)
            logger.info({"event":"policy_reload","policy_version":_policy.version})

# Initialize
_policy = _load_policy_locked()
try:
    _policy_mtime = os.path.getmtime(POLICY_PATH)
except FileNotFoundError:
    _policy_mtime = 0.0
_metrics["policy_version"] = _policy.version
_metrics["last_reload_epoch"] = time.time()
for dp in _policy.deny_patterns:
    _metrics["rule_hits"].setdefault(dp.id, 0)

# ---- Helpers ----
def log_event(event: dict):
    event.setdefault("component","gateway")
    logger.info(event)

def evaluate_prompt(prompt: str):
    for dp in _policy.deny_patterns:
        if re.search(dp.pattern, prompt):
            return False, {"rule_id": dp.id, "description": dp.description, "category": dp.category}
    return True, None

# ---- API Endpoints ----
@app.get("/health")
async def health():
    _maybe_reload_policy()
    return {"status":"ok","policy_version":_policy.version,"monitor_only":_metrics["monitor_only"]}

@app.get("/policy")
async def get_policy():
    _maybe_reload_policy()
    return {"max_tokens": _policy.max_tokens, "deny_patterns": [p.model_dump() for p in _policy.deny_patterns], "version": _policy.version}

@app.post("/admin/reload")
async def force_reload():
    # Force a reload regardless of mtime by resetting _policy_mtime
    global _policy_mtime
    with _state_lock:
        _policy_mtime = -1.0
    _maybe_reload_policy()
    return {"reloaded": True, "policy_version": _metrics["policy_version"], "last_reload_epoch": _metrics["last_reload_epoch"]}

@app.post("/admin/mode")
async def set_mode(payload: dict):
    mo = bool(payload.get("monitor_only", False))
    with _state_lock:
        _metrics["monitor_only"] = mo
    log_event({"event":"mode_change","monitor_only":mo})
    return {"monitor_only": _metrics["monitor_only"]}

@app.get("/metrics")
async def metrics():
    with _state_lock:
        return {
            "allow": _metrics["allow"],
            "block": _metrics["block"],
            "monitor": _metrics["monitor"],
            "rule_hits": _metrics["rule_hits"],
            "policy_version": _metrics["policy_version"],
            "last_reload_epoch": _metrics["last_reload_epoch"],
            "uptime_epoch": _metrics["uptime_epoch"],
            "monitor_only": _metrics["monitor_only"],
        }

@app.get("/dashboard")
async def dashboard():
    return FileResponse(path="/app/static/dashboard.html", media_type="text/html")

@app.get("/admin/logs")
async def download_logs():
    # Streams the current rotating log file
    return FileResponse(LOG_FILE, media_type="text/plain", filename="asg.log")

app.mount("/static", StaticFiles(directory="/app/static"), name="static")

@app.post("/chat")
async def chat(payload: dict, request: Request):
    _maybe_reload_policy()
    t0 = time.time()
    request_id = str(uuid.uuid4())
    prompt = payload.get("prompt")

    if not isinstance(prompt, str) or not prompt.strip():
        raise HTTPException(status_code=400, detail="Missing 'prompt' (string)." )

    allow, match = evaluate_prompt(prompt)
    if not allow:
        rid = match["rule_id"]
        with _state_lock:
            _metrics["rule_hits"][rid] = _metrics["rule_hits"].get(rid,0) + 1
        if _metrics["monitor_only"]:
            with _state_lock:
                _metrics["monitor"] += 1
            log_event({"event":"decision","request_id":request_id,"action":"MONITOR",
                       "rule_id":rid,"category":match.get("category"),"latency_ms":int((time.time()-t0)*1000),
                       "policy_version":_policy.version})
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(LLM_ENDPOINT, json={"prompt":prompt, "request_id":request_id})
                    resp.raise_for_status()
                upstream = resp.json()
            except httpx.HTTPError as e:
                raise HTTPException(status_code=502, detail=f"Upstream LLM error: {e}")
            return JSONResponse(content={"request_id":request_id, "policy_version":_policy.version,
                                         "decision": {"action":"MONITOR","rule_id":rid,"reason":match.get("description")},
                                         "upstream": upstream})
        else:
            with _state_lock:
                _metrics["block"] += 1
            decision = {"request_id":request_id, "action":"BLOCK", "rule_id":rid,
                        "category":match.get("category"), "reason":match.get("description") or "Policy violation",
                        "policy_version":_policy.version}
            log_event({"event":"decision","request_id":request_id,"action":"BLOCK","rule_id":rid,
                       "category":match.get("category"),"latency_ms":int((time.time()-t0)*1000),"policy_version":_policy.version})
            return JSONResponse(status_code=403, content=decision)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(LLM_ENDPOINT, json={"prompt":prompt, "request_id":request_id})
            resp.raise_for_status()
        upstream = resp.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Upstream LLM error: {e}")

    with _state_lock:
        _metrics["allow"] += 1

    log_event({"event":"decision","request_id":request_id,"action":"ALLOW",
               "latency_ms":int((time.time()-t0)*1000),"policy_version":_policy.version})
    return JSONResponse(content={"request_id":request_id, "policy_version":_policy.version, "upstream": upstream})