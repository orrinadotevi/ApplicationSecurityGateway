"""
LLM-ASG Gateway (Step 4+) — Reliability, Security & Observability polish
- Policy enforcement (block / monitor-only) with severity
- PII redaction with counters (Step 3)
- Metrics & dashboard (incl. latency histogram, sum/count)
- Force policy reload (+ validation), admin bearer token (+ optional IP allow-list)
- Prometheus metrics endpoint (provider & retries exposed)
- Request size guard, CORS, basic security headers
- LLM adapter: MOCK (default), OPENAI/OPENAI_COMPAT, OLLAMA
- LLM retries with jittered backoff, tunable timeouts, provider info in /metrics
- NEW: Rate limiter for /chat with X-RateLimit-* headers (+ drop counter metric)
- NEW: Provider/model included in decision logs & JSON responses
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import httpx, os, uuid, yaml, re, time, threading, hashlib, logging, json, random, asyncio, ipaddress
from logging.handlers import RotatingFileHandler
from pydantic import BaseModel
from typing import Optional, List, Deque, Dict
from pathlib import Path
from collections import deque
from src.redaction import redact_text, REDACT_UPSTREAM  # Step 3 redaction

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = FastAPI(title="LLM-ASG Gateway (Step 4+)")

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("DASHBOARD_ORIGIN", "http://localhost:8000")],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- Basic security headers ---
@app.middleware("http")
async def security_headers_mw(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

# --- Paths & limits ---
ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = os.getenv("POLICY_PATH", str(ROOT_DIR / "configs" / "policy.yaml"))
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://mock-llm:8001/echo")  # used for MOCK
LOG_DIR = os.getenv("LOG_DIR", str(ROOT_DIR / "logs"))
STATIC_DIR = Path(os.getenv("STATIC_DIR", str(ROOT_DIR / "static")))
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "32768"))  # 32 KB

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
LOG_FILE = str(Path(LOG_DIR) / "asg.log")
logger = logging.getLogger("asg")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
_handler.setFormatter(_formatter)
if not logger.handlers:
    logger.addHandler(_handler)

def log_event(event: dict):
    event.setdefault("component", "gateway")
    logger.info(event)

# -----------------------------------------------------------------------------
# Security: Bearer token for admin routes + optional IP allow-list
# -----------------------------------------------------------------------------
security = HTTPBearer(auto_error=False)
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "changeme123")
ALLOW_INSECURE_ADMIN = (
    os.getenv("ALLOW_INSECURE_ADMIN", "false").lower() in ("1","true","yes","on")
    or bool(os.environ.get("PYTEST_CURRENT_TEST"))
)

ADMIN_IP_ALLOWLIST = [s.strip() for s in os.getenv("ADMIN_IP_ALLOWLIST","").split(",") if s.strip()]

def _admin_bypass_active() -> bool:
    return (
        ALLOW_INSECURE_ADMIN
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
        or os.getenv("TEST_MODE", "0") == "1"
    )

def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")

def _ip_allowed(ip: str) -> bool:
    if not ADMIN_IP_ALLOWLIST:
        return True
    try:
        ipobj = ipaddress.ip_address(ip)
        for entry in ADMIN_IP_ALLOWLIST:
            if "/" in entry:
                if ipobj in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == entry:
                return True
        return False
    except ValueError:
        return False

def require_admin(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if _admin_bypass_active():
        return
    if creds is None or creds.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid or missing admin token.")

# -----------------------------------------------------------------------------
# LLM Provider configuration (Step 4)
# -----------------------------------------------------------------------------
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "MOCK").upper()  # MOCK | OPENAI | OPENAI_COMPAT | OLLAMA

# OpenAI-compatible
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.2"))
OPENAI_HEADERS = {
    "Authorization": f"Bearer {OPENAI_API_KEY}" if OPENAI_API_KEY else "",
    "Content-Type": "application/json",
}

# Ollama (local)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Reliability knobs
LLM_TIMEOUT_SECS = float(os.getenv("LLM_TIMEOUT_SECS", "60"))
RETRY_MAX_ATTEMPTS = int(os.getenv("RETRY_MAX_ATTEMPTS", "2"))
RETRY_BASE_MS = int(os.getenv("RETRY_BASE_MS", "200"))

async def _post_with_retries(url, *, json_body, headers=None, timeout=LLM_TIMEOUT_SECS, verify=True):
    attempt = 0
    last_exc = None
    while attempt <= RETRY_MAX_ATTEMPTS:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
                resp = await client.post(url, headers=headers, json=json_body)
                resp.raise_for_status()
                if attempt > 0:
                    with _state_lock:
                        _metrics["retries_total"] += 1
                return resp
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            last_exc = e
            status = getattr(getattr(e, "response", None), "status_code", None)
            retriable = isinstance(e, httpx.RequestError) or (status and 500 <= status < 600)
            if not retriable or attempt == RETRY_MAX_ATTEMPTS:
                break
            delay = (RETRY_BASE_MS * (attempt + 1)) / 1000.0 + random.uniform(0, 0.2)
            await asyncio.sleep(delay)
            attempt += 1
    raise last_exc

async def _call_llm(text: str, request_id: str):
    """
    Pluggable LLM call. Returns raw upstream JSON so existing clients/tests keep working.
    """
    if LLM_PROVIDER == "MOCK":
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(LLM_ENDPOINT, json={"prompt": text, "request_id": request_id})
            resp.raise_for_status()
            return resp.json()

    elif LLM_PROVIDER in ("OPENAI", "OPENAI_COMPAT"):
        if not OPENAI_API_KEY:
            raise HTTPException(status_code=500, detail="OPENAI_API_KEY not set")
        payload = {
            "model": OPENAI_MODEL,
            "messages": [{"role": "user", "content": text}],
            "temperature": OPENAI_TEMPERATURE,
            "max_tokens": int(os.getenv("OPENAI_MAX_TOKENS", "512")),
        }
        base = OPENAI_BASE_URL.rstrip("/")
        url = f"{base}/v1/chat/completions"
        try:
            resp = await _post_with_retries(
                url, json_body=payload, headers=OPENAI_HEADERS,
                timeout=LLM_TIMEOUT_SECS, verify=True
            )
            return resp.json()
        except httpx.HTTPStatusError as e:
            status = e.response.status_code if e.response is not None else "n/a"
            body = (e.response.text[:300] if e.response is not None else "")
            raise HTTPException(status_code=502, detail=f"Upstream HTTP {status} at {url}: {body}")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Upstream connect error to {url}: {str(e)}")

    elif LLM_PROVIDER == "OLLAMA":
        payload = {"model": OLLAMA_MODEL, "prompt": text, "stream": False}
        base = OLLAMA_HOST.rstrip("/")
        url = f"{base}/api/generate"
        try:
            resp = await _post_with_retries(
                url, json_body=payload, timeout=LLM_TIMEOUT_SECS, verify=True
            )
            return resp.json()
        except httpx.HTTPStatusError as e:
            status = e.response.status_code if e.response is not None else "n/a"
            body = (e.response.text[:300] if e.response is not None else "")
            raise HTTPException(status_code=502, detail=f"Ollama HTTP {status} at {url}: {body}")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Ollama connect error to {url}: {str(e)}")

    else:
        raise HTTPException(status_code=500, detail=f"Unsupported LLM_PROVIDER={LLM_PROVIDER}")

# -----------------------------------------------------------------------------
# Policy structures (Step 4: +severity)
# -----------------------------------------------------------------------------
class DenyPattern(BaseModel):
    id: str
    pattern: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[int] = 1   # 1 (low) .. 5 (critical)

class Policy(BaseModel):
    deny_patterns: List[DenyPattern] = []
    max_tokens: int = 800
    version: Optional[str] = None

# Count-all-matches (analytics)
COUNT_ALL_MATCHES = os.getenv("COUNT_ALL_MATCHES", "false").lower() in ("1","true","yes","on")

# -----------------------------------------------------------------------------
# State: policy, metrics, mode
# -----------------------------------------------------------------------------
_state_lock = threading.Lock()
_policy: Policy
_policy_mtime: float = 0.0
_metrics = {
    "allow": 0, "block": 0, "monitor": 0,
    "rule_hits": {}, "last_reload_epoch": None, "policy_version": None,
    "uptime_epoch": time.time(),
    "monitor_only": os.getenv("MONITOR_ONLY", "false").lower() in ("1","true","yes","on"),
    "redactions": {"ssn":0,"email":0,"phone":0,"card":0},
    "latency_ms_histogram": {"le_50":0,"le_100":0,"le_200":0,"le_500":0,"gt_500":0},
    "latency_count": 0,
    "latency_sum_ms": 0.0,
    "retries_total": 0,
    # NEW: rate-limit drops
    "rate_limit_drops": 0,
}

def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()[:12]
    except FileNotFoundError:
        return "no-policy"

def _load_policy_locked() -> Policy:
    try:
        with open(POLICY_PATH,"r",encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raw = {}
    dps = [DenyPattern(**item) for item in (raw.get("deny_patterns") or [])]
    return Policy(deny_patterns=dps, max_tokens=raw.get("max_tokens",800), version=_file_hash(POLICY_PATH))

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
                _metrics["rule_hits"].setdefault(dp.id,0)
            log_event({"event":"policy_reload","policy_version":_policy.version})

def _validate_policy_file(path: str) -> None:
    with open(path,"r",encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    _ = [DenyPattern(**item) for item in (raw.get("deny_patterns") or [])]
    ids = [dp["id"] for dp in (raw.get("deny_patterns") or []) if isinstance(dp,dict) and "id" in dp]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate rule IDs in deny_patterns")

def _observe_latency_ms(ms: float):
    with _state_lock:
        _metrics["latency_count"] += 1
        _metrics["latency_sum_ms"] += float(ms)
        if ms <= 50: _metrics["latency_ms_histogram"]["le_50"] += 1
        elif ms <= 100: _metrics["latency_ms_histogram"]["le_100"] += 1
        elif ms <= 200: _metrics["latency_ms_histogram"]["le_200"] += 1
        elif ms <= 500: _metrics["latency_ms_histogram"]["le_500"] += 1
        else: _metrics["latency_ms_histogram"]["gt_500"] += 1

# Initialize policy
_policy = _load_policy_locked()
try: _policy_mtime = os.path.getmtime(POLICY_PATH)
except FileNotFoundError: _policy_mtime = 0.0
_metrics["policy_version"] = _policy.version
_metrics["last_reload_epoch"] = time.time()
for dp in _policy.deny_patterns:
    _metrics["rule_hits"].setdefault(dp.id,0)

# -----------------------------------------------------------------------------
# Rate limiter (per-IP, sliding window) — /chat only
# -----------------------------------------------------------------------------
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "false").lower() in ("1","true","yes","on")
RATE_LIMIT_WINDOW_SECS = int(os.getenv("RATE_LIMIT_WINDOW_SECS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))
_rate_buckets: Dict[str, Deque[float]] = {}
_rate_lock = threading.Lock()

def _rate_check_and_update(ip: str) -> (bool|int):
    """
    Returns (allowed, remaining). If not allowed, remaining will be 0.
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECS
    with _rate_lock:
        dq = _rate_buckets.get(ip)
        if dq is None:
            dq = deque()
            _rate_buckets[ip] = dq
        # drop old
        while dq and dq[0] < window_start:
            dq.popleft()
        if len(dq) >= RATE_LIMIT_MAX_REQUESTS:
            return (False, 0)
        dq.append(now)
        remaining = max(0, RATE_LIMIT_MAX_REQUESTS - len(dq))
        return (True, remaining)

@app.middleware("http")
async def rate_limit_mw(request: Request, call_next):
    # Only enforce on POST /chat
    if RATE_LIMIT_ENABLED and request.method == "POST" and request.url.path.rstrip("/") == "/chat":
        ip = _client_ip(request)
        allowed, remaining = _rate_check_and_update(ip)
        if not allowed:
            with _state_lock:
                _metrics["rate_limit_drops"] += 1
            return JSONResponse(
                {"detail": "Too Many Requests"},
                status_code=429,
                headers={
                    "X-RateLimit-Limit": str(RATE_LIMIT_MAX_REQUESTS),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(RATE_LIMIT_WINDOW_SECS),
                    "Cache-Control": "no-store",
                },
            )
        # proceed; attach headers after processing in size_guard_mw below
        resp = await call_next(request)
        resp.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_MAX_REQUESTS)
        resp.headers["X-RateLimit-Remaining"] = str(remaining)
        resp.headers["X-RateLimit-Reset"] = str(RATE_LIMIT_WINDOW_SECS)
        return resp
    return await call_next(request)

# -----------------------------------------------------------------------------
# Global size guard middleware (pre-routing)
# -----------------------------------------------------------------------------
@app.middleware("http")
async def size_guard_mw(request: Request, call_next):
    path = request.url.path.rstrip("/")
    if request.method in ("POST","PUT","PATCH") and path == "/chat":
        try:
            raw = await request.body()
        except Exception:
            raw = b""
        raw_len = len(raw)
        try:
            logger.info({"event":"body_len","path":request.url.path,"bytes":raw_len})
        except Exception:
            pass
        if raw_len > MAX_REQUEST_BYTES:
            return JSONResponse(
                {"detail": f"Request too large ({raw_len} bytes > {MAX_REQUEST_BYTES})"},
                status_code=413, headers={"Cache-Control": "no-store"},
            )
    return await call_next(request)

# -----------------------------------------------------------------------------
# Static + Dashboard
# -----------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/dashboard")
async def dashboard():
    dash = STATIC_DIR / "dashboard.html"
    if dash.exists():
        return FileResponse(path=str(dash), media_type="text/html")
    return HTMLResponse("<h1>LLM-ASG Dashboard</h1><p>No dashboard.html found.</p>")

# -----------------------------------------------------------------------------
# Core endpoints
# -----------------------------------------------------------------------------
@app.get("/health")
async def health():
    _maybe_reload_policy()
    return {"status":"ok","policy_version":_policy.version,"monitor_only":_metrics["monitor_only"]}

@app.get("/policy")
async def get_policy():
    _maybe_reload_policy()
    return JSONResponse(
        content={
            "max_tokens": _policy.max_tokens,
            "deny_patterns": [p.model_dump() for p in _policy.deny_patterns],
            "version": _policy.version,
        },
        headers={"Cache-Control":"no-store"}
    )

def _provider_name_model():
    name = LLM_PROVIDER
    model = "mock-echo" if name == "MOCK" else (OLLAMA_MODEL if name == "OLLAMA" else OPENAI_MODEL)
    return name, model

@app.post("/chat")
async def chat(payload: dict, request: Request):
    """
    Evaluate prompt against policy:
    - BLOCK -> 403
    - MONITOR -> forward + annotate
    - ALLOW -> forward
    Uses severity to choose primary rule; can count all matches for analytics.
    """
    _maybe_reload_policy()
    t0 = time.time()
    request_id = str(uuid.uuid4())
    prov_name, prov_model = _provider_name_model()

    # Defensive: parse body for size-accurate handling
    try:
        raw = await request.body()
    except Exception:
        raw = b""
    raw_len = len(raw)
    if raw_len > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail=f"Request too large ({raw_len} bytes > {MAX_REQUEST_BYTES})")
    if raw:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise HTTPException(status_code=400, detail="Missing 'prompt' (string).")

    # Redact incoming prompt (for logs and optional upstream)
    original_prompt = prompt
    red = redact_text(original_prompt)
    redacted_prompt = red.text
    if red.hits:
        with _state_lock:
            for k, v in red.hits.items():
                _metrics["redactions"][k] = _metrics["redactions"].get(k, 0) + v

    # Evaluate policy: gather ALL matches, then pick primary by highest severity
    matches: List[DenyPattern] = []
    for dp in _policy.deny_patterns:
        try:
            if re.search(dp.pattern, original_prompt):
                matches.append(dp)
        except re.error:
            log_event({"event":"bad_regex","rule_id":dp.id})
            continue

    allow = len(matches) == 0
    primary: Optional[DenyPattern] = None
    if not allow:
        primary = max(matches, key=lambda m: (m.severity or 1))
        with _state_lock:
            if COUNT_ALL_MATCHES:
                for m in matches:
                    _metrics["rule_hits"][m.id] = _metrics["rule_hits"].get(m.id, 0) + 1
            else:
                _metrics["rule_hits"][primary.id] = _metrics["rule_hits"].get(primary.id, 0) + 1

    upstream_payload = {
        "prompt": (redacted_prompt if REDACT_UPSTREAM else original_prompt),
        "request_id": request_id
    }

    # Decision branches
    if not allow:
        rid = primary.id
        if _metrics["monitor_only"]:
            with _state_lock:
                _metrics["monitor"] += 1
            try:
                upstream = await _call_llm(upstream_payload["prompt"], request_id)
            except httpx.HTTPError as e:
                raise HTTPException(status_code=502, detail=f"Upstream LLM error: {e}")
            lat_ms = (time.time() - t0) * 1000.0
            _observe_latency_ms(lat_ms)
            log_event({
                "event":"decision","request_id":request_id,"action":"MONITOR",
                "rule_id":rid,"category":primary.category,"severity":primary.severity,
                "all_matches":[m.id for m in matches],
                "provider": prov_name, "model": prov_model,
                "latency_ms":int(lat_ms),"policy_version":_policy.version,
            })
            return JSONResponse({
                "request_id":request_id,"policy_version":_policy.version,
                "provider": prov_name, "model": prov_model,
                "decision":{"action":"MONITOR","rule_id":rid,"reason":primary.description,"severity":primary.severity},
                "upstream":upstream
            })
        else:
            with _state_lock:
                _metrics["block"] += 1
            lat_ms = (time.time() - t0) * 1000.0
            _observe_latency_ms(lat_ms)
            decision = {
                "request_id":request_id,"action":"BLOCK","rule_id":rid,
                "category":primary.category,"severity":primary.severity,
                "reason":primary.description or "Policy violation",
                "policy_version":_policy.version,
                "provider": prov_name, "model": prov_model,
                "all_matches":[m.id for m in matches],
            }
            log_event({**decision,"event":"decision","latency_ms":int(lat_ms)})
            return JSONResponse(status_code=403, content=decision)

    # Allowed
    try:
        upstream = await _call_llm(upstream_payload["prompt"], request_id)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Upstream LLM error: {e}")
    with _state_lock:
        _metrics["allow"] += 1
    lat_ms = (time.time() - t0) * 1000.0
    _observe_latency_ms(lat_ms)
    log_event({
        "event":"decision","request_id":request_id,"action":"ALLOW",
        "provider": prov_name, "model": prov_model,
        "latency_ms":int(lat_ms),"policy_version":_policy.version,
    })
    return JSONResponse({
        "request_id":request_id,"policy_version":_policy.version,
        "provider": prov_name, "model": prov_model,
        "upstream":upstream
    })

# -----------------------------------------------------------------------------
# Admin endpoints (require Bearer token + optional IP allow-list)
# -----------------------------------------------------------------------------
def _validate_policy_or_raise():
    _validate_policy_file(POLICY_PATH)
    return {"valid": True, "policy_path": POLICY_PATH}

@app.post("/admin/policy/validate")
async def validate_policy_post(request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        raise HTTPException(status_code=403, detail="Admin IP not allowed")
    try:
        return _validate_policy_or_raise()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")

@app.get("/admin/policy/validate")
async def validate_policy_get(request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        raise HTTPException(status_code=403, detail="Admin IP not allowed")
    try:
        return _validate_policy_or_raise()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")

@app.post("/admin/reload")
async def force_reload(request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        raise HTTPException(status_code=403, detail="Admin IP not allowed")
    try:
        _validate_policy_file(POLICY_PATH)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")
    global _policy, _policy_mtime
    with _state_lock:
        _policy = _load_policy_locked()
        try:
            _policy_mtime = os.path.getmtime(POLICY_PATH)
        except FileNotFoundError:
            _policy_mtime = 0.0
        _metrics["last_reload_epoch"] = time.time()
        _metrics["policy_version"] = _policy.version
        for dp in _policy.deny_patterns:
            _metrics["rule_hits"].setdefault(dp.id, 0)
    log_event({"event":"policy_reload_forced","actor":ip,"policy_version":_policy.version})
    return JSONResponse(
        content={"reloaded": True, "policy_version": _metrics["policy_version"], "last_reload_epoch": _metrics["last_reload_epoch"]},
        headers={"Cache-Control":"no-store"}
    )

@app.post("/admin/mode")
async def set_mode(payload: dict, request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        raise HTTPException(status_code=403, detail="Admin IP not allowed")
    mo = bool(payload.get("monitor_only", False))
    with _state_lock:
        old = _metrics["monitor_only"]
        _metrics["monitor_only"] = mo
    log_event({"event":"mode_change","actor":ip,"from":old,"to":mo})
    return {"monitor_only": _metrics["monitor_only"]}

@app.get("/admin/logs")
async def download_logs(request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        raise HTTPException(status_code=403, detail="Admin IP not allowed")
    return FileResponse(LOG_FILE, media_type="text/plain", filename="asg.log")

# -----------------------------------------------------------------------------
# Metrics endpoints
# -----------------------------------------------------------------------------
@app.get("/metrics")
async def metrics():
    with _state_lock:
        content = dict(_metrics)
        content["rule_hits"] = dict(_metrics["rule_hits"])
        # Provider summary for dashboard chip
        content["provider"] = {
            "name": LLM_PROVIDER,
            "model": OLLAMA_MODEL if LLM_PROVIDER == "OLLAMA" else ("mock-echo" if LLM_PROVIDER == "MOCK" else OPENAI_MODEL),
            "base_url": OLLAMA_HOST if LLM_PROVIDER == "OLLAMA" else (LLM_ENDPOINT if LLM_PROVIDER == "MOCK" else OPENAI_BASE_URL),
            "count_all_matches": COUNT_ALL_MATCHES,
        }
    return JSONResponse(content=content, headers={"Cache-Control":"no-store"})

@app.get("/metrics/prometheus")
async def metrics_prometheus():
    with _state_lock:
        lines = []
        lines.append(f"llmasg_allow_total {_metrics['allow']}")
        lines.append(f"llmasg_block_total {_metrics['block']}")
        lines.append(f"llmasg_monitor_total {_metrics['monitor']}")
        for rule_id, hits in _metrics["rule_hits"].items():
            lines.append(f'llmasg_rule_hits_total{{rule="{rule_id}"}} {hits}')
        for k, v in _metrics["redactions"].items():
            lines.append(f'llmasg_redactions_total{{type="{k}"}} {v}')
        h = _metrics["latency_ms_histogram"]
        lines.append(f'llmasg_latency_ms_bucket{{le="50"}} {h["le_50"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="100"}} {h["le_100"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="200"}} {h["le_200"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="500"}} {h["le_500"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="Inf"}} {h["gt_500"]}')
        lines.append(f'llmasg_latency_ms_sum {_metrics["latency_sum_ms"]:.3f}')
        lines.append(f'llmasg_latency_ms_count {_metrics["latency_count"]}')
        # retries, provider/model, policy version, count-all flag, rate-limit drops
        lines.append(f"llmasg_retries_total {_metrics.get('retries_total', 0)}")
        prov = LLM_PROVIDER
        model = "mock-echo" if prov == "MOCK" else (OLLAMA_MODEL if prov == "OLLAMA" else OPENAI_MODEL)
        lines.append(f'llmasg_provider_info{{provider="{prov}",model="{model}"}} 1')
        lines.append(f'llmasg_policy_version_info{{version="{_metrics.get("policy_version","unknown")}"}} 1')
        lines.append(f"llmasg_count_all_matches {1 if COUNT_ALL_MATCHES else 0}")
        lines.append(f"llmasg_rate_limit_drops_total {_metrics.get('rate_limit_drops',0)}")
    return PlainTextResponse("\n".join(lines) + "\n")

# -----------------------------------------------------------------------------
# Diagnostics (optional)
# -----------------------------------------------------------------------------
@app.get("/debug/config")
async def debug_config():
    return {
        "MAX_REQUEST_BYTES": MAX_REQUEST_BYTES,
        "LLM_PROVIDER": LLM_PROVIDER,
        "OPENAI_BASE_URL": OPENAI_BASE_URL,
        "OPENAI_MODEL": OPENAI_MODEL,
        "OLLAMA_HOST": OLLAMA_HOST,
        "OLLAMA_MODEL": OLLAMA_MODEL,
        "COUNT_ALL_MATCHES": COUNT_ALL_MATCHES,
        "LLM_TIMEOUT_SECS": LLM_TIMEOUT_SECS,
        "RETRY_MAX_ATTEMPTS": RETRY_MAX_ATTEMPTS,
        "RETRY_BASE_MS": RETRY_BASE_MS,
        "ADMIN_IP_ALLOWLIST": ADMIN_IP_ALLOWLIST,
        "RATE_LIMIT_ENABLED": RATE_LIMIT_ENABLED,
        "RATE_LIMIT_WINDOW_SECS": RATE_LIMIT_WINDOW_SECS,
        "RATE_LIMIT_MAX_REQUESTS": RATE_LIMIT_MAX_REQUESTS,
    }

@app.post("/debug/bodylen")
async def debug_bodylen(request: Request):
    raw = await request.body()
    return {"path": request.url.path, "bytes": len(raw), "max": MAX_REQUEST_BYTES}




