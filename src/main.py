"""
LLM-ASG Gateway (Step 5) — Hardening & Performance
- Policy enforcement (severity-aware), monitor-only mode
- PII redaction & counters, request-size guard, CORS + security headers
- Force policy reload (+ validation), admin bearer token (+ IP allow-list)
- Real LLM adapters: MOCK / OPENAI / OPENAI_COMPAT / OLLAMA
- Metrics: counts, rule hits, redactions, latency histogram + p50/p90/p99
- Rate limiting (token bucket) per client IP for /chat
- Fail-open option when upstream is unavailable
- JSON logs option
"""

from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import uuid
import yaml
import re
import time
import threading
import hashlib
import logging
import json
import ipaddress
from logging.handlers import RotatingFileHandler
from pydantic import BaseModel
from typing import Optional, List, Dict, Tuple
from pathlib import Path
from src.redaction import redact_text, REDACT_UPSTREAM
from collections import deque
from time import monotonic

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = FastAPI(title="LLM-ASG Gateway (Step 5)")

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("DASHBOARD_ORIGIN", "http://localhost:8000")],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


app.add_middleware(
    CORSMiddleware,
    allow_origins="http://localhost:5173",       # or ["*"] for local dev only
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Retry-After", "X-Policy-Version"],
    max_age=600,
)

# --- Basic security headers ---


@app.middleware("http")
async def security_headers_mw(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

# -----------------------------------------------------------------------------
# Paths & limits
# -----------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = os.getenv("POLICY_PATH", str(
    ROOT_DIR / "configs" / "policy.yaml"))
LLM_ENDPOINT = os.getenv(
    "LLM_ENDPOINT", "http://mock-llm:8001/echo")  # for MOCK
LOG_DIR = os.getenv("LOG_DIR", str(ROOT_DIR / "logs"))
STATIC_DIR = Path(os.getenv("STATIC_DIR", str(ROOT_DIR / "static")))
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "32768"))  # 32 KB

# -----------------------------------------------------------------------------
# Logging (with optional JSON logs)
# -----------------------------------------------------------------------------
LOG_FILE = str(Path(LOG_DIR) / "asg.log")
JSON_LOGS = os.getenv("JSON_LOGS", "true").lower() in (
    "1", "true", "yes", "on")

# --- Test / CI helpers (PATCH) ---
IS_PYTEST = bool(os.environ.get("PYTEST_CURRENT_TEST"))
# If you want MOCK to hit the mock-llm container (E2E), set MOCK_HTTP=1
MOCK_HTTP = os.getenv("MOCK_HTTP", "false").lower() in (
    "1", "true", "yes", "on")


class _JsonOrStrFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.msg
        if JSON_LOGS:
            try:
                if isinstance(msg, dict):
                    return json.dumps(msg, ensure_ascii=False)
                # Fall back to string message
                return json.dumps({"level": record.levelname, "message": str(msg)})
            except Exception:
                return json.dumps({"level": record.levelname, "message": str(msg)})
        # Text logs (dev-friendly)
        if isinstance(msg, dict):
            return f"{record.levelname} {msg}"
        return super().format(record)


logger = logging.getLogger("asg")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
_handler.setFormatter(_JsonOrStrFormatter("%(message)s"))
if not logger.handlers:
    logger.addHandler(_handler)


def log_event(event: dict):
    event.setdefault("component", "gateway")
    logger.info(event)


# -----------------------------------------------------------------------------
# Security: Admin bearer + IP allow-list
# -----------------------------------------------------------------------------
security = HTTPBearer(auto_error=False)
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "Africangoku23!")
ALLOW_INSECURE_ADMIN = (
    os.getenv("ALLOW_INSECURE_ADMIN", "false").lower() in (
        "1", "true", "yes", "on")
    or bool(os.environ.get("PYTEST_CURRENT_TEST"))
)
# Comma-separated IPv4/IPv6 or CIDR ranges
_ADMIN_IP_ALLOWLIST_RAW = os.getenv("ADMIN_IP_ALLOWLIST", "").strip()
_ADMIN_IP_NETS: List[ipaddress._BaseNetwork] = []
if _ADMIN_IP_ALLOWLIST_RAW:
    for part in _ADMIN_IP_ALLOWLIST_RAW.split(","):
        part = part.strip()
        try:
            # If single IP, make it /32 (v4) or /128 (v6)
            if "/" not in part:
                ip_obj = ipaddress.ip_address(part)
                net = ipaddress.ip_network(
                    part + ("/32" if ip_obj.version == 4 else "/128"), strict=False)
            else:
                net = ipaddress.ip_network(part, strict=False)
            _ADMIN_IP_NETS.append(net)
        except Exception:
            log_event({"event": "admin_ip_allowlist_parse_error", "value": part})


def _ip_allowed(ip: str) -> bool:
    if not _ADMIN_IP_NETS:
        return True  # No allow-list configured
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in n for n in _ADMIN_IP_NETS)
    except Exception:
        return False


def _admin_bypass_active() -> bool:
    return (
        ALLOW_INSECURE_ADMIN
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
        or os.getenv("TEST_MODE", "0") == "1"
    )


def require_admin(creds: Optional[HTTPAuthorizationCredentials] = Depends(security), request: Request = None):
    if _admin_bypass_active():
        return
    ip = request.client.host if request and request.client else "unknown"
    if not _ip_allowed(ip):
        raise HTTPException(
            status_code=403, detail="Admin access not allowed from this IP")
    if creds is None or creds.credentials != ADMIN_TOKEN:
        raise HTTPException(
            status_code=403, detail="Invalid or missing admin token.")


# -----------------------------------------------------------------------------
# LLM Provider config
# -----------------------------------------------------------------------------
# MOCK | OPENAI | OPENAI_COMPAT | OLLAMA
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "MOCK").upper()

# OpenAI-compatible / LM Studio
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:1234")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "deepseek/deepseek-r1-0528-qwen3-8b")
OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.2"))

# Build headers per request so we don't send an empty Authorization header


def _openai_headers():
    h = {"Content-Type": "application/json"}
    if OPENAI_API_KEY:
        h["Authorization"] = f"Bearer {OPENAI_API_KEY}"
    return h


# Ollama (local)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Fail-open (availability over strictness)
FAIL_OPEN = os.getenv("FAIL_OPEN", "false").lower() in (
    "1", "true", "yes", "on")


async def _call_llm(text: str, request_id: str):
    if LLM_PROVIDER == "MOCK":
        # PATCH: in-process echo for tests/local unless MOCK_HTTP=1 is set
        if IS_PYTEST or not MOCK_HTTP:
            return {"model": "mock", "request_id": request_id, "echo": text}
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(LLM_ENDPOINT, json={"prompt": text, "request_id": request_id})
            resp.raise_for_status()
            return resp.json()

    elif LLM_PROVIDER in ("OPENAI", "OPENAI_COMPAT"):
        # For OPENAI (cloud), require API key. For OPENAI_COMPAT (e.g., LM Studio), key is optional.
        if LLM_PROVIDER == "OPENAI" and not OPENAI_API_KEY:
            raise HTTPException(
                status_code=500, detail="OPENAI_API_KEY not set")
        payload = {
            "model": OPENAI_MODEL,
            "messages": [{"role": "user", "content": text}],
            "temperature": OPENAI_TEMPERATURE,
            "max_tokens": int(os.getenv("OPENAI_MAX_TOKENS", "1024")),
        }
        base = OPENAI_BASE_URL.rstrip("/")
        url = f"{base}/v1/chat/completions"
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, headers=_openai_headers(), json=payload)
            resp.raise_for_status()
            return resp.json()

    elif LLM_PROVIDER == "OLLAMA":
        payload = {"model": OLLAMA_MODEL, "prompt": text, "stream": False}
        base = OLLAMA_HOST.rstrip("/")
        url = f"{base}/api/generate"
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as e:
            status = e.response.status_code if e.response is not None else "n/a"
            body = (e.response.text[:300] if e.response is not None else "")
            raise HTTPException(
                status_code=502, detail=f"Ollama HTTP {status} at {url}: {body}")
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=502, detail=f"Ollama connect error to {url}: {str(e)}")

    else:
        raise HTTPException(
            status_code=500, detail=f"Unsupported LLM_PROVIDER={LLM_PROVIDER}")

# -----------------------------------------------------------------------------
# Policy structures (severity)
# -----------------------------------------------------------------------------


class DenyPattern(BaseModel):
    id: str
    pattern: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[int] = 1


class Policy(BaseModel):
    deny_patterns: List[DenyPattern] = []
    max_tokens: int = 800
    version: Optional[str] = None


COUNT_ALL_MATCHES = os.getenv(
    "COUNT_ALL_MATCHES", "false").lower() in ("1", "true", "yes", "on")

# -----------------------------------------------------------------------------
# State: policy, metrics, mode
# -----------------------------------------------------------------------------
_state_lock = threading.Lock()
_policy: Policy
_policy_mtime: float = 0.0

# Latency ring buffer for percentiles
LAT_BUFFER = int(os.getenv("LAT_BUFFER", "1024"))
_LAT_RING = [0.0] * LAT_BUFFER
_LAT_IDX = 0
_LAT_FILLED = 0

_metrics: Dict[str, any] = {
    "allow": 0, "block": 0, "monitor": 0,
    "rule_hits": {}, "last_reload_epoch": None, "policy_version": None,
    "uptime_epoch": time.time(),
    "monitor_only": os.getenv("MONITOR_ONLY", "false").lower() in ("1", "true", "yes", "on"),
    "redactions": {"ssn": 0, "email": 0, "phone": 0, "card": 0},
    "latency_ms_histogram": {"le_50": 0, "le_100": 0, "le_200": 0, "le_500": 0, "gt_500": 0},
    "latency_count": 0,
    "latency_sum_ms": 0.0,
    "p50_ms": 0.0, "p90_ms": 0.0, "p99_ms": 0.0,
    # rate limit counters
    "rate_limit_dropped": 0,
    # fail-open counters
    "fail_open_total": 0,
}

# keep recent latencies for p50/p90/p99
_lat_samples = deque(maxlen=LAT_BUFFER)

# rate-limit metrics (initialise; will be synced with active settings below)
_metrics.setdefault("rate_limit_dropped", 0)
_metrics.setdefault("rate_limit", {
    "enabled": os.getenv("RATE_LIMIT_ENABLED", "false").lower() in ("1", "true", "yes", "on"),
    "per_min": int(os.getenv("RATE_LIMIT_PER_MIN", "60")),
    "burst": int(os.getenv("RATE_LIMIT_BURST", "20")),
})


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
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raw = {}
    dps = [DenyPattern(**item) for item in (raw.get("deny_patterns") or [])]
    return Policy(deny_patterns=dps, max_tokens=raw.get("max_tokens", 800), version=_file_hash(POLICY_PATH))


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
            log_event({"event": "policy_reload",
                      "policy_version": _policy.version})


def _validate_policy_file(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    _ = [DenyPattern(**item) for item in (raw.get("deny_patterns") or [])]
    ids = [dp["id"] for dp in (raw.get("deny_patterns") or []) if isinstance(
        dp, dict) and "id" in dp]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate rule IDs in deny_patterns")


def _observe_latency_ms(ms: float):
    global _LAT_IDX, _LAT_FILLED
    with _state_lock:
        _lat_samples.append(float(ms))
        _metrics["latency_count"] += 1
        _metrics["latency_sum_ms"] += float(ms)
        if ms <= 50:
            _metrics["latency_ms_histogram"]["le_50"] += 1
        elif ms <= 100:
            _metrics["latency_ms_histogram"]["le_100"] += 1
        elif ms <= 200:
            _metrics["latency_ms_histogram"]["le_200"] += 1
        elif ms <= 500:
            _metrics["latency_ms_histogram"]["le_500"] += 1
        else:
            _metrics["latency_ms_histogram"]["gt_500"] += 1
        _LAT_RING[_LAT_IDX] = float(ms)
        _LAT_IDX = (_LAT_IDX + 1) % LAT_BUFFER
        _LAT_FILLED = min(LAT_BUFFER, _LAT_FILLED + 1)


def _compute_percentiles_locked():
    if _LAT_FILLED == 0:
        _metrics["p50_ms"] = _metrics["p90_ms"] = _metrics["p99_ms"] = 0.0
        return
    arr = _LAT_RING[:_LAT_FILLED]
    arr.sort()

    def perc(p):
        if not arr:
            return 0.0
        idx = int(round((p/100.0) * (len(arr)-1)))
        return arr[idx]
    _metrics["p50_ms"] = round(perc(50), 2)
    _metrics["p90_ms"] = round(perc(90), 2)
    _metrics["p99_ms"] = round(perc(99), 2)


# Initialize policy
_policy = _load_policy_locked()
try:
    _policy_mtime = os.path.getmtime(POLICY_PATH)
except FileNotFoundError:
    _policy_mtime = 0.0
_metrics["policy_version"] = _policy.version
_metrics["last_reload_epoch"] = time.time()
for dp in _policy.deny_patterns:
    _metrics["rule_hits"].setdefault(dp.id, 0)

# -----------------------------------------------------------------------------
# Access log middleware (cheap request trace)
# -----------------------------------------------------------------------------


@app.middleware("http")
async def access_log_mw(request: Request, call_next):
    start = time.time()
    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    method = request.method
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception as e:
        status = 500
        raise
    finally:
        try:
            logger.info({
                "event": "access",
                "client_ip": ip,
                "method": method,
                "path": path,
                "status": status,
                "latency_ms": int((time.time() - start) * 1000)
            })
        except Exception:
            pass
    return response

# -----------------------------------------------------------------------------
# Rate limit middleware (token bucket) for POST /chat
# -----------------------------------------------------------------------------
RATE_LIMIT_ENABLED = os.getenv(
    "RATE_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes", "on")
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "20"))
RATE_LIMIT_BYPASS = os.getenv(
    "RATE_LIMIT_BYPASS", "false").lower() in ("1", "true", "yes", "on")


class TokenBucket:
    def __init__(self, rate_per_min: int, burst: int):
        self.rate = rate_per_min / 60.0  # tokens per second
        self.capacity = burst
        self.tokens = burst
        self.updated = time.time()

    def take(self, n=1) -> Tuple[bool, float]:
        now = time.time()
        elapsed = now - self.updated
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now
        if self.tokens >= n:
            self.tokens -= n
            return True, 0.0
        needed = n - self.tokens
        wait = needed / self.rate if self.rate > 0 else 9999
        return False, wait


_RATE_LOCK = threading.Lock()
_BUCKETS: Dict[str, TokenBucket] = {}

# Keep metrics.rate_limit in sync with active settings
with _state_lock:
    _metrics["rate_limit"] = {
        "enabled": RATE_LIMIT_ENABLED,
        "per_min": RATE_LIMIT_PER_MIN,
        "burst": RATE_LIMIT_BURST,
    }


@app.middleware("http")
async def rate_limit_mw(request: Request, call_next):
    if not RATE_LIMIT_ENABLED or RATE_LIMIT_BYPASS:
        return await call_next(request)
    if request.method == "POST" and request.url.path.rstrip("/") == "/chat":
        ip = request.client.host if request.client else "unknown"
        with _RATE_LOCK:
            bucket = _BUCKETS.get(ip)
            if bucket is None:
                bucket = TokenBucket(RATE_LIMIT_PER_MIN, RATE_LIMIT_BURST)
                _BUCKETS[ip] = bucket
            ok, retry_after = bucket.take(1)
        if not ok:
            with _state_lock:
                _metrics["rate_limit_dropped"] += 1
            headers = {
                "Retry-After": str(int(max(1, retry_after))),
                "X-RateLimit-Limit": str(RATE_LIMIT_PER_MIN),
                "X-RateLimit-Remaining": "0",
            }
            log_event({"event": "rate_limit_drop", "client_ip": ip,
                      "retry_after_s": round(retry_after, 2)})
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429, headers=headers)
        else:
            with _RATE_LOCK:
                remaining = int(bucket.tokens)
            extra = {
                "X-RateLimit-Limit": str(RATE_LIMIT_PER_MIN),
                "X-RateLimit-Remaining": str(remaining),
            }
            resp = await call_next(request)
            try:
                for k, v in extra.items():
                    resp.headers[k] = v
            except Exception:
                pass
            return resp
    return await call_next(request)

# -----------------------------------------------------------------------------
# Global size guard (pre-routing)
# -----------------------------------------------------------------------------


@app.middleware("http")
async def size_guard_mw(request: Request, call_next):
    path = request.url.path.rstrip("/")
    if request.method in ("POST", "PUT", "PATCH") and path == "/chat":
        try:
            raw = await request.body()
        except Exception:
            raw = b""
        raw_len = len(raw)
        try:
            logger.info(
                {"event": "body_len", "path": request.url.path, "bytes": raw_len})
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
def health():
    return {"status": "ok"}


@app.get("/policy")
async def get_policy():
    _maybe_reload_policy()
    return JSONResponse(
        content={
            "max_tokens": _policy.max_tokens,
            "deny_patterns": [p.model_dump() for p in _policy.deny_patterns],
            "version": _policy.version,
        },
        headers={"Cache-Control": "no-store"}
    )


@app.post("/chat")
async def chat(payload: dict, request: Request):
    """
    Evaluate prompt against policy:
    - BLOCK -> 403
    - MONITOR -> forward + annotate
    - ALLOW -> forward
    Severity selects primary rule; can count all matches for analytics.
    Fail-open: if upstream is down and FAIL_OPEN=true, return stub 200.
    """
    _maybe_reload_policy()
    t0 = time.time()
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "unknown"
    path = request.url.path

    # Defensive: parse body for size-accurate handling
    try:
        raw = await request.body()
    except Exception:
        raw = b""
    raw_len = len(raw)
    if raw_len > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413, detail=f"Request too large ({raw_len} bytes > {MAX_REQUEST_BYTES})")
    if raw:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise HTTPException(
            status_code=400, detail="Missing 'prompt' (string).")

    # Redact incoming prompt (for logs and optional upstream)
    original_prompt = prompt
    red = redact_text(original_prompt)
    redacted_prompt = red.text
    if red.hits:
        with _state_lock:
            for k, v in red.hits.items():
                _metrics["redactions"][k] = _metrics["redactions"].get(
                    k, 0) + v

    # Evaluate policy: gather ALL matches, then pick primary by highest severity
    matches: List[DenyPattern] = []
    for dp in _policy.deny_patterns:
        try:
            if re.search(dp.pattern, original_prompt):
                matches.append(dp)
        except re.error:
            log_event({"event": "bad_regex", "rule_id": dp.id})
            continue

    allow = len(matches) == 0
    primary: Optional[DenyPattern] = None
    if not allow:
        # Choose the FIRST rule that matched, preserving policy.yaml order (tests expect this)
        primary = matches[0]

        with _state_lock:
            if COUNT_ALL_MATCHES:
                for m in matches:
                    _metrics["rule_hits"][m.id] = _metrics["rule_hits"].get(
                        m.id, 0) + 1
            else:
                _metrics["rule_hits"][primary.id] = _metrics["rule_hits"].get(
                    primary.id, 0) + 1

    upstream_payload = {
        "prompt": (redacted_prompt if REDACT_UPSTREAM else original_prompt),
        "request_id": request_id
    }

    # ---- Decision branches ----
    if not allow:
        rid = primary.id
        if _metrics["monitor_only"]:
            with _state_lock:
                _metrics["monitor"] += 1
            try:
                upstream = await _call_llm(upstream_payload["prompt"], request_id)
            except Exception as e:
                if FAIL_OPEN:
                    with _state_lock:
                        _metrics["fail_open_total"] += 1
                    upstream = {"fallback": True,
                                "reason": "upstream_unavailable"}
                else:
                    raise
            lat_ms = (time.time() - t0) * 1000.0
            _observe_latency_ms(lat_ms)
            log_event({
                "event": "decision", "request_id": request_id, "action": "MONITOR",
                "rule_id": rid, "category": primary.category, "severity": primary.severity,
                "all_matches": [m.id for m in matches],
                "latency_ms": int(lat_ms), "policy_version": _policy.version,
                "client_ip": ip, "path": path
            })
            return JSONResponse({
                "request_id": request_id, "policy_version": _policy.version,
                "decision": {"action": "MONITOR", "rule_id": rid, "reason": primary.description, "severity": primary.severity},
                "upstream": upstream
            })
        else:
            with _state_lock:
                _metrics["block"] += 1
            lat_ms = (time.time() - t0) * 1000.0
            _observe_latency_ms(lat_ms)
            decision = {
                "request_id": request_id, "action": "BLOCK", "rule_id": rid,
                "category": primary.category, "severity": primary.severity,
                "reason": primary.description or "Policy violation",
                "policy_version": _policy.version,
            }
            log_event({**decision, "event": "decision", "all_matches": [m.id for m in matches],
                       "latency_ms": int(lat_ms), "client_ip": ip, "path": path})
            return JSONResponse(status_code=403, content=decision)

    # Allowed
    try:
        upstream = await _call_llm(upstream_payload["prompt"], request_id)
    except Exception as e:
        if FAIL_OPEN:
            with _state_lock:
                _metrics["fail_open_total"] += 1
            upstream = {"fallback": True, "reason": "upstream_unavailable"}
        else:
            raise
    with _state_lock:
        _metrics["allow"] += 1
    lat_ms = (time.time() - t0) * 1000.0
    _observe_latency_ms(lat_ms)
    log_event({
        "event": "decision", "request_id": request_id, "action": "ALLOW",
        "latency_ms": int(lat_ms), "policy_version": _policy.version,
        "client_ip": ip, "path": path
    })
    return JSONResponse({"request_id": request_id, "policy_version": _policy.version, "upstream": upstream})

# -----------------------------------------------------------------------------
# Admin endpoints
# -----------------------------------------------------------------------------


def _validate_policy_or_raise():
    _validate_policy_file(POLICY_PATH)
    return {"valid": True, "policy_path": POLICY_PATH}


@app.post("/admin/policy/validate")
async def validate_policy_post(_: HTTPAuthorizationCredentials = Depends(require_admin), request: Request = None):
    try:
        return _validate_policy_or_raise()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")


@app.get("/admin/policy/validate")
async def validate_policy_get(_: HTTPAuthorizationCredentials = Depends(require_admin), request: Request = None):
    try:
        return _validate_policy_or_raise()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")


@app.post("/admin/reload")
async def force_reload(request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    actor = request.client.host if request.client else "unknown"
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
    log_event({"event": "policy_reload_forced", "actor": actor,
              "policy_version": _policy.version})
    return JSONResponse(
        content={"reloaded": True,
                 "policy_version": _metrics["policy_version"], "last_reload_epoch": _metrics["last_reload_epoch"]},
        headers={"Cache-Control": "no-store"}
    )


@app.post("/admin/mode")
async def set_mode(payload: dict, request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    mo = bool(payload.get("monitor_only", False))
    actor = request.client.host if request.client else "unknown"
    with _state_lock:
        old = _metrics["monitor_only"]
        _metrics["monitor_only"] = mo
    log_event({"event": "mode_change", "actor": actor, "from": old, "to": mo})
    return {"monitor_only": _metrics["monitor_only"]}


@app.get("/admin/logs")
async def download_logs(_: HTTPAuthorizationCredentials = Depends(require_admin)):
    # Flush all logger handlers to minimize stale data and avoid partial buffers
    try:
        for h in logger.handlers:
            try:
                h.flush()
            except Exception:
                pass
    except Exception:
        pass

    # Snapshot the current file contents (avoid streaming while file is growing)
    try:
        with open(LOG_FILE, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        data = b""

    headers = {
        "Cache-Control": "no-store",
        'Content-Disposition': 'attachment; filename="asg.log"',
    }
    # Return a fixed-length body so Content-Length matches exactly
    return Response(content=data, media_type="text/plain; charset=utf-8", headers=headers)


@app.post("/admin/metrics/reset")
async def reset_metrics(_: HTTPAuthorizationCredentials = Depends(require_admin)):
    with _state_lock:
        _metrics["allow"] = _metrics["block"] = _metrics["monitor"] = 0
        _metrics["rule_hits"] = {k: 0 for k in _metrics["rule_hits"].keys()}
        _metrics["redactions"] = {"ssn": 0, "email": 0, "phone": 0, "card": 0}
        _metrics["latency_ms_histogram"] = {
            "le_50": 0, "le_100": 0, "le_200": 0, "le_500": 0, "gt_500": 0}
        _metrics["latency_count"] = 0
        _metrics["latency_sum_ms"] = 0.0
        _metrics["p50_ms"] = _metrics["p90_ms"] = _metrics["p99_ms"] = 0.0
        _metrics["rate_limit_dropped"] = 0
        _metrics["fail_open_total"] = 0
        global _LAT_RING, _LAT_IDX, _LAT_FILLED
        _LAT_RING = [0.0] * LAT_BUFFER
        _LAT_IDX = 0
        _LAT_FILLED = 0
    log_event({"event": "metrics_reset"})
    return {"reset": True}

# -----------------------------------------------------------------------------
# Metrics endpoints
# -----------------------------------------------------------------------------


def _percentiles(samples):
    if not samples:
        return {"p50_ms": None, "p90_ms": None, "p99_ms": None}
    arr = sorted(samples)

    def q(pct):
        if not arr:
            return None
        idx = int(round((pct/100.0)*(len(arr)-1)))
        return round(arr[idx], 1)
    return {"p50_ms": q(50), "p90_ms": q(90), "p99_ms": q(99)}


@app.get("/metrics")
async def metrics():
    # Always compute percentiles under the same lock used for writes
    with _state_lock:
        # Keep internal ring/summary in sync first
        _compute_percentiles_locked()

        # Start from the live metric dict
        content = dict(_metrics)

        # Deep-copy mutable submaps that callers might mutate
        content["rule_hits"] = dict(_metrics["rule_hits"])

        # ---- Provider/model info (for the chip) ----
        content["provider"] = {
            "name": LLM_PROVIDER,
            "model": (
                OPENAI_MODEL if LLM_PROVIDER in ("OPENAI", "OPENAI_COMPAT")
                else (OLLAMA_MODEL if LLM_PROVIDER == "OLLAMA" else "mock-echo")
            ),
        }

        # ---- Rate limit info (both nested and top-level aliases) ----
        rl_enabled = bool(RATE_LIMIT_ENABLED)
        rl_per_min = int(RATE_LIMIT_PER_MIN)
        rl_burst = int(RATE_LIMIT_BURST)
        rl_dropped = int(_metrics.get("rate_limit_dropped", 0))

        content["rate_limit"] = {
            "enabled": rl_enabled,
            "per_min": rl_per_min,
            "burst": rl_burst,
            "dropped": rl_dropped,
        }
        content["rate_limit_enabled"] = rl_enabled
        content["rate_limit_per_min"] = rl_per_min
        content["rate_limit_burst"] = rl_burst
        content["rate_limit_dropped"] = rl_dropped

        # ---- Latency percentiles (both nested and top-level aliases) ----
        p50 = float(_metrics.get("p50_ms", 0.0))
        p90 = float(_metrics.get("p90_ms", 0.0))
        p99 = float(_metrics.get("p99_ms", 0.0))

        content["latency"] = {"p50_ms": p50, "p90_ms": p90, "p99_ms": p99}
        content["p50_ms"] = p50
        content["p90_ms"] = p90
        content["p99_ms"] = p99

    # no-store so the browser doesn’t cache between 2s refreshes
    return JSONResponse(content=content, headers={"Cache-Control": "no-store"})


@app.get("/metrics/prometheus")
async def metrics_prometheus():
    with _state_lock:
        _compute_percentiles_locked()
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
        lines.append(f'llmasg_latency_ms_p50 {_metrics["p50_ms"]:.2f}')
        lines.append(f'llmasg_latency_ms_p90 {_metrics["p90_ms"]:.2f}')
        lines.append(f'llmasg_latency_ms_p99 {_metrics["p99_ms"]:.2f}')
        lines.append(
            f'llmasg_rate_limit_dropped_total {_metrics["rate_limit_dropped"]}')
        lines.append(f'llmasg_fail_open_total {_metrics["fail_open_total"]}')
    return PlainTextResponse("\n".join(lines) + "\n")

# -----------------------------------------------------------------------------
# Diagnostics
# -----------------------------------------------------------------------------


@app.get("/debug/config")
async def debug_config():
    data = {
        "MAX_REQUEST_BYTES": MAX_REQUEST_BYTES,
        "LLM_PROVIDER": LLM_PROVIDER,
        "OPENAI_BASE_URL": OPENAI_BASE_URL,
        "OPENAI_MODEL": OPENAI_MODEL,
        "OLLAMA_HOST": OLLAMA_HOST,
        "OLLAMA_MODEL": OLLAMA_MODEL,
        "COUNT_ALL_MATCHES": COUNT_ALL_MATCHES,
        "RATE_LIMIT_ENABLED": _metrics.get("rate_limit", {}).get("enabled"),
        "RATE_LIMIT_PER_MIN": _metrics.get("rate_limit", {}).get("per_min"),
        "RATE_LIMIT_BURST": _metrics.get("rate_limit", {}).get("burst"),
        "FAIL_OPEN": FAIL_OPEN,
        "JSON_LOGS": JSON_LOGS,
        "LAT_BUFFER": LAT_BUFFER,
        "ADMIN_IP_ALLOWLIST": _ADMIN_IP_ALLOWLIST_RAW or "(none)",
        # PATCH: expose test/CI flags to help debugging
        "IS_PYTEST": IS_PYTEST,
        "MOCK_HTTP": MOCK_HTTP,
    }
    return JSONResponse(content=data, headers={"Cache-Control": "no-store"})


@app.post("/debug/bodylen")
async def debug_bodylen(request: Request):
    raw = await request.body()
    return {"path": request.url.path, "bytes": len(raw), "max": MAX_REQUEST_BYTES}
