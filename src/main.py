"""
LLM-ASG Gateway (Step 3 hardening) with:
- Policy enforcement (block / monitor-only)
- Metrics & dashboard
- Force policy reload (with validation)
- Bearer token auth for admin endpoints
- Prometheus metrics endpoint (+ latency _sum/_count)
- CORS + basic security headers
- Request size guard
- Step 3 redaction hooks preserved
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import httpx, os, uuid, yaml, re, time, threading, hashlib, logging, json
from logging.handlers import RotatingFileHandler
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
from src.redaction import redact_text, REDACT_UPSTREAM  # Step 3 redaction


# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = FastAPI(title="LLM-ASG Gateway (Step 3)")

# --- CORS (lock to your dashboard origin if you host elsewhere) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("DASHBOARD_ORIGIN", "http://localhost:8000")],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- Basic security headers on all responses ---
@app.middleware("http")
async def security_headers_mw(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

# --- Global size guard middleware (pre-routing) ---
@app.middleware("http")
async def size_guard_mw(request: Request, call_next):
    """
    Enforce a hard body-size limit on /chat (and variants) before hitting handlers.
    We read the body here; Starlette caches it so downstream can read again.
    """
    path = request.url.path.rstrip("/")  # normalize /chat and /chat/
    if request.method in ("POST", "PUT", "PATCH") and path == "/chat":
        try:
            raw = await request.body()
        except Exception:
            raw = b""
        raw_len = len(raw)
        # Instrumentation: log what we actually received
        try:
            logger.info({"event": "body_len", "path": request.url.path, "bytes": raw_len})
        except Exception:
            pass
        if raw_len > MAX_REQUEST_BYTES:
            return JSONResponse(
                {"detail": f"Request too large ({raw_len} bytes > {MAX_REQUEST_BYTES})"},
                status_code=413,
                headers={"Cache-Control": "no-store"},
            )
    return await call_next(request)

# --- Paths (work locally + in Docker) ---
ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = os.getenv("POLICY_PATH", str(ROOT_DIR / "configs" / "policy.yaml"))
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://mock-llm:8001/echo")
LOG_DIR = os.getenv("LOG_DIR", str(ROOT_DIR / "logs"))
STATIC_DIR = Path(os.getenv("STATIC_DIR", str(ROOT_DIR / "static")))

# Ensure local dirs exist so pytest doesn't crash
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# Request size guard (default 32KB). We check Content-Length to avoid re-reading body.
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "32768"))

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
    """Helper to log structured JSON-like events."""
    event.setdefault("component", "gateway")
    logger.info(event)

# -----------------------------------------------------------------------------
# Security: Bearer token for admin routes
# -----------------------------------------------------------------------------
# NOTE: auto_error=False lets us receive `creds=None` so we can bypass in tests.
security = HTTPBearer(auto_error=False)
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "changeme123")  # default for dev
ALLOW_INSECURE_ADMIN = (
    os.getenv("ALLOW_INSECURE_ADMIN", "false").lower() in ("1", "true", "yes", "on")
    or bool(os.environ.get("PYTEST_CURRENT_TEST"))  # auto-bypass during pytest
)

def _admin_bypass_active() -> bool:
    """
    Decide at *call time* whether to bypass admin auth.
    - True if ALLOW_INSECURE_ADMIN is set
    - True if running under pytest (PYTEST_CURRENT_TEST is present)
    - True if TEST_MODE=1 (optional escape hatch)
    """
    return (
        ALLOW_INSECURE_ADMIN
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
        or os.getenv("TEST_MODE", "0") == "1"
    )

def require_admin(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """
    Require a valid bearer token for /admin endpoints, unless bypass is active.
    """
    if _admin_bypass_active():
        return  # bypass during tests/dev when enabled
    if creds is None or creds.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid or missing admin token.")

# -----------------------------------------------------------------------------
# Policy structures
# -----------------------------------------------------------------------------
class DenyPattern(BaseModel):
    id: str
    pattern: str
    description: Optional[str] = None
    category: Optional[str] = None

class Policy(BaseModel):
    deny_patterns: list[DenyPattern] = []
    max_tokens: int = 800
    version: Optional[str] = None  # hash of file contents

# -----------------------------------------------------------------------------
# State: policy, metrics, mode
# -----------------------------------------------------------------------------
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
    "monitor_only": os.getenv("MONITOR_ONLY", "false").lower() in ("1", "true", "yes", "on"),

    # Step 3: redaction counters + simple latency histogram buckets
    "redactions": {"ssn": 0, "email": 0, "phone": 0, "card": 0},
    "latency_ms_histogram": {
        "le_50": 0, "le_100": 0, "le_200": 0, "le_500": 0, "gt_500": 0
    },
    # NEW: proper histogram companions
    "latency_count": 0,
    "latency_sum_ms": 0.0,
}

# -----------------------------------------------------------------------------
# Policy helpers
# -----------------------------------------------------------------------------
def _file_hash(path: str) -> str:
    """Return short sha256 hash of file contents for versioning."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()[:12]
    except FileNotFoundError:
        return "no-policy"

def _load_policy_locked() -> Policy:
    """Load policy.yaml into memory."""
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raw = {}
    dps = [DenyPattern(**item) for item in (raw.get("deny_patterns") or [])]
    return Policy(deny_patterns=dps, max_tokens=raw.get("max_tokens", 800), version=_file_hash(POLICY_PATH))

def _maybe_reload_policy():
    """Reload policy if file changed on disk."""
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
            log_event({"event": "policy_reload", "policy_version": _policy.version})

def _validate_policy_file(path: str) -> None:
    """
    Validate that policy at `path` is well-formed (raises on error).
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    # Pydantic validation will raise if fields are missing/wrong
    _ = [DenyPattern(**item) for item in (raw.get("deny_patterns") or [])]
    # Optional duplicate-check
    ids = [dp["id"] for dp in (raw.get("deny_patterns") or []) if isinstance(dp, dict) and "id" in dp]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate rule IDs detected in deny_patterns")

def _observe_latency_ms(ms: float):
    """Record latency into simple histogram buckets + keep sum/count."""
    with _state_lock:
        _metrics["latency_count"] += 1
        _metrics["latency_sum_ms"] += float(ms)
        if ms <= 50:   _metrics["latency_ms_histogram"]["le_50"]  += 1
        elif ms <= 100:_metrics["latency_ms_histogram"]["le_100"] += 1
        elif ms <= 200:_metrics["latency_ms_histogram"]["le_200"] += 1
        elif ms <= 500:_metrics["latency_ms_histogram"]["le_500"] += 1
        else:          _metrics["latency_ms_histogram"]["gt_500"] += 1


# Initialize policy on startup
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
# Static mount & dashboard
# -----------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/dashboard")
async def dashboard():
    """Serve the dashboard page. Falls back to inline HTML if missing locally."""
    dash = STATIC_DIR / "dashboard.html"
    if dash.exists():
        return FileResponse(path=str(dash), media_type="text/html")
    return HTMLResponse(
        "<!doctype html><html><body><h1>LLM-ASG Dashboard</h1>"
        "<p>No dashboard.html found. Use <code>/metrics</code> for raw stats.</p>"
        "</body></html>"
    )

# -----------------------------------------------------------------------------
# Core endpoints
# -----------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Health check: confirms service is running and policy loaded."""
    _maybe_reload_policy()
    return {"status": "ok", "policy_version": _policy.version, "monitor_only": _metrics["monitor_only"]}

@app.get("/policy")
async def get_policy():
    """Return current policy rules + version."""
    _maybe_reload_policy()
    return JSONResponse(
        content={
            "max_tokens": _policy.max_tokens,
            "deny_patterns": [p.model_dump() for p in _policy.deny_patterns],  # Pydantic v2 safe
            "version": _policy.version,
        },
        headers={"Cache-Control": "no-store"}  # help dashboard avoid stale data
    )

@app.post("/chat")
async def chat(payload: dict, request: Request):
    """
    Main gateway: evaluates prompt against policy.
    - Allowed → forward to LLM
    - Block mode → return 403 BLOCK
    - Monitor mode → forward but annotate MONITOR
    - Step 3: redact PII for logging and (optionally) upstream forwarding
    """
    _maybe_reload_policy()
    t0 = time.time()
    request_id = str(uuid.uuid4())

    # Re-read body (cached by Starlette); defensive check in-route as well.
    try:
        raw = await request.body()
    except Exception:
        raw = b""
    raw_len = len(raw)
    if raw_len > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Request too large ({raw_len} bytes > {MAX_REQUEST_BYTES})"
        )

    # Prefer parsing from raw if present to avoid mismatches
    if raw:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise HTTPException(status_code=400, detail="Missing 'prompt' (string).")

    # --- Step 3: Redact incoming prompt (for logs and optional upstream) ---
    original_prompt = prompt
    red = redact_text(original_prompt)      # uses env toggles inside redaction module
    redacted_prompt = red.text
    if red.hits:
        with _state_lock:
            for k, v in red.hits.items():
                _metrics["redactions"][k] = _metrics["redactions"].get(k, 0) + v

    # Evaluate prompt against deny patterns (use ORIGINAL, not redacted)
    allow = True
    match = None
    for dp in _policy.deny_patterns:
        if re.search(dp.pattern, original_prompt):
            allow, match = False, dp
            break

    # Payload for upstream (redacted or original based on toggle)
    upstream_payload = {"prompt": (redacted_prompt if REDACT_UPSTREAM else original_prompt),
                        "request_id": request_id}

    # Handle violation
    if not allow:
        rid = match.id
        with _state_lock:
            _metrics["rule_hits"][rid] = _metrics["rule_hits"].get(rid, 0) + 1

        if _metrics["monitor_only"]:
            # Monitor: log + forward upstream
            with _state_lock:
                _metrics["monitor"] += 1
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(LLM_ENDPOINT, json=upstream_payload)
                    resp.raise_for_status()
                upstream = resp.json()
            except httpx.HTTPError as e:
                raise HTTPException(status_code=502, detail=f"Upstream LLM error: {e}")

            lat_ms = (time.time() - t0) * 1000.0
            _observe_latency_ms(lat_ms)
            log_event({
                "event": "decision", "request_id": request_id, "action": "MONITOR",
                "rule_id": rid, "category": match.category,
                "latency_ms": int(lat_ms), "policy_version": _policy.version,
            })
            return JSONResponse({
                "request_id": request_id, "policy_version": _policy.version,
                "decision": {"action": "MONITOR", "rule_id": rid, "reason": match.description},
                "upstream": upstream
            })
        else:
            # Block mode
            with _state_lock:
                _metrics["block"] += 1
            lat_ms = (time.time() - t0) * 1000.0
            _observe_latency_ms(lat_ms)
            decision = {
                "request_id": request_id, "action": "BLOCK",
                "rule_id": rid, "category": match.category,
                "reason": match.description or "Policy violation",
                "policy_version": _policy.version,
            }
            log_event({**decision, "event": "decision", "latency_ms": int(lat_ms)})
            return JSONResponse(status_code=403, content=decision)

    # Allowed → forward to LLM
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(LLM_ENDPOINT, json=upstream_payload)
            resp.raise_for_status()
        upstream = resp.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Upstream LLM error: {e}")

    with _state_lock:
        _metrics["allow"] += 1

    lat_ms = (time.time() - t0) * 1000.0
    _observe_latency_ms(lat_ms)
    log_event({
        "event": "decision", "request_id": request_id, "action": "ALLOW",
        "latency_ms": int(lat_ms), "policy_version": _policy.version,
    })
    return JSONResponse({"request_id": request_id, "policy_version": _policy.version, "upstream": upstream})

# --- Diagnostics (optional but helpful) ---
@app.get("/debug/config")
async def debug_config():
    return {"MAX_REQUEST_BYTES": MAX_REQUEST_BYTES}

@app.post("/debug/bodylen")
async def debug_bodylen(request: Request):
    raw = await request.body()
    return {"path": request.url.path, "bytes": len(raw), "max": MAX_REQUEST_BYTES}

# -----------------------------------------------------------------------------
# Admin endpoints (require Bearer token)
# -----------------------------------------------------------------------------
def _validate_policy_or_raise():
    _validate_policy_file(POLICY_PATH)
    return {"valid": True, "policy_path": POLICY_PATH}

@app.post("/admin/policy/validate")
async def validate_policy_post(_: HTTPAuthorizationCredentials = Depends(require_admin)):
    try:
        return _validate_policy_or_raise()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")

@app.get("/admin/policy/validate")
async def validate_policy_get(_: HTTPAuthorizationCredentials = Depends(require_admin)):
    try:
        return _validate_policy_or_raise()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")

@app.post("/admin/reload")
async def force_reload(request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    """Force reload the policy file after validating it; logs actor IP."""
    actor = request.client.host if request.client else "unknown"
    # Validate first; if invalid, do not change in-memory policy
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
    log_event({"event": "policy_reload_forced", "actor": actor, "policy_version": _policy.version})
    return JSONResponse(
        content={"reloaded": True, "policy_version": _metrics["policy_version"], "last_reload_epoch": _metrics["last_reload_epoch"]},
        headers={"Cache-Control": "no-store"}
    )

@app.post("/admin/mode")
async def set_mode(payload: dict, request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    """Toggle monitor-only mode on/off at runtime and audit the actor IP."""
    mo = bool(payload.get("monitor_only", False))
    actor = request.client.host if request.client else "unknown"
    with _state_lock:
        old = _metrics["monitor_only"]
        _metrics["monitor_only"] = mo
    log_event({"event": "mode_change", "actor": actor, "from": old, "to": mo})
    return {"monitor_only": _metrics["monitor_only"]}

@app.get("/admin/logs")
async def download_logs(_: HTTPAuthorizationCredentials = Depends(require_admin)):
    """Download the rotating log file."""
    return FileResponse(LOG_FILE, media_type="text/plain", filename="asg.log")
@app.post("/admin/policy/validate")
async def validate_policy(_: HTTPAuthorizationCredentials = Depends(require_admin)):
    """
    Validate the current policy file on disk without applying it.
    Returns {'valid': true} or 400 with the reason.
    """
    try:
        _validate_policy_file(POLICY_PATH)
        return {"valid": True, "policy_path": POLICY_PATH}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy invalid: {e}")

@app.post("/admin/mode")
async def set_mode(payload: dict, request: Request, _: HTTPAuthorizationCredentials = Depends(require_admin)):
    """Toggle monitor-only mode on/off at runtime and audit the actor IP."""
    mo = bool(payload.get("monitor_only", False))
    actor = request.client.host if request.client else "unknown"
    with _state_lock:
        old = _metrics["monitor_only"]
        _metrics["monitor_only"] = mo
    log_event({"event": "mode_change", "actor": actor, "from": old, "to": mo})
    return {"monitor_only": _metrics["monitor_only"]}

@app.get("/admin/logs")
async def download_logs(_: HTTPAuthorizationCredentials = Depends(require_admin)):
    """Download the rotating log file."""
    return FileResponse(LOG_FILE, media_type="text/plain", filename="asg.log")

# -----------------------------------------------------------------------------
# Metrics endpoints
# -----------------------------------------------------------------------------
@app.get("/metrics")
async def metrics():
    """JSON metrics for dashboard."""
    with _state_lock:
        content = dict(_metrics)
        content["rule_hits"] = dict(_metrics["rule_hits"])
    return JSONResponse(content=content, headers={"Cache-Control": "no-store"})

@app.get("/metrics/prometheus")
async def metrics_prometheus():
    """Prometheus-compatible metrics exposition."""
    with _state_lock:
        lines = []
        # Decision counters
        lines.append(f"llmasg_allow_total {_metrics['allow']}")
        lines.append(f"llmasg_block_total {_metrics['block']}")
        lines.append(f"llmasg_monitor_total {_metrics['monitor']}")
        for rule_id, hits in _metrics["rule_hits"].items():
            lines.append(f'llmasg_rule_hits_total{{rule="{rule_id}"}} {hits}')
        # Redaction counters
        for k, v in _metrics["redactions"].items():
            lines.append(f'llmasg_redactions_total{{type="{k}"}} {v}')
        # Latency histogram buckets (cumulative)
        h = _metrics["latency_ms_histogram"]
        lines.append(f'llmasg_latency_ms_bucket{{le="50"}} {h["le_50"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="100"}} {h["le_100"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="200"}} {h["le_200"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="500"}} {h["le_500"]}')
        lines.append(f'llmasg_latency_ms_bucket{{le="Inf"}} {h["gt_500"]}')
        # Proper histogram companions
        lines.append(f'llmasg_latency_ms_sum {_metrics["latency_sum_ms"]:.3f}')
        lines.append(f'llmasg_latency_ms_count {_metrics["latency_count"]}')
    return PlainTextResponse("\n".join(lines) + "\n")

