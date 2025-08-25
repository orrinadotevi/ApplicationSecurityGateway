# LLM-ASG Step 1 Skeleton

Foundation scaffold for the LLM Application Security Gateway project.

## Quick Start
```bash
docker compose up --build
```
- Gateway: http://localhost:8000
- Mock LLM: http://localhost:8001

### Health Check
```bash
curl http://localhost:8000/health
```

### Policy Check
```bash
curl http://localhost:8000/policy
```

### Chat Echo
```bash
curl -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d '{"prompt":"Hello!"}'
```

## Local Dev
```bash
uvicorn src.main:app --reload --port 8000
uvicorn scripts.mock_llm:app --port 8001
```

## Tests
```bash
pytest -q
```
