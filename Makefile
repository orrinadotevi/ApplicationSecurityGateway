.PHONY: test lint k6 quick-metrics

test:
	pytest -q

k6:
	@echo "Running k6 (BASE?=$(BASE), VUS?=$(VUS), DURATION?=$(DURATION))"
	k6 run load/k6-chat.js

quick-metrics:
	curl -s http://localhost:8000/metrics | jq .

lint:
	ruff check .
