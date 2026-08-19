PYTHON ?= python3
VENV ?= .venv
PNPM := npx --yes pnpm@10.6.3

.PHONY: setup setup-api api web lint test test-api test-web build docker-api demo

setup: setup-api

setup-api:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e .[dev]
	cd apps/web && $(PNPM) install

api:
	$(VENV)/bin/uvicorn kubesentry.main:app --app-dir apps/api/src --host 0.0.0.0 --port 4900

web:
	cd apps/web && $(PNPM) dev

lint:
	$(VENV)/bin/ruff check .

test-api:
	$(VENV)/bin/pytest -q

test-web:
	cd apps/web && $(PNPM) test

test: lint test-api test-web

build:
	cd apps/web && $(PNPM) build

docker-api:
	docker compose up --build api

demo:
	@echo "Terminal 1: make api"
	@echo "Terminal 2: make web"
	@echo "Open http://localhost:5200 and choose a synthetic fixture or submit an authorized local manifest."
