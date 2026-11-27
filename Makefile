.PHONY: help setup validate up down test check check-release chaos bench demo demo-recorded clean

VENV ?= .venv
BOOTSTRAP_PYTHON ?= python3
PYTHON ?= $(VENV)/bin/python
PIP ?= $(PYTHON) -m pip

help:
	@echo "Trust-But-Verify Commands:"
	@echo "  make setup - Create .venv and install every validation dependency"
	@echo "  make validate - Clean-machine lint, tests, docs, and offline submission checks"
	@echo "  make up    - Spin up sandbox cluster with Docker Compose"
	@echo "  make down  - Stop and tear down sandbox cluster"
	@echo "  make test  - Run full test suite"
	@echo "  make check - Verify the two-page brief and README links"
	@echo "  make check-release - Also require a public walkthrough link"
	@echo "  make chaos - Run lifecycle & crash chaos tests"
	@echo "  make bench - Run latency & throughput benchmarks"
	@echo "  make demo  - Run the live judge walkthrough"
	@echo "  make demo-recorded - Show recorded evidence without starting services"
	@echo "  make clean - Remove cache, temporary logs and data"

setup:
	$(BOOTSTRAP_PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

validate: setup
	$(PYTHON) -m ruff check src tests track4_service.py
	$(PYTHON) -m pytest -q
	$(PYTHON) -m src.cli doc-check
	$(PYTHON) -m scripts.check_submission --offline

up:
	docker compose up -d --build

down:
	docker compose down -v

test:
	$(PYTHON) -m pytest tests/ -v

check:
	$(PYTHON) -m scripts.check_submission

check-release:
	$(PYTHON) -m scripts.check_submission --require-public-video

chaos:
	$(PYTHON) -m pytest tests/test_lifecycle_chaos.py -v || $(PYTHON) -m unittest tests/test_lifecycle_chaos.py -v

bench:
	$(PYTHON) scripts/benchmark.py

demo:
	PYTHON="$(PYTHON)" ./scripts/run_demo.sh

demo-recorded:
	@echo "Recorded evidence only. No live checks are running."
	@cat reports/demo_run.md

clean:
	rm -rf __pycache__ src/**/__pycache__ tests/__pycache__ .pytest_cache /tmp/tbv_data /tmp/demo_audit.log .venv
