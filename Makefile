.PHONY: help setup up down test check chaos bench demo demo-recorded clean

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
VENV ?= .venv

help:
	@echo "Trust-But-Verify Commands:"
	@echo "  make setup - Install local dependencies"
	@echo "  make up    - Spin up sandbox cluster with Docker Compose"
	@echo "  make down  - Stop and tear down sandbox cluster"
	@echo "  make test  - Run full test suite"
	@echo "  make check - Verify the two-page brief and README links"
	@echo "  make chaos - Run lifecycle & crash chaos tests"
	@echo "  make bench - Run latency & throughput benchmarks"
	@echo "  make demo  - Run the live judge walkthrough"
	@echo "  make demo-recorded - Show recorded evidence without starting services"
	@echo "  make clean - Remove cache, temporary logs and data"

setup:
	$(PIP) install -r requirements.txt

up:
	docker compose up -d --build

down:
	docker compose down -v

test:
	$(PYTHON) -m pytest tests/ -v

check:
	$(PYTHON) -m scripts.check_submission

chaos:
	$(PYTHON) -m pytest tests/test_lifecycle_chaos.py -v || $(PYTHON) -m unittest tests/test_lifecycle_chaos.py -v

bench:
	$(PYTHON) scripts/benchmark.py

demo:
	./scripts/run_demo.sh

demo-recorded:
	@echo "Recorded evidence only. No live checks are running."
	@cat reports/demo_run.md

clean:
	rm -rf __pycache__ src/**/__pycache__ tests/__pycache__ .pytest_cache /tmp/tbv_data /tmp/demo_audit.log .venv
