.PHONY: help setup up down test chaos bench demo clean

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
VENV ?= .venv

help:
	@echo "Trust-But-Verify Commands:"
	@echo "  make setup - Install local dependencies"
	@echo "  make up    - Spin up sandbox cluster with Docker Compose"
	@echo "  make down  - Stop and tear down sandbox cluster"
	@echo "  make test  - Run full test suite"
	@echo "  make chaos - Run lifecycle & crash chaos tests"
	@echo "  make bench - Run latency & throughput benchmarks"
	@echo "  make demo  - Run 5-minute judge walkthrough demo"
	@echo "  make clean - Remove cache, temporary logs and data"

setup:
	$(PIP) install -r requirements.txt

up:
	docker compose up -d --build

down:
	docker compose down -v

test:
	$(PYTHON) -m pytest tests/test_crypto_security.py tests/test_lifecycle_chaos.py tests/test_log_injection.py tests/test_detector_eval.py tests/test_integration_e2e.py tests/test_security_regression.py -v

chaos:
	$(PYTHON) -m pytest tests/test_lifecycle_chaos.py -v || $(PYTHON) -m unittest tests/test_lifecycle_chaos.py -v

bench:
	$(PYTHON) scripts/benchmark.py

demo:
	./scripts/run_demo.sh

clean:
	rm -rf __pycache__ src/**/__pycache__ tests/__pycache__ .pytest_cache /tmp/tbv_data /tmp/demo_audit.log .venv
