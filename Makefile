.PHONY: help setup up down test chaos bench demo gates clean distclean

# All project targets run inside the local virtualenv created by `make setup`.
# Override PYTHON only if you know that interpreter already has requirements.txt.
PYTHON ?= .venv/bin/python
BASE_PYTHON ?= python3.11
PIP := $(PYTHON) -m pip
VENV ?= .venv

help:
	@echo "Trust-But-Verify Commands:"
	@echo "  make setup - Create .venv, install pinned deps, enable git hooks"
	@echo "  make up    - Spin up sandbox cluster with Docker Compose"
	@echo "  make down  - Stop and tear down sandbox cluster"
	@echo "  make test  - Run full test suite from the repo root"
	@echo "  make gates - Run lint, type, CLI, and test gates"
	@echo "  make chaos - Run lifecycle & crash chaos tests"
	@echo "  make bench - Run reproducible performance measurements"
	@echo "  make demo  - Run 5-minute judge walkthrough demo"
	@echo "  make clean - Remove caches, temporary logs and data"
	@echo "  make distclean - Also remove .venv"

setup:
	@if [ ! -x "$(VENV)/bin/python" ]; then \
		echo "Creating $(VENV) with $(BASE_PYTHON)..."; \
		$(BASE_PYTHON) -m venv $(VENV); \
	fi
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	git config core.hooksPath .githooks
	@echo "Setup complete. Run 'make test' or 'make demo'."

up:
	docker compose up -d --build

down:
	docker compose down -v

test:
	$(PYTHON) -m pytest . -q

gates:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy
	$(PYTHON) -m src.cli verify-logs > /dev/null
	$(PYTHON) -m pytest . -q

chaos:
	$(PYTHON) -m pytest tests/test_lifecycle_chaos.py -v || $(PYTHON) -m unittest tests/test_lifecycle_chaos.py -v

bench:
	$(PYTHON) scripts/benchmark.py

demo:
	PATH="$(CURDIR)/$(VENV)/bin:$$PATH" ./scripts/run_demo.sh

clean:
	rm -rf __pycache__ src/**/__pycache__ tests/__pycache__ .pytest_cache /tmp/tbv_data /tmp/demo_audit.log

distclean: clean
	rm -rf $(VENV)
