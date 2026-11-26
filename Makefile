.PHONY: setup test demo bench clean verify-log help

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
VENV ?= .venv

help:
	@echo "Trust-But-Verify Makefile Commands:"
	@echo "  make setup      - Install dependencies into environment"
	@echo "  make test       - Run all automated security & lifecycle tests"
	@echo "  make demo       - Run end-to-end judge walkthrough demo"
	@echo "  make bench      - Run cryptographic and detector latency benchmarks"
	@echo "  make clean      - Clean temp files, logs, and python bytecode"

setup:
	$(PIP) install -r requirements.txt || echo "Note: Running in standalone standard-library fallback mode."

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py"

demo:
	./scripts/run_demo.sh

bench:
	$(PYTHON) scripts/benchmark.py

verify-log:
	$(PYTHON) -m src.audit.verifier /tmp/tbv_data/node-1_audit.log

clean:
	rm -rf __pycache__ src/**/__pycache__ tests/__pycache__ .pytest_cache /tmp/tbv_data /tmp/demo_audit.log .venv
