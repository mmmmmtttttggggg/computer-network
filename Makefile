PYTHON ?= python3

.PHONY: install serve test lint demo benchmark lab-up lab-down browser-test
install:
	$(PYTHON) -m pip install -r requirements.lock
	$(PYTHON) -m pip install -e '.[dev]'
serve:
	$(PYTHON) -m app.cli serve
test:
	$(PYTHON) -m pytest -q
lint:
	$(PYTHON) -m ruff check src tests scripts
	$(PYTHON) -m ruff format --check src tests scripts
demo:
	$(PYTHON) -m app.cli demo --out artifacts/demo
benchmark:
	$(PYTHON) scripts/benchmark.py artifacts/benchmark.json
lab-up:
	$(PYTHON) scripts/lab.py up
lab-down:
	$(PYTHON) scripts/lab.py down
browser-test:
	$(PYTHON) scripts/browser_smoke.py
