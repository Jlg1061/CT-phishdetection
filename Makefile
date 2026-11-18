# One-command reproducibility. Run `make help` to see targets.
# Uses a plain Python venv + pip (no conda).
.PHONY: help setup reproduce test lint clean

VENV := .venv
PY := $(VENV)/bin/python

help:
	@echo "make setup      - create .venv and install requirements"
	@echo "make reproduce  - train + evaluate, writing results/ (THE grading command)"
	@echo "make test       - run smoke tests"
	@echo "make lint       - byte-compile check (stdlib only)"
	@echo "make clean      - remove generated results"

setup:
	python3 -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt

# The single command a grader runs. Must recreate your reported results.
reproduce:
	$(PY) -m src.train --config config.yaml

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m py_compile src/*.py tests/*.py

clean:
	rm -f results/*.png results/*.json results/*.pt
