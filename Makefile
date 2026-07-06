PYTHON ?= python3

.PHONY: help install dev test demo lint clean

help:
	@echo "advsim - benign, authorized-use-only adversary-emulation harness"
	@echo ""
	@echo "  make install   install advsim"
	@echo "  make dev       install with dev extras (pytest)"
	@echo "  make test      run the full test suite (incl. scope guard)"
	@echo "  make demo      run the cross-platform demo driver"
	@echo "  make clean     remove build artifacts and the sandbox"

install:
	$(PYTHON) -m pip install .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) demos/run_all_demos.py

clean:
	-advsim cleanup
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
