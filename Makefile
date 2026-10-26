export PATH := $(HOME)/.cargo/bin:$(PATH)
PY := .venv/bin/python
PYTEST := .venv/bin/pytest

.PHONY: test rust-test python-test bench demo venv

test: rust-test python-test

venv: $(PYTEST)

$(PYTEST):
	python3.12 -m venv .venv
	.venv/bin/pip install -q pytest

rust-test:
	cargo test

python-test: $(PYTEST)
	$(PYTEST) -q python/tests

bench:
	cargo run --release -p aegis-runtime -- bench all

demo: $(PYTEST)
	cargo build --release -p aegis-runtime
	cd python && PYTHONPATH=. ../$(PY) -m aegis demo --runtime ../target/release/aegis --bench
