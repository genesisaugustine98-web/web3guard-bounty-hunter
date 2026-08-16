.PHONY: test bench bench-gate lint

test:
	python3 -m pytest -q

# Run the precision/recall benchmark over the in-repo corpus.
bench:
	python3 -m web3guard.cli bench

# CI gate: fail if precision or recall drops below the floor.
# Floors are intentionally strict for the in-repo fixtures; raise them
# as the analyzer improves on external corpora (e.g. ARC).
bench-gate:
	python3 -m web3guard.cli bench --fail-below 0.99,0.95

lint:
	python3 -m ruff check web3guard tests
