VERSION := $(shell poetry run python -c "import challenge; print(challenge.__version__)")

all: build

.PHONY: build
build: test lint
	docker build -t challenge/protector:$(VERSION) .

.PHONY: lint
lint:
	@ # TODO: see how other python project achieves lower line length.
	poetry run flake8 --exclude 'tests/test_*.py' --max-line-length 120

.PHONY: test
test:
	@ # TODO: --forked is used to reset the statefully instrumentalized `connections()` in between tests.
	poetry run pytest --forked -v

.PHONY: clean
clean:
	docker rmi challenge/protector:$(VERSION)
