.PHONY: build test lint check

build:
	go build -o bin/reconx ./cmd/reconx

test:
	go test ./...
	bash -n scripts/*.sh

lint:
	npx markdownlint-cli2 "**/*.md"

check: test lint
	git diff --check
