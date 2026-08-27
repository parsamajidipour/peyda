.SHELLFLAGS := -eu -o pipefail -c
SHELL := /bin/bash

.PHONY: build test lint check

build:
	go build -o bin/reconx ./cmd/reconx

test:
	go test ./...
	if compgen -G "scripts/*.sh" > /dev/null; then bash -n scripts/*.sh; fi

lint:
	npx markdownlint-cli2 "**/*.md" "#runs/**" "#.cache/**"

check: test lint
	git diff --check
