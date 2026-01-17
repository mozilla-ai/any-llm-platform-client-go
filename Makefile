.PHONY: lint test build clean fmt install

# Run linting with auto-fix
lint:
	golangci-lint run --fix ./...

# Run all tests
test: lint
	go test -v -race ./...

# Run tests without linting (faster)
test-only:
	go test -v -race ./...

# Run unit tests only (skip integration tests)
test-unit:
	go test -v -race -short ./...

# Build and verify compilation
build:
	go build ./...

# Build CLI
build-cli:
	go build -o bin/any-llm ./cmd/any-llm

# Install CLI
install:
	go install ./cmd/any-llm

# Format code
fmt:
	gofmt -s -w .
	goimports -w .

# Clean test cache
clean:
	go clean -testcache
	rm -rf bin/

# Tidy dependencies
tidy:
	go mod tidy

# Run all checks (lint + test + build)
all: lint test build
