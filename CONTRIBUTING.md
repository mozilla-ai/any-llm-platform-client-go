# Contributing to any-llm-platform-client-go

Thank you for your interest in contributing to this project! This guide will help you get started.

## Development Setup

### Prerequisites

- Go 1.23 or newer
- golangci-lint (for linting)
- make (optional, for convenience)

### Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/mozilla-ai/any-llm-platform-client-go
   cd any-llm-platform-client-go
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Run tests:
   ```bash
   go test -v ./...
   ```

4. Run linting:
   ```bash
   golangci-lint run ./...
   ```

## Project Structure

```
any-llm-platform-client-go/
├── cmd/
│   └── any-llm/           # CLI application
│       └── main.go
├── examples/
│   └── basic/             # Example usage
│       └── main.go
├── internal/
│   └── testutil/          # Test utilities (internal)
├── .github/
│   └── workflows/         # CI/CD workflows
│       └── ci.yaml
├── client.go              # HTTP client implementation
├── client_test.go         # Client tests
├── crypto.go              # Cryptographic utilities
├── crypto_test.go         # Crypto tests
├── errors.go              # Error types
├── go.mod                 # Go module definition
├── go.sum                 # Dependency checksums
├── Makefile               # Build automation
├── .golangci.yaml         # Linting configuration
├── README.md              # Project documentation
├── ARCHITECTURE.md        # Cryptographic architecture docs
├── CONTRIBUTING.md        # This file
└── LICENSE                # Apache 2.0 license
```

## Coding Standards

### Naming Conventions

- **Exported (public)**: PascalCase (e.g., `NewClient`, `DecryptData`)
- **Unexported (private)**: camelCase (e.g., `handleError`, `parseKey`)
- **Constants**: PascalCase or ALL_CAPS for well-known constants

### Error Handling

- Use sentinel errors for common conditions (`ErrInvalidKey`, `ErrDecryption`)
- Use typed errors for detailed information (`*ChallengeCreationError`, `*ProviderKeyFetchError`)
- Always wrap errors with context using `fmt.Errorf("context: %w", err)`

### Testing

- Use table-driven tests with `t.Run()`
- Use `require` for fatal assertions, `assert` for non-fatal
- Mock HTTP responses using `httptest.NewServer`

Example:
```go
func TestSomething(t *testing.T) {
    t.Run("success case", func(t *testing.T) {
        // test code
    })

    t.Run("error case", func(t *testing.T) {
        // test code
    })
}
```

## Making Changes

1. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and write tests

3. Run the test suite:
   ```bash
   make test
   ```

4. Run linting:
   ```bash
   make lint
   ```

5. Commit your changes with a descriptive message:
   ```bash
   git commit -m "Add feature X that does Y"
   ```

6. Push and create a pull request

## Pull Request Guidelines

- Keep PRs focused and small when possible
- Include tests for new functionality
- Update documentation if needed
- Ensure all CI checks pass
- Reference any related issues

## Code of Conduct

Please be respectful and constructive in all interactions. We're all here to build great software together.

## Questions?

If you have questions, please open an issue or reach out to the maintainers.
