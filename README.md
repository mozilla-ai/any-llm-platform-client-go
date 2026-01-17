# Provider Key Decrypter (Go)

Go package to decrypt provider API keys using X25519 sealed box encryption and challenge-response authentication with the ANY LLM backend.

## Installation

```bash
go get github.com/mozilla-ai/any-llm-platform-client-go
```

### CLI Installation

```bash
go install github.com/mozilla-ai/any-llm-platform-client-go/cmd/any-llm@latest
```

## Usage

### Command Line Interface

Interactive mode (prompts for provider):
```bash
export ANY_LLM_KEY='ANY.v1.<kid>.<fingerprint>-<base64_key>'
any-llm
```

Direct mode (specify provider as argument):
```bash
any-llm openai
```

With custom platform URL:
```bash
any-llm -platform-url https://api.example.com/v1 openai
```

### Configuring the API Base URL

By default, the client connects to `http://localhost:8000/api/v1`. To change this:

```go
package main

import (
    anyllmplatform "github.com/mozilla-ai/any-llm-platform-client-go"
)

func main() {
    // Create a client that talks to a different backend
    client := anyllmplatform.NewClient(
        anyllmplatform.WithPlatformURL("https://api.example.com/v1"),
    )

    // Now calls on client will use the configured base URL
}
```

Or set the environment variable before running the CLI:
```bash
export ANY_LLM_PLATFORM_URL="https://staging-api.example.com/v1"
any-llm openai
```

### As a Go Library

#### Simple Usage (Recommended)

```go
package main

import (
    "context"
    "fmt"
    "log"

    anyllmplatform "github.com/mozilla-ai/any-llm-platform-client-go"
)

func main() {
    ctx := context.Background()

    // Create client
    client := anyllmplatform.NewClient()

    // Get decrypted provider key with metadata in one call
    anyLLMKey := "ANY.v1.12345678.abcdef01-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA=="
    result, err := client.GetDecryptedProviderKey(ctx, anyLLMKey, "openai")
    if err != nil {
        log.Fatal(err)
    }

    // Access the decrypted API key and metadata
    fmt.Printf("API Key: %s\n", result.APIKey)
    fmt.Printf("Provider Key ID: %s\n", result.ProviderKeyID)
    fmt.Printf("Project ID: %s\n", result.ProjectID)
    fmt.Printf("Provider: %s\n", result.Provider)
    fmt.Printf("Created At: %s\n", result.CreatedAt)
}
```

#### Advanced Usage (Manual Steps)

For more control over the authentication flow:

```go
package main

import (
    "context"
    "fmt"
    "log"

    anyllmplatform "github.com/mozilla-ai/any-llm-platform-client-go"
)

func main() {
    ctx := context.Background()

    // Parse the key
    anyLLMKey := "ANY.v1...."
    keyComponents, err := anyllmplatform.ParseAnyLLMKey(anyLLMKey)
    if err != nil {
        log.Fatal(err)
    }

    // Load private key
    privateKey, err := anyllmplatform.LoadPrivateKey(keyComponents.Base64EncodedPrivateKey)
    if err != nil {
        log.Fatal(err)
    }

    // Extract public key
    publicKey, err := anyllmplatform.ExtractPublicKey(privateKey)
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate with challenge-response using the client
    client := anyllmplatform.NewClient()
    challengeData, err := client.CreateChallenge(ctx, publicKey)
    if err != nil {
        log.Fatal(err)
    }

    solvedChallenge, err := client.SolveChallenge(challengeData.EncryptedChallenge, privateKey)
    if err != nil {
        log.Fatal(err)
    }

    // Request access token
    accessToken, err := client.RequestAccessToken(ctx, solvedChallenge)
    if err != nil {
        log.Fatal(err)
    }

    // Fetch and decrypt provider key
    providerKeyData, err := client.FetchProviderKey(ctx, "openai", accessToken)
    if err != nil {
        log.Fatal(err)
    }

    apiKey, err := client.DecryptProviderKeyValue(providerKeyData.EncryptedKey, privateKey)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("API Key: %s\n", apiKey)
}
```

### Error Handling

All errors can be checked using Go's `errors.Is` and `errors.As`:

```go
import "errors"

result, err := client.GetDecryptedProviderKey(ctx, anyLLMKey, "openai")
if err != nil {
    switch {
    case errors.Is(err, anyllmplatform.ErrChallengeCreation):
        // Handle challenge creation errors
    case errors.Is(err, anyllmplatform.ErrProviderKeyFetch):
        // Handle provider key fetch errors
    case errors.Is(err, anyllmplatform.ErrInvalidKey):
        // Handle invalid key format errors
    case errors.Is(err, anyllmplatform.ErrDecryption):
        // Handle decryption errors
    default:
        // Handle other errors
    }
}

// Get more details with type assertions
var challengeErr *anyllmplatform.ChallengeCreationError
if errors.As(err, &challengeErr) {
    fmt.Printf("Challenge failed with status %d: %s\n", challengeErr.StatusCode, challengeErr.Message)
}
```

## How It Works

1. The library extracts the X25519 private key from your ANY_LLM_KEY
2. Derives the public key and sends it to create an authentication challenge
3. The backend returns an encrypted challenge
4. Decrypts the challenge UUID using your private key
5. Uses the solved challenge to authenticate and fetch the encrypted provider key
6. Decrypts the provider API key using your private key

## Requirements

- Go 1.23+
- `golang.org/x/crypto` (for X25519 and XChaCha20-Poly1305)

## ANY_LLM_KEY Format

```
ANY.v1.<kid>.<fingerprint>-<base64_32byte_private_key>
```

Generate your ANY_LLM_KEY from the project page in the web UI.

## Security Notes

- The private key from your ANY_LLM_KEY is highly sensitive and should never be logged or transmitted over insecure channels
- This package uses X25519 sealed box encryption with XChaCha20-Poly1305 for strong cryptographic guarantees

## Development

Run tests:
```bash
go test -v ./...
```

Run tests with race detection:
```bash
go test -v -race ./...
```

Run linting:
```bash
golangci-lint run ./...
```

Build:
```bash
go build ./...
```

## Comparison with Python Version

This is the official Go port of [any-llm-platform-client](https://github.com/mozilla-ai/any-llm-platform-client). Key differences:

| Feature | Python | Go |
|---------|--------|-----|
| Async support | `async`/`await` | Goroutines + context |
| Error handling | Exceptions | `error` return values |
| Type hints | Type annotations | Static types |
| HTTP client | httpx | net/http |
| Crypto library | PyNaCl | golang.org/x/crypto |

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
