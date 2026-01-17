package anyllmplatform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	t.Run("creates client with default URL", func(t *testing.T) {
		t.Parallel()
		client := NewClient()
		assert.Equal(t, DefaultPlatformURL, client.PlatformURL)
		assert.NotNil(t, client.HTTPClient)
	})

	t.Run("creates client with custom URL", func(t *testing.T) {
		t.Parallel()
		customURL := "https://api.example.com/v1"
		client := NewClient(WithPlatformURL(customURL))
		assert.Equal(t, customURL, client.PlatformURL)
	})

	t.Run("creates client with custom HTTP client", func(t *testing.T) {
		t.Parallel()
		customHTTPClient := &http.Client{}
		client := NewClient(WithHTTPClient(customHTTPClient))
		assert.Same(t, customHTTPClient, client.HTTPClient)
	})
}

func TestCreateChallenge(t *testing.T) {
	t.Parallel()

	t.Run("creates challenge successfully", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/auth/", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var body map[string]string
			err := json.NewDecoder(r.Body).Decode(&body)
			require.NoError(t, err)
			assert.Equal(t, "test-public-key", body["encryption_key"])

			w.WriteHeader(http.StatusOK)
			err = json.NewEncoder(w).Encode(map[string]string{
				"encrypted_challenge": "test-challenge",
			})
			require.NoError(t, err)
		}))
		defer server.Close()

		client := NewClient(WithPlatformURL(server.URL))
		result, err := client.CreateChallenge(context.Background(), "test-public-key")

		require.NoError(t, err)
		assert.Equal(t, "test-challenge", result.EncryptedChallenge)
	})

	t.Run("returns error on non-200 status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "Bad request"}`))
		}))
		defer server.Close()

		client := NewClient(WithPlatformURL(server.URL))
		_, err := client.CreateChallenge(context.Background(), "test-public-key")

		require.Error(t, err)
		var challengeErr *ChallengeCreationError
		assert.True(t, errors.As(err, &challengeErr))
		assert.Equal(t, http.StatusBadRequest, challengeErr.StatusCode)
	})

	t.Run("returns specific error for no project found", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": "No project found"}`))
		}))
		defer server.Close()

		client := NewClient(WithPlatformURL(server.URL))
		_, err := client.CreateChallenge(context.Background(), "test-public-key")

		require.Error(t, err)
		var challengeErr *ChallengeCreationError
		assert.True(t, errors.As(err, &challengeErr))
		assert.Contains(t, challengeErr.Message, "No project found")
	})
}

func TestRequestAccessToken(t *testing.T) {
	t.Parallel()

	t.Run("requests access token successfully", func(t *testing.T) {
		t.Parallel()
		challengeUUID := uuid.New()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/auth/token", r.URL.Path)

			var body map[string]string
			err := json.NewDecoder(r.Body).Decode(&body)
			require.NoError(t, err)
			assert.Equal(t, challengeUUID.String(), body["solved_challenge"])

			w.WriteHeader(http.StatusOK)
			err = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
				"token_type":   "bearer",
			})
			require.NoError(t, err)
		}))
		defer server.Close()

		client := NewClient(WithPlatformURL(server.URL))
		result, err := client.RequestAccessToken(context.Background(), challengeUUID)

		require.NoError(t, err)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", result)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", client.accessToken)
		assert.False(t, client.tokenExpiresAt.IsZero())
	})

	t.Run("returns error on non-200 status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "Invalid challenge"}`))
		}))
		defer server.Close()

		client := NewClient(WithPlatformURL(server.URL))
		_, err := client.RequestAccessToken(context.Background(), uuid.New())

		require.Error(t, err)
		var challengeErr *ChallengeCreationError
		assert.True(t, errors.As(err, &challengeErr))
		assert.Equal(t, http.StatusUnauthorized, challengeErr.StatusCode)
	})
}

func TestFetchProviderKey(t *testing.T) {
	t.Parallel()

	t.Run("fetches provider key successfully", func(t *testing.T) {
		t.Parallel()
		accessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/provider-keys/openai", r.URL.Path)
			assert.Equal(t, "Bearer "+accessToken, r.Header.Get("Authorization"))

			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(map[string]string{
				"id":            uuid.New().String(),
				"project_id":    uuid.New().String(),
				"provider":      "openai",
				"encrypted_key": "encrypted-api-key",
				"created_at":    "2025-01-01T00:00:00Z",
			})
			require.NoError(t, err)
		}))
		defer server.Close()

		client := NewClient(WithPlatformURL(server.URL))
		result, err := client.FetchProviderKey(context.Background(), "openai", accessToken)

		require.NoError(t, err)
		assert.Equal(t, "openai", result.Provider)
		assert.Equal(t, "encrypted-api-key", result.EncryptedKey)
	})

	t.Run("returns error on non-200 status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "Unauthorized"}`))
		}))
		defer server.Close()

		client := NewClient(WithPlatformURL(server.URL))
		_, err := client.FetchProviderKey(context.Background(), "openai", "invalid-token")

		require.Error(t, err)
		var fetchErr *ProviderKeyFetchError
		assert.True(t, errors.As(err, &fetchErr))
		assert.Equal(t, http.StatusUnauthorized, fetchErr.StatusCode)
		assert.Equal(t, "openai", fetchErr.Provider)
	})
}

func TestGetPublicKey(t *testing.T) {
	t.Parallel()

	t.Run("extracts public key from ANY_LLM_KEY", func(t *testing.T) {
		t.Parallel()
		client := NewClient()
		publicKey, err := client.GetPublicKey(validAnyLLMKey)

		require.NoError(t, err)
		assert.NotEmpty(t, publicKey)
	})

	t.Run("returns error for invalid key", func(t *testing.T) {
		t.Parallel()
		client := NewClient()
		_, err := client.GetPublicKey("invalid-key")

		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKey))
	})
}

// validAnyLLMKey is defined in crypto_test.go
