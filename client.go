package anyllmplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultPlatformURL is the default URL for the ANY LLM platform API.
	DefaultPlatformURL = "http://localhost:8000/api/v1"
	// TokenValidityDuration is the validity duration for access tokens (23 hours for safety margin).
	TokenValidityDuration = 23 * time.Hour
)

// Timestamp formats the server may return.
var timestampFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999",
	"2006-01-02T15:04:05",
}

// parseTimestamp parses a timestamp string trying multiple formats.
func parseTimestamp(s string) (time.Time, error) {
	for _, format := range timestampFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse timestamp %q", s)
}

// DecryptedProviderKey contains the decrypted provider key and metadata.
type DecryptedProviderKey struct {
	// APIKey is the decrypted API key for the provider.
	APIKey string
	// ProviderKeyID is the unique identifier for the provider key.
	ProviderKeyID uuid.UUID
	// ProjectID is the unique identifier for the project.
	ProjectID uuid.UUID
	// Provider is the provider name (e.g., "openai", "anthropic").
	Provider string
	// CreatedAt is when the provider key was created.
	CreatedAt time.Time
	// UpdatedAt is when the provider key was last updated (may be zero).
	UpdatedAt time.Time
}

// Client is the HTTP client for communicating with the ANY LLM backend.
type Client struct {
	// PlatformURL is the base URL for the ANY LLM platform API.
	PlatformURL string
	// HTTPClient is the HTTP client to use for requests.
	HTTPClient *http.Client

	// accessToken is the current access token.
	accessToken string
	// tokenExpiresAt is when the current token expires.
	tokenExpiresAt time.Time
}

// Option is a functional option for configuring the Client.
type Option func(*Client)

// WithPlatformURL sets a custom platform URL.
func WithPlatformURL(url string) Option {
	return func(c *Client) {
		c.PlatformURL = url
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.HTTPClient = client
	}
}

// NewClient creates a new Client with the given options.
func NewClient(opts ...Option) *Client {
	c := &Client{
		PlatformURL: DefaultPlatformURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// challengeResponse represents the response from the challenge creation endpoint.
type challengeResponse struct {
	EncryptedChallenge string `json:"encrypted_challenge"`
}

// tokenResponse represents the response from the token request endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// providerKeyResponse represents the response from the provider key endpoint.
type providerKeyResponse struct {
	ID           string  `json:"id"`
	ProjectID    string  `json:"project_id"`
	Provider     string  `json:"provider"`
	EncryptedKey string  `json:"encrypted_key"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    *string `json:"updated_at,omitempty"`
}

// CreateChallenge creates an authentication challenge using the provided public key.
func (c *Client) CreateChallenge(ctx context.Context, publicKey string) (*challengeResponse, error) {
	url := fmt.Sprintf("%s/auth/", c.PlatformURL)

	body := map[string]string{"encryption_key": publicKey}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, &ChallengeCreationError{Message: "failed to marshal request: " + err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, &ChallengeCreationError{Message: "failed to create request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, &ChallengeCreationError{Message: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleChallengeError(resp)
	}

	var result challengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, &ChallengeCreationError{Message: "failed to decode response: " + err.Error()}
	}

	return &result, nil
}

// handleChallengeError processes error responses from challenge creation.
func (c *Client) handleChallengeError(resp *http.Response) error {
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	if strings.Contains(bodyStr, "No project found") {
		return &ChallengeCreationError{
			StatusCode: resp.StatusCode,
			Message:    "No project found for the provided public key",
		}
	}

	return &ChallengeCreationError{
		StatusCode: resp.StatusCode,
		Message:    "challenge creation failed",
	}
}

// SolveChallenge decrypts and solves the authentication challenge.
func (c *Client) SolveChallenge(encryptedChallenge string, privateKey []byte) (uuid.UUID, error) {
	decryptedUUIDStr, err := DecryptData(encryptedChallenge, privateKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to decrypt challenge: %w", err)
	}

	solvedChallenge, err := uuid.Parse(decryptedUUIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse challenge UUID: %w", err)
	}

	return solvedChallenge, nil
}

// RequestAccessToken requests an access token by submitting the solved challenge.
func (c *Client) RequestAccessToken(ctx context.Context, solvedChallenge uuid.UUID) (string, error) {
	url := fmt.Sprintf("%s/auth/token", c.PlatformURL)

	body := map[string]string{"solved_challenge": solvedChallenge.String()}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", &ChallengeCreationError{Message: "failed to marshal request: " + err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return "", &ChallengeCreationError{Message: "failed to create request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", &ChallengeCreationError{Message: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", &ChallengeCreationError{
			StatusCode: resp.StatusCode,
			Message:    "failed to request access token",
		}
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", &ChallengeCreationError{Message: "failed to decode response: " + err.Error()}
	}

	// Store token and expiration
	c.accessToken = result.AccessToken
	c.tokenExpiresAt = time.Now().Add(TokenValidityDuration)

	return result.AccessToken, nil
}

// RefreshAccessToken refreshes the access token using the ANY_LLM_KEY.
func (c *Client) RefreshAccessToken(ctx context.Context, anyLLMKey string) (string, error) {
	// Parse the ANY_LLM_KEY
	keyComponents, err := ParseAnyLLMKey(anyLLMKey)
	if err != nil {
		return "", err
	}

	// Load the private key
	privateKey, err := LoadPrivateKey(keyComponents.Base64EncodedPrivateKey)
	if err != nil {
		return "", err
	}

	// Extract the public key
	publicKey, err := ExtractPublicKey(privateKey)
	if err != nil {
		return "", err
	}

	// Create and solve the challenge
	challengeData, err := c.CreateChallenge(ctx, publicKey)
	if err != nil {
		return "", err
	}

	solvedChallenge, err := c.SolveChallenge(challengeData.EncryptedChallenge, privateKey)
	if err != nil {
		return "", err
	}

	// Request access token
	return c.RequestAccessToken(ctx, solvedChallenge)
}

// ensureValidToken ensures a valid access token exists, refreshing if necessary.
func (c *Client) ensureValidToken(ctx context.Context, anyLLMKey string) (string, error) {
	now := time.Now()

	// Request new token if missing or expired
	if c.accessToken == "" || now.After(c.tokenExpiresAt) {
		_, err := c.RefreshAccessToken(ctx, anyLLMKey)
		if err != nil {
			return "", err
		}
	}

	return c.accessToken, nil
}

// GetAccessToken returns a valid access token, refreshing if necessary.
// This is useful for making authenticated requests to the platform API.
func (c *Client) GetAccessToken(ctx context.Context, anyLLMKey string) (string, error) {
	return c.ensureValidToken(ctx, anyLLMKey)
}

// FetchProviderKey fetches the encrypted provider API key from the server.
func (c *Client) FetchProviderKey(ctx context.Context, provider, accessToken string) (*providerKeyResponse, error) {
	url := fmt.Sprintf("%s/provider-keys/%s", c.PlatformURL, provider)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &ProviderKeyFetchError{
			Provider: provider,
			Message:  "failed to create request: " + err.Error(),
		}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, &ProviderKeyFetchError{
			Provider: provider,
			Message:  "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &ProviderKeyFetchError{
			StatusCode: resp.StatusCode,
			Provider:   provider,
			Message:    "failed to fetch provider key",
		}
	}

	var result providerKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, &ProviderKeyFetchError{
			Provider: provider,
			Message:  "failed to decode response: " + err.Error(),
		}
	}

	return &result, nil
}

// DecryptProviderKeyValue decrypts the provider API key.
func (c *Client) DecryptProviderKeyValue(encryptedKey string, privateKey []byte) (string, error) {
	return DecryptData(encryptedKey, privateKey)
}

// GetPublicKey extracts the public key from an ANY_LLM_KEY.
func (c *Client) GetPublicKey(anyLLMKey string) (string, error) {
	keyComponents, err := ParseAnyLLMKey(anyLLMKey)
	if err != nil {
		return "", err
	}

	privateKey, err := LoadPrivateKey(keyComponents.Base64EncodedPrivateKey)
	if err != nil {
		return "", err
	}

	return ExtractPublicKey(privateKey)
}

// GetSolvedChallenge gets a solved authentication challenge from an ANY_LLM_KEY.
func (c *Client) GetSolvedChallenge(ctx context.Context, anyLLMKey string) (uuid.UUID, error) {
	keyComponents, err := ParseAnyLLMKey(anyLLMKey)
	if err != nil {
		return uuid.Nil, err
	}

	privateKey, err := LoadPrivateKey(keyComponents.Base64EncodedPrivateKey)
	if err != nil {
		return uuid.Nil, err
	}

	publicKey, err := ExtractPublicKey(privateKey)
	if err != nil {
		return uuid.Nil, err
	}

	challengeData, err := c.CreateChallenge(ctx, publicKey)
	if err != nil {
		return uuid.Nil, err
	}

	return c.SolveChallenge(challengeData.EncryptedChallenge, privateKey)
}

// GetDecryptedProviderKey gets a decrypted provider API key using the complete authentication flow.
func (c *Client) GetDecryptedProviderKey(ctx context.Context, anyLLMKey, provider string) (*DecryptedProviderKey, error) {
	// Ensure we have a valid access token
	accessToken, err := c.ensureValidToken(ctx, anyLLMKey)
	if err != nil {
		return nil, err
	}

	// Load private key for decryption
	keyComponents, err := ParseAnyLLMKey(anyLLMKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := LoadPrivateKey(keyComponents.Base64EncodedPrivateKey)
	if err != nil {
		return nil, err
	}

	// Fetch the encrypted provider key
	providerKeyData, err := c.FetchProviderKey(ctx, provider, accessToken)
	if err != nil {
		return nil, err
	}

	// Decrypt the provider key
	decryptedKey, err := c.DecryptProviderKeyValue(providerKeyData.EncryptedKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Parse UUIDs
	providerKeyID, err := uuid.Parse(providerKeyData.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provider key ID: %w", err)
	}

	projectID, err := uuid.Parse(providerKeyData.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse project ID: %w", err)
	}

	// Parse timestamps (server may return with or without timezone)
	createdAt, err := parseTimestamp(providerKeyData.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	var updatedAt time.Time
	if providerKeyData.UpdatedAt != nil && *providerKeyData.UpdatedAt != "" {
		updatedAt, err = parseTimestamp(*providerKeyData.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse updated_at: %w", err)
		}
	}

	return &DecryptedProviderKey{
		APIKey:        decryptedKey,
		ProviderKeyID: providerKeyID,
		ProjectID:     projectID,
		Provider:      providerKeyData.Provider,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}, nil
}
