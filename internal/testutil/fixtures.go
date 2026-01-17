// Package testutil provides test utilities and fixtures for the any-llm-platform-client-go package.
package testutil

// Test key constants for testing purposes.
// The base64 part decodes to "abcdefghijklmnopqrstuvwxyz123456" (32 bytes).
const (
	// ValidAnyLLMKey is a valid test key in the expected format.
	ValidAnyLLMKey = "ANY.v1.12345678.abcdef01-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

	// ValidBase64PrivateKey is a valid 32-byte private key encoded as base64.
	// Decodes to "abcdefghijklmnopqrstuvwxyz123456".
	ValidBase64PrivateKey = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

	// InvalidBase64 is an invalid base64 string for testing error cases.
	InvalidBase64 = "not-valid-base64!!!"

	// ShortBase64 is valid base64 but decodes to only 3 bytes (too short for a key).
	// Decodes to "abc".
	ShortBase64 = "YWJj"

	// TestKeyID is a test key ID.
	TestKeyID = "12345678"

	// TestPublicKeyFingerprint is a test public key fingerprint.
	TestPublicKeyFingerprint = "abcdef01"
)

// InvalidKeyFormats provides various invalid key formats for testing.
var InvalidKeyFormats = []string{
	"invalid-key-format",
	"ANY.v2.12345678.abcdef01-YWJj",    // wrong version
	"ANY.v1.12345678",                  // missing components
	"",                                 // empty
	"ANY.v1.",                          // incomplete
	"PREFIX.v1.12345678.abcdef01-YWJj", // wrong prefix
}

// MockChallengeResponse returns a mock challenge response body.
func MockChallengeResponse(encryptedChallenge string) map[string]string {
	return map[string]string{
		"encrypted_challenge": encryptedChallenge,
	}
}

// MockTokenResponse returns a mock token response body.
func MockTokenResponse(accessToken string) map[string]string {
	return map[string]string{
		"access_token": accessToken,
		"token_type":   "Bearer",
	}
}

// MockProviderKeyResponse returns a mock provider key response body.
func MockProviderKeyResponse(id, projectID, provider, encryptedKey string) map[string]any {
	return map[string]any{
		"id":            id,
		"project_id":    projectID,
		"provider":      provider,
		"encrypted_key": encryptedKey,
		"created_at":    "2025-01-15T12:00:00Z",
	}
}
