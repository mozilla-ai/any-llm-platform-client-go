package anyllmplatform

import (
	"errors"
	"fmt"
)

// Sentinel errors for common error conditions.
var (
	// ErrChallengeCreation indicates authentication challenge creation failed.
	ErrChallengeCreation = errors.New("challenge creation failed")

	// ErrProviderKeyFetch indicates fetching a provider API key failed.
	ErrProviderKeyFetch = errors.New("provider key fetch failed")

	// ErrInvalidKey indicates the ANY_LLM_KEY format is invalid.
	ErrInvalidKey = errors.New("invalid ANY_LLM_KEY format")

	// ErrDecryption indicates a decryption operation failed.
	ErrDecryption = errors.New("decryption failed")

	// ErrAuthentication indicates an authentication failure.
	ErrAuthentication = errors.New("authentication failed")
)

// ChallengeCreationError represents an error during authentication challenge creation.
type ChallengeCreationError struct {
	StatusCode int
	Message    string
}

func (e *ChallengeCreationError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("challenge creation failed (status: %d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("challenge creation failed: %s", e.Message)
}

func (e *ChallengeCreationError) Unwrap() error {
	return ErrChallengeCreation
}

// Is implements errors.Is for ChallengeCreationError.
func (e *ChallengeCreationError) Is(target error) bool {
	return target == ErrChallengeCreation
}

// ProviderKeyFetchError represents an error when fetching a provider API key.
type ProviderKeyFetchError struct {
	StatusCode int
	Provider   string
	Message    string
}

func (e *ProviderKeyFetchError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("failed to fetch provider key for %s (status: %d): %s", e.Provider, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("failed to fetch provider key for %s: %s", e.Provider, e.Message)
}

func (e *ProviderKeyFetchError) Unwrap() error {
	return ErrProviderKeyFetch
}

// Is implements errors.Is for ProviderKeyFetchError.
func (e *ProviderKeyFetchError) Is(target error) bool {
	return target == ErrProviderKeyFetch
}

// InvalidKeyError represents an error when parsing an ANY_LLM_KEY.
type InvalidKeyError struct {
	Message string
}

func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid ANY_LLM_KEY: %s", e.Message)
}

func (e *InvalidKeyError) Unwrap() error {
	return ErrInvalidKey
}

// Is implements errors.Is for InvalidKeyError.
func (e *InvalidKeyError) Is(target error) bool {
	return target == ErrInvalidKey
}

// DecryptionError represents a decryption failure.
type DecryptionError struct {
	Message string
}

func (e *DecryptionError) Error() string {
	return fmt.Sprintf("decryption failed: %s", e.Message)
}

func (e *DecryptionError) Unwrap() error {
	return ErrDecryption
}

// Is implements errors.Is for DecryptionError.
func (e *DecryptionError) Is(target error) bool {
	return target == ErrDecryption
}
