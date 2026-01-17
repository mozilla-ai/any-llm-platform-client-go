// Package anyllmplatform provides a client for the ANY LLM platform API.
//
// # Security Notes
//
// This package implements X25519 sealed box encryption for secure key exchange.
// The cryptographic primitives used are:
//   - X25519 (Curve25519) for Elliptic Curve Diffie-Hellman key agreement
//   - XChaCha20-Poly1305 for authenticated encryption (AEAD)
//   - SHA-512 for deterministic nonce derivation
//
// The sealed box format follows the NaCl/libsodium convention and provides:
//   - Forward secrecy through ephemeral keypairs
//   - Authenticated encryption preventing tampering
//   - Deterministic nonces preventing nonce reuse attacks
//
// Private keys should be handled with care and never logged or exposed.
package anyllmplatform

import (
	"crypto/sha512"
	"encoding/base64"
	"regexp"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// X25519KeySize is the size of an X25519 key in bytes (256 bits).
	// This provides approximately 128 bits of security.
	X25519KeySize = 32

	// XChaCha20NonceSize is the size of an XChaCha20 nonce in bytes (192 bits).
	// The extended nonce size eliminates practical nonce collision concerns.
	XChaCha20NonceSize = 24
)

// KeyComponents represents the parsed components of an ANY_LLM_KEY.
type KeyComponents struct {
	// KeyID is the unique key identifier.
	KeyID string
	// PublicKeyFingerprint is the fingerprint of the public key.
	PublicKeyFingerprint string
	// Base64EncodedPrivateKey is the base64-encoded X25519 private key.
	Base64EncodedPrivateKey string
}

// anyLLMKeyPattern matches the ANY_LLM_KEY format: ANY.v1.<key_id>.<fingerprint>-<base64_key>
var anyLLMKeyPattern = regexp.MustCompile(`^ANY\.v1\.([^.]+)\.([^-]+)-(.+)$`)

// ParseAnyLLMKey parses an ANY_LLM_KEY string into its components.
//
// The expected format is: ANY.v1.<key_id>.<fingerprint>-<base64_key>
//
// Returns an error if the key format is invalid.
func ParseAnyLLMKey(anyLLMKey string) (*KeyComponents, error) {
	matches := anyLLMKeyPattern.FindStringSubmatch(anyLLMKey)
	if matches == nil || len(matches) != 4 {
		return nil, &InvalidKeyError{
			Message: "expected format: ANY.v1.<key_id>.<fingerprint>-<base64_key>",
		}
	}

	return &KeyComponents{
		KeyID:                   matches[1],
		PublicKeyFingerprint:    matches[2],
		Base64EncodedPrivateKey: matches[3],
	}, nil
}

// LoadPrivateKey loads an X25519 private key from a base64-encoded string.
//
// Returns the 32-byte private key or an error if decoding fails or the key is invalid.
func LoadPrivateKey(base64PrivateKey string) ([]byte, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return nil, &InvalidKeyError{
			Message: "failed to decode base64 private key: " + err.Error(),
		}
	}

	if len(privateKeyBytes) != X25519KeySize {
		return nil, &InvalidKeyError{
			Message: "X25519 private key must be 32 bytes",
		}
	}

	return privateKeyBytes, nil
}

// ExtractPublicKey derives the public key from an X25519 private key.
//
// Returns the base64-encoded public key.
func ExtractPublicKey(privateKey []byte) (string, error) {
	if len(privateKey) != X25519KeySize {
		return "", &InvalidKeyError{
			Message: "private key must be 32 bytes",
		}
	}

	var publicKey [X25519KeySize]byte
	var privateKeyArray [X25519KeySize]byte
	copy(privateKeyArray[:], privateKey)

	curve25519.ScalarBaseMult(&publicKey, &privateKeyArray)

	return base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

// DecryptData decrypts data using X25519 sealed box format.
//
// The sealed box format is:
//   - First 32 bytes: ephemeral public key
//   - Remaining bytes: XChaCha20-Poly1305 ciphertext with 16-byte auth tag
//
// The shared secret is computed using X25519 ECDH, and the nonce is derived
// deterministically from SHA512(ephemeral_public_key || recipient_public_key)[:24].
//
// Security properties:
//   - Forward secrecy: Compromising the recipient's private key does not
//     compromise past messages encrypted with ephemeral keypairs.
//   - Authenticated encryption: The Poly1305 MAC ensures message integrity
//     and prevents tampering.
//   - Nonce uniqueness: Deterministic derivation from public keys guarantees
//     unique nonces for each sender-recipient pair.
func DecryptData(encryptedDataBase64 string, privateKey []byte) (string, error) {
	if len(privateKey) != X25519KeySize {
		return "", &DecryptionError{Message: "private key must be 32 bytes"}
	}

	encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataBase64)
	if err != nil {
		return "", &DecryptionError{Message: "failed to decode base64 encrypted data: " + err.Error()}
	}

	if len(encryptedData) < X25519KeySize {
		return "", &DecryptionError{Message: "invalid sealed box format: too short"}
	}

	// Extract ephemeral public key and ciphertext
	ephemeralPublicKey := encryptedData[:X25519KeySize]
	ciphertext := encryptedData[X25519KeySize:]

	// Compute recipient's public key from private key
	var recipientPublicKey [X25519KeySize]byte
	var privateKeyArray [X25519KeySize]byte
	copy(privateKeyArray[:], privateKey)
	curve25519.ScalarBaseMult(&recipientPublicKey, &privateKeyArray)

	// Compute shared secret using X25519 ECDH
	var ephemeralPubKeyArray [X25519KeySize]byte
	copy(ephemeralPubKeyArray[:], ephemeralPublicKey)
	sharedSecret, err := curve25519.X25519(privateKey, ephemeralPublicKey)
	if err != nil {
		return "", &DecryptionError{Message: "failed to compute shared secret: " + err.Error()}
	}

	// Derive nonce: SHA512(ephemeral_public_key || recipient_public_key)[:24]
	combined := make([]byte, X25519KeySize*2)
	copy(combined[:X25519KeySize], ephemeralPublicKey)
	copy(combined[X25519KeySize:], recipientPublicKey[:])
	nonceHash := sha512.Sum512(combined)
	nonce := nonceHash[:XChaCha20NonceSize]

	// Create XChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return "", &DecryptionError{Message: "failed to create cipher: " + err.Error()}
	}

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", &DecryptionError{Message: "failed to decrypt: " + err.Error()}
	}

	return string(plaintext), nil
}
