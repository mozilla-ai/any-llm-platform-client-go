package anyllmplatform

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validAnyLLMKey is a test key for testing purposes.
// The base64 part decodes to "abcdefghijklmnopqrstuvwxyz123456" (32 bytes).
const validAnyLLMKey = "ANY.v1.12345678.abcdef01-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

func TestParseAnyLLMKey(t *testing.T) {
	t.Parallel()

	t.Run("parses valid key", func(t *testing.T) {
		t.Parallel()
		components, err := ParseAnyLLMKey(validAnyLLMKey)
		require.NoError(t, err)
		assert.Equal(t, "12345678", components.KeyID)
		assert.Equal(t, "abcdef01", components.PublicKeyFingerprint)
		assert.Equal(t, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", components.Base64EncodedPrivateKey)
	})

	t.Run("returns error for invalid format", func(t *testing.T) {
		t.Parallel()
		_, err := ParseAnyLLMKey("invalid-key-format")
		require.Error(t, err)

		var invalidKeyErr *InvalidKeyError
		assert.True(t, errors.As(err, &invalidKeyErr))
		assert.True(t, errors.Is(err, ErrInvalidKey))
	})

	t.Run("returns error for wrong version", func(t *testing.T) {
		t.Parallel()
		_, err := ParseAnyLLMKey("ANY.v2.12345678.abcdef01-YWJj")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKey))
	})

	t.Run("returns error for missing components", func(t *testing.T) {
		t.Parallel()
		_, err := ParseAnyLLMKey("ANY.v1.12345678")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKey))
	})
}

func TestLoadPrivateKey(t *testing.T) {
	t.Parallel()

	t.Run("loads valid 32-byte key", func(t *testing.T) {
		t.Parallel()
		// "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=" decodes to 32 bytes
		base64Key := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
		privateKey, err := LoadPrivateKey(base64Key)
		require.NoError(t, err)
		assert.Len(t, privateKey, X25519KeySize)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		t.Parallel()
		_, err := LoadPrivateKey("not-valid-base64!!!")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKey))
	})

	t.Run("returns error for wrong key size", func(t *testing.T) {
		t.Parallel()
		// "YWJj" decodes to "abc" (3 bytes)
		_, err := LoadPrivateKey("YWJj")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKey))
		assert.Contains(t, err.Error(), "32 bytes")
	})
}

func TestExtractPublicKey(t *testing.T) {
	t.Parallel()

	t.Run("extracts public key from private key", func(t *testing.T) {
		t.Parallel()
		base64Key := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
		privateKey, err := LoadPrivateKey(base64Key)
		require.NoError(t, err)

		publicKey, err := ExtractPublicKey(privateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, publicKey)
		// Public key should be base64 encoded, so roughly same length
		assert.Greater(t, len(publicKey), 0)
	})

	t.Run("returns error for invalid private key size", func(t *testing.T) {
		t.Parallel()
		_, err := ExtractPublicKey([]byte("short"))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKey))
	})
}

func TestDecryptData(t *testing.T) {
	t.Parallel()

	t.Run("returns error for too short data", func(t *testing.T) {
		t.Parallel()
		base64Key := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
		privateKey, err := LoadPrivateKey(base64Key)
		require.NoError(t, err)

		// "YWJj" is only 3 bytes, less than the required 32 bytes for ephemeral public key
		_, err = DecryptData("YWJj", privateKey)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDecryption))
		assert.Contains(t, err.Error(), "too short")
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		t.Parallel()
		base64Key := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
		privateKey, err := LoadPrivateKey(base64Key)
		require.NoError(t, err)

		_, err = DecryptData("not-valid-base64!!!", privateKey)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDecryption))
	})

	t.Run("returns error for invalid private key size", func(t *testing.T) {
		t.Parallel()
		_, err := DecryptData("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA==", []byte("short"))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDecryption))
	})
}
