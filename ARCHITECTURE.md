# Cryptographic Architecture

This document describes the cryptographic design, security properties, and implementation details of the provider key decryption system.

## Table of Contents

- [Overview](#overview)
- [Cryptographic Architecture](#cryptographic-architecture)
- [Threat Model](#threat-model)
- [Security Properties](#security-properties)
- [Nonce Management](#nonce-management)
- [Known Limitations](#known-limitations)
- [Security Considerations](#security-considerations)
- [Algorithm Choices](#algorithm-choices)

---

## Overview

This system provides secure, anonymous encryption for API provider keys using a **hybrid cryptosystem** based on the ECIES (Elliptic Curve Integrated Encryption Scheme) pattern, commonly known as "sealed boxes" in libsodium.

### System Components

The system consists of three components that work together:

1. **Frontend (TypeScript/Browser)** - Generates X25519 keypairs client-side, encrypts provider API keys before storing
2. **Backend (Python/FastAPI)** - Creates authentication challenges, stores encrypted provider keys
3. **CLI Client (Python)** - This decrypter tool, decrypts challenges and provider keys

### Core Design Principles

1. **User keys never leave the client machine** - X25519 keypairs generated in browser, private keys NEVER sent to server
2. **Forward secrecy** - Ephemeral keys ensure past messages can't be decrypted if long-term keys are compromised
3. **Anonymous encryption** - Recipients can decrypt without knowing sender's identity
4. **Challenge-response authentication** - Proves possession of private key without transmitting it

---

## Cryptographic Architecture

### High-Level Flow

**Phase 1: Key Generation & Storage (Frontend → Backend)**

```
┌─────────────┐                               ┌─────────────┐
│  Frontend   │                               │   Backend   │
│ (Browser)   │                               │  (FastAPI)  │
└──────┬──────┘                               └──────┬──────┘
       │                                             │
       │  1. Generate X25519 keypair client-side     │
       │     priv_key, pub_key = generate()          │
       │                                             │
       │  2. Format as ANY_LLM_KEY, download to user │
       │     ANY.v1.<kid>.<fp>-<priv_key>            │
       │                                             │
       │  3. Send pub_key to create project          │
       ├────────────────────────────────────────────>│
       │                                             │
       │  4. Store pub_key in Project.encryption_key │
       │<────────────────────────────────────────────┤
       │     ✅ Project created                      │
       │                                             │
       │  5. User enters provider API key in UI      │
       │                                             │
       │  6. Encrypt with sealed box (pub_key)       │
       │     encrypted = sealedbox(api_key, pub_key) │
       │                                             │
       │  7. Send encrypted provider key             │
       ├────────────────────────────────────────────>│
       │                                             │
       │  8. Store encrypted in database             │
       │<────────────────────────────────────────────┤
       │     ✅ Provider key stored (encrypted)      │
```

**Phase 2: Retrieval via CLI (CLI Client → Backend)**

```
┌─────────────┐                               ┌─────────────┐
│ CLI Client  │                               │   Backend   │
│  (Python)   │                               │  (FastAPI)  │
└──────┬──────┘                               └──────┬──────┘
       │                                             │
       │  1. Parse ANY_LLM_KEY → extract priv_key    │
       │     Derive pub_key from priv_key            │
       │                                             │
       │  2. Send pub_key to request challenge       │
       ├────────────────────────────────────────────>│
       │                                             │
       │  3. Generate UUID, encrypt with pub_key     │
       │<────────────────────────────────────────────┤
       │     (sealed box: eph_pub || ciphertext)     │
       │                                             │
       │  4. Decrypt challenge with priv_key         │
       │     → Get challenge UUID                    │
       │                                             │
       │  5. Request provider_key with solved UUID   │
       ├────────────────────────────────────────────>│
       │     Headers: pub_key, X-Solved-Challenge    │
       │                                             │
       │  6. Verify challenge, return encrypted key  │
       │<────────────────────────────────────────────┤
       │     (sealed box: eph_pub || ciphertext)     │
       │                                             │
       │  7. Decrypt provider_key with priv_key      │
       │     → Get plaintext API key                 │
       │                                             │
```

### Sealed Box Construction (ECIES)

Each encrypted message uses this construction:

```
┌─────────────────────────────────────────────────────────────┐
│                    Sealed Box Format                        │
├──────────────────┬──────────────────────────────────────────┤
│ Ephemeral Public │         Ciphertext + Auth Tag            │
│   Key (32 bytes) │         (variable length)                │
└──────────────────┴──────────────────────────────────────────┘
```

**Encryption (Server → Client):**

```python
# NOTE: This is pseudocode showing the cryptographic operations.
# Actual implementations use library-specific APIs (e.g., PyNaCl, libsodium).

# 1. Generate ephemeral X25519 keypair
eph_priv = random(32 bytes)  # Cryptographically secure RNG
eph_pub = scalar_multiply_base(eph_priv)  # Derive public from private

# 2. Perform ECDH key agreement
shared_secret = scalar_multiply(eph_priv, recipient_pub)  # X25519 ECDH

# 3. Derive nonce deterministically
nonce = SHA512(eph_pub || recipient_pub)[:24]

# 4. Encrypt with AEAD
ciphertext = XChaCha20_Poly1305_Encrypt(
    plaintext=message,
    key=shared_secret,
    nonce=nonce,
    associated_data=None
)

# 5. Output sealed box
sealed_box = eph_pub || ciphertext

# 6. CRITICAL: Destroy eph_priv (forward secrecy!)
secure_zero(eph_priv)
```

**Decryption (Client):**

```python
# 1. Parse sealed box
eph_pub = sealed_box[:32]
ciphertext = sealed_box[32:]

# 2. Perform ECDH with recipient's private key
shared_secret = scalar_multiply(recipient_priv, eph_pub)  # X25519 ECDH

# 3. Derive same nonce
recipient_pub = scalar_multiply_base(recipient_priv)  # Derive public from private
nonce = SHA512(eph_pub || recipient_pub)[:24]

# 4. Decrypt and authenticate
plaintext = XChaCha20_Poly1305_Decrypt(
    ciphertext=ciphertext,
    key=shared_secret,
    nonce=nonce,
    associated_data=None
)
# Raises exception if authentication fails
```

**Mapping to Actual Implementations:**

| Pseudocode                   | libsodium                  | PyNaCl                              | Description                    |
|------------------------------|----------------------------|-------------------------------------|--------------------------------|
| `scalar_multiply_base(priv)` | `crypto_scalarmult_base()` | `PrivateKey.public_key`             | Derive public key from private |
| `scalar_multiply(priv, pub)` | `crypto_scalarmult()`      | `nacl.bindings.crypto_scalarmult()` | X25519 ECDH                    |
| `random(32)`                 | `randombytes(32)`          | `nacl.utils.random()`               | CSPRNG                         |

---

## Threat Model

### What We Protect Against

| Threat                             | Protection  | Mechanism                                           |
|------------------------------------|-------------|-----------------------------------------------------|
| **Network eavesdropping**          | ✅ Protected | End-to-end encryption with X25519 + XChaCha20       |
| **Man-in-the-middle (passive)**    | ✅ Protected | Encryption prevents plaintext disclosure            |
| **Replay attacks**                 | ✅ Protected | Challenge-response with UUID, time-limited validity |
| **Ciphertext tampering**           | ✅ Protected | Poly1305 MAC authentication (AEAD)                  |
| **Key compromise (past messages)** | ✅ Protected | Forward secrecy via ephemeral keys                  |
| **Unauthorized decryption**        | ✅ Protected | Only holder of private key can decrypt              |
| **Nonce reuse attacks**            | ✅ Protected | Deterministic nonce from unique ephemeral keys      |

### What We DON'T Protect Against

| Threat                          | Status               | Mitigation                                                                              |
|---------------------------------|----------------------|-----------------------------------------------------------------------------------------|
| **Active MITM (TLS stripping)** | ⚠️ Vulnerable (HTTP) | **TODO: Enforce HTTPS**                                                                 |
| **Compromised client machine**  | ❌ Not protected      | Private key would be stolen                                                             |
| **Compromised server**          | ⚠️ Partial           | Server can't decrypt past messages (forward secrecy), but can impersonate going forward |
| **Timing side-channels**        | ✅ Mitigated          | libsodium uses constant-time operations                                                 |
| **Quantum computer attacks**    | ❌ Not protected      | X25519 broken by Shor's algorithm (future threat)                                       |

---

## Security Properties

### 1. Confidentiality (CPA Security)

**Property:** An attacker who observes ciphertexts cannot learn anything about plaintexts.

**Provided by:**
- X25519 ECDH (~128-bit security)
- XChaCha20 stream cipher (256-bit key)

**Security level:** ~128 bits (limited by X25519, not XChaCha20)

### 2. Authenticity (Forgery Resistance)

**Property:** An attacker cannot create valid ciphertexts without the encryption key.

**Provided by:**
- Poly1305 MAC (128-bit security)
- AEAD construction (encrypt-then-MAC)

**Note:** Sealed boxes provide ciphertext integrity but NOT sender authentication (anonymous encryption).

### 3. Forward Secrecy

**Property:** Compromise of long-term keys doesn't compromise past session keys.

**Provided by:**
- Ephemeral X25519 keypairs (generated fresh per message)
- Ephemeral private keys destroyed after encryption

**Implication:** Even if recipient's private key is stolen, past messages remain secure.

### 4. CCA2 Security (Chosen-Ciphertext Attack Resistance)

**Property:** Attacker with decryption oracle for other ciphertexts cannot decrypt target ciphertext.

**Provided by:**
- AEAD construction
- Authentication prevents tampering

---

## Nonce Management

### Critical Security Property

**Nonce reuse is CATASTROPHIC** for XChaCha20-Poly1305:

| Attack Vector       | Consequence of Nonce Reuse                                                        |
|---------------------|-----------------------------------------------------------------------------------|
| **Confidentiality** | Plaintext recovery via XOR: `ciphertext₁ ⊕ ciphertext₂ = plaintext₁ ⊕ plaintext₂` |
| **Authenticity**    | Poly1305 key recovery → universal forgery attacks                                 |

### How We Guarantee Nonce Uniqueness

Our sealed box construction makes nonce reuse **mathematically impossible**:

```
nonce = SHA512(eph_pub || recipient_pub)[:24]

Where:
- eph_pub is generated fresh for EACH message (2^256 keyspace)
- SHA512 is collision-resistant
- 24-byte (192-bit) nonces provide collision resistance up to 2^96 messages

Result: Nonce uniqueness guaranteed without state management or counters
```

**Why this works:**

1. Each encryption generates a new random ephemeral X25519 private key (32 bytes)
2. Probability of ephemeral key collision: 2^-256 (astronomically small)
3. Nonce is deterministically derived from ephemeral public key
4. Therefore, nonce collision probability: 2^-256
5. XChaCha20's 192-bit nonces further reduce collision risk to 2^-96

**No state required:**
- No counters to synchronize
- No random number generator state to preserve
- Works across restarts, crashes, multiple clients

### Comparison to Manual Nonce Management

| Approach              | Nonce Uniqueness             | Failure Mode                           |
|-----------------------|------------------------------|----------------------------------------|
| **Counter**           | Must maintain state          | Counter reset → nonce reuse            |
| **Random (96-bit)**   | ~2^48 messages safe          | Birthday paradox → collision           |
| **Random (192-bit)**  | ~2^96 messages safe          | Still requires good RNG                |
| **Sealed box (ours)** | Cryptographically guaranteed | Requires 2^256 collisions (impossible) |

---

## Known Limitations

### 1. HTTP Communication (HIGH PRIORITY)

**Issue:** API communication uses HTTP, not HTTPS.

**Risk:**
- Man-in-the-middle can intercept traffic
- Public keys could be substituted (downgrade attack)
- Challenges could be replayed

**Mitigation:** TODO: Enforce HTTPS in production

**Current Scope:** Localhost development only

### 2. Private Key Handling

**Issue:** Private keys handled in memory without explicit zeroing.

**Risk:**
- Keys may persist in memory after use
- Memory dumps could expose keys

**Mitigation:**
- Python's garbage collector eventually clears memory
- Use secure systems (encrypted disk, no swap)

**Improvement:** Use memory-mapped secure buffers (challenging in Python)

### 3. Terminal Input Visibility

**Issue:** Private key input via `input()` is visible on screen.

**Risk:**
- Shoulder surfing
- Terminal history logging

**Mitigation:** TODO: Use `getpass` module for hidden input

### 4. Error Message Information Disclosure

**Issue:** Detailed error messages may leak information.

**Risk:**
- Timing attacks
- Oracle attacks via error messages

**Mitigation:** Use generic error messages in production

### 5. No Post-Quantum Security

**Issue:** X25519 is vulnerable to quantum computers (Shor's algorithm).

**Risk:** Future quantum computers could break ECDH.

**Mitigation:**
- Monitor NIST post-quantum standardization
- Consider ML-KEM (Kyber) in future

**Timeline:** Not an immediate threat (10+ years)

---

## Security Considerations

### Key Generation

**Client-side (Frontend generates user keypairs):**

User X25519 keypairs are generated **entirely client-side** in the browser using the `@noble/curves` library:

```typescript
// Frontend: frontend/src/utils/any-llm-key.ts
const privateKey = randomBytes(32)  // Cryptographically secure RNG
const publicKey = x25519.getPublicKey(privateKey)

// Private key stays in browser, formatted as ANY_LLM_KEY for user download
// Only public key is sent to server for storage
```

**Server-side (generates ephemeral keypairs per encryption):**

The backend generates fresh ephemeral keypairs for each encryption operation:

```python
# Backend: backend/app/utils.py
ephemeral_public_key, ephemeral_private_key = nacl.bindings.crypto_box_keypair()
# Ephemeral keys used once, then destroyed (forward secrecy)
```

**Requirements:**
- MUST use cryptographically secure RNG (browser: `crypto.getRandomValues()`, Python: `/dev/urandom`)
- MUST NOT use predictable seeds
- User private keys MUST NEVER be transmitted to server
- Ephemeral private keys MUST be destroyed after encryption

### Key Storage

**Client-side:**
- Private keys stored in `ANY_LLM_KEY` format: `ANY.v1.<key_id>.<fingerprint>-<base64_private_key>`
  - `key_id`: Random 8-character hex identifier (4 bytes)
  - `fingerprint`: SHA-256(public_key)[:4 bytes] as 8 hex characters
  - `base64_private_key`: X25519 private key (32 bytes, base64-encoded)
- Users SHOULD store in secure credential managers (not plaintext files)
- Users SHOULD NOT commit keys to version control
- Keys downloaded from browser as text file for user safekeeping

**Server-side (Backend database):**
- Public keys stored in `Project.encryption_key` field (non-sensitive, base64)
- Provider API keys stored encrypted as sealed boxes
- Database encryption at rest recommended
- Server NEVER sees or stores user private keys

### Challenge-Response Authentication

**Properties:**
- Challenges expire (time-limited)
- Challenges single-use (server validates)
- Challenges cryptographically random (UUID v4)

**Attack prevention:**
- Replay attacks: Challenge expires after use
- Brute force: 128-bit UUID space (2^128 attempts)

---

## Algorithm Choices

### Why X25519?

| Property                    | X25519    | RSA-2048  | P-256     |
|-----------------------------|-----------|-----------|-----------|
| **Security level**          | ~128 bits | ~112 bits | ~128 bits |
| **Key size**                | 32 bytes  | 256 bytes | 32 bytes  |
| **Performance**             | Fast      | Slow      | Medium    |
| **Side-channel resistance** | Excellent | Poor      | Medium    |
| **Implementation safety**   | Easy      | Complex   | Medium    |

**Choice:** X25519 provides best security/performance trade-off.

### Why XChaCha20-Poly1305?

| Property                     | XChaCha20-Poly1305 | AES-256-GCM          | AES-256-GCM-SIV      |
|------------------------------|--------------------|----------------------|----------------------|
| **Nonce size**               | 192 bits           | 96 bits              | 96 bits              |
| **Random nonces safe?**      | ✅ Yes (~2^96)      | ⚠️ Limited (~2^32)   | ✅ Yes (~2^48)        |
| **Hardware acceleration**    | ❌ No               | ✅ Yes (AES-NI)       | ✅ Yes (AES-NI)       |
| **Timing attack resistance** | ✅ Constant-time    | ⚠️ Requires AES-NI   | ⚠️ Requires AES-NI   |
| **Nonce misuse resistance**  | ❌ No               | ❌ No                 | ✅ Yes                |
| **Performance (software)**   | ✅ Fast             | ⚠️ Slow + vulnerable | ⚠️ Slow + vulnerable |

**Choice:** XChaCha20-Poly1305 provides:
- Best software-only security (constant-time)
- Large nonces (sealed box uses deterministic derivation)
- No hardware requirements
- Battle-tested in libsodium

**Alternative:** Use AES-256-GCM if:
- FIPS 140-2 compliance required
- Hardware acceleration guaranteed (AES-NI)
- No sealed box pattern (manual nonce management)

### Why SHA-512 for Nonce Derivation?

**Requirements:**
- Collision resistance
- Pre-image resistance
- Domain separation from shared secret

**Alternatives considered:**
- HKDF: More complex, unnecessary for fixed-length output
- SHA-256: Smaller output (would need concatenation)
- Direct ECDH result: No domain separation, predictable

**Choice:** SHA-512 provides 512-bit collision resistance, simple truncation to 192 bits.

---

## Cryptographic Assumptions

Our security relies on the following assumptions:

1. **X25519 ECDH** is computationally hard (discrete logarithm problem on Curve25519)
2. **XChaCha20** is a secure PRF (pseudorandom function)
3. **Poly1305** is a secure MAC (message authentication code)
4. **SHA-512** is collision-resistant and behaves as a random oracle
5. **Random number generation** is cryptographically secure (OS provides good entropy)

If any of these assumptions break, the system's security is compromised.

---

## Security Audit Status

| Component               | Status                   | Last Reviewed   |
|-------------------------|--------------------------|-----------------|
| Cryptographic design    | ✅ Documented             | 2025-01         |
| Implementation (Python) | ⚠️ Not formally audited  | -               |
| Dependencies (PyNaCl)   | ✅ libsodium audited      | Multiple audits |
| Key generation          | ⚠️ Depends on OS entropy | -               |
| HTTP → HTTPS migration  | ❌ TODO                   | -               |

**Recommendation:** Consider third-party security audit before production deployment.

---

## References

- [libsodium documentation](https://libsodium.gitbook.io/)
- [RFC 7539: ChaCha20 and Poly1305](https://tools.ietf.org/html/rfc7539)
- [RFC 7748: Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
- [XChaCha20-Poly1305 IETF Draft](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha)
- [ECIES: Elliptic Curve Integrated Encryption Scheme](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)
- [NaCl: Networking and Cryptography library](https://nacl.cr.yp.to/)

---
