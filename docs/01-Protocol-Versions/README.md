# Protocol Versions

This document describes the cryptography and encoding rules for Paseto protocol versions,
to assist in cross-platform library development.

# Rules for Current and Future Protocol Versions

1. Everything must be authenticated. Attackers should never be allowed the opportunity
   to alter messages freely.
   * If encryption is specified, unauthenticated modes (e.g. AES-CBC) are forbidden.
   * The nonce or initialization vector must be covered by the authentication
     tag, not just the ciphertext.
   * Some degree of nonce-misuse resistance should be provided by any future schemes. 
2. Non-deterministic, stateful, and otherwise dangerous signature schemes (e.g. ECDSA
   without RFC 6979, XMSS) are forbidden.
3. Public-key cryptography must be IND-CCA2 secure to be considered for inclusion.
   * This means no RSA with PKCS1v1.5 padding, textbook RSA, etc.
4. By default, libraries should only allow the two most recent versions to be used.
   * If there are only two versions, that means `v1` and `v2`.
   * If a future post-quantum `v3` is defined, `v1` should no longer be accepted.
   * If an additional version `v4` is defined, `v2` should no longer be accepted.

# Versions

## Version 1: Compatibility Mode

See [the version 1 specification](Version1.md) for details. At a glance:

* **`v1.local`**: Symmetric Authenticated Encryption:
  * AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC)
  * Key-splitting: HKDF-SHA384
    * Info for encryption key: `paseto-encryption-key`
    * Info for authentication key: `paseto-auth-key-for-aead`
  * 32-byte nonce (first half for AES-CTR, latter half for the HKDF salt)
  * The nonce calculated from HMAC-SHA384(message, `random_bytes(32)`)
    truncated to 32 bytes, during encryption only
  * The HMAC covers the header, nonce, and ciphertext
  * Reference implementation in [Version1.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version1.php):
    * See `aeadEncrypt()` for encryption
    * See `aeadDncrypt()` for decryption
* **`v1.public`**: Asymmetric Authentication (Public-Key Signatures):
  * 2048-bit RSA keys
  * RSASSA-PSS with
    * Hash function: SHA384 as the hash function
    * Mask generation function: MGF1+SHA384
    * Public exponent: 65537
  * Reference implementation in [Version1.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version1.php):
    * See `sign()` for signature generation
    * See `verify()` for signature verification

Version 1 implements the best possible RSA + AES + SHA2 ciphersuite. We only use
OAEP and PSS for RSA encryption and RSA signatures (respectively), never PKCS1v1.5.

Version 1 is recommended only for legacy systems that cannot use modern cryptography.

See also: [Common implementation details for all versions](Common.md).

## Version 2: Recommended

See [the version 2 specification](Version2.md) for details. At a glance:

* **`v2.local`**: Symmetric Encryption:
  * XChaCha20-Poly1305 (192-bit nonce, 256-bit key, 128-bit authentication tag)
  * Encrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()`
  * Decrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt()`
  * The nonce is calculated from `sodium_crypto_generichash()` of the message,
    with a BLAKE2b key provided by `random_bytes(24)` and an output length of 24,
    during encryption only
  * Reference implementation in [Version2.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version2.php):
    * See `aeadEncrypt()` for encryption
    * See `aeadDncrypt()` for decryption
* **`v2.public`**: Asymmetric Authentication (Public-Key Signatures):
  * Ed25519 (EdDSA over Curve25519)
  * Signing: `sodium_crypto_sign_detached()` 
  * Verifying: `sodium_crypto_sign_verify_detached()`
  * Reference implementation in [Version2.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version2.php):
    * See `sign()` for signature generation
    * See `verify()` for signature verification

See also: [Common implementation details for all versions](Common.md).
