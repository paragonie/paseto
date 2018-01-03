# Protocol Versions

This document describes the cryptography and encoding rules for PAST protocol versions,
to assist in cross-platform library development.

# Rules for Current and Future Protocol Versions

1. Everything must be authenticated. Attackers should never be allowed the opportunity
   to alter messages freely.
   * If encryption is specified, unauthenticated modes (e.g. AES-CBC) are forbidden.
   * The nonce or initialization vector must be covered by the authentication
     tag, not just the ciphertext.
2. Non-deterministic and stateful signature schemes (e.g. ECDSA without RFC 6979, XMSS) 
   are forbidden.
3. Public-key cryptography must be IND-CCA2 secure to be considered for inclusion.
   * This means no RSA with PKCS1v1.5 padding, textbook RSA, etc.

# Versions

## Version 1: Compatibility Mode

* **`v1.auth`**: Symmetric Authentication:
  * HMAC-SHA384 with 256-bit keys
* **`v1.enc`**: Symmetric Encryption:
  * AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC)
  * Key-splitting: HKDF-SHA384
  * 32-byte nonce (half for AES-CTR, half for the HKDF salt)
  * The HMAC covers the header, nonce, and ciphertext
* **`v1.sign`**: Asymmetric Authentication (Public-Key Signatures):
  * 2048-bit RSA keys
  * RSASSA-PSS with
    * Hash function: SHA384 as the hash function
    * Mask generation function: MGF1+SHA384
    * Public exponent: 65537
* **`v1.seal`**: Asymmetric Encryption (Public-Key Encryption):
  * 2048-bit RSA keys
  * RSAES-OAEP with
    * Hash function: SHA384 as the hash function
    * Mask generation function: MGF1+SHA384
    * Public exponent: 65537
  * KEM+DEM approach:
    1. Generate a random 32-byte key
    2. Encrypt the output of step 1 with the RSA public key
    3. Calculate HKDF-SHA384 of the output of step 2, using the output of
       step 1 (the random key) as the salt
    4. Use the output of step3 as a key to perform symmetric encryption
       (i.e. AES-CTR + HMAC-SHA2)

Version 1 implements the best possible RSA + AES + SHA2 ciphersuite. We only use
OAEP and PSS for RSA encryption and RSA signatures (respectively), never PKCS1v1.5.

Version 1 is recommended only for legacy systems that cannot use modern cryptography.

## Version 2: Recommended

* **`v2.auth`**: Symmetric Authentication:
  * HMAC-SHA512 truncated to 256 characters 
  * Authenticating: `sodium_crypto_auth()` 
  * Verifying: `sodium_crypto_auth_verify()`
* **`v2.enc`**: Symmetric Encryption:
  * XChaCha20-Poly1305 (192-bit nonce, 256-bit key, 128-bit authentication tag)
  * Encrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()`
  * Decrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt()`
* **`v2.sign`**: Asymmetric Authentication (Public-Key Signatures): 
  * Ed25519 (EdDSA over Curve25519)
  * Signing: `sodium_crypto_sign_detached()` 
  * Verifying: `sodium_crypto_sign_verify_detached()`
* **`v2.seal`**: Asymmetric Encryption (Public-Key Encryption):
  * Key exchange (`sodium_crypto_kx()`) with an ephemeral keypair,
    followed by symmetric encryption
  * `sodium_crypto_kx()` is a BLAKE2 hash of the X25519 shared secret,
    followed by the sender's ephemeral public key, followed by the
    recipient's long-term public key.

