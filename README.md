# PAST: Platform-Agnostic Security Tokens

PAST is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

What follows is a reference implementation. **Requires PHP 7 or newer.**

# Implementation Details

## PAST Message Format:

```
version.purpose.payload
```

The `version` is a string that represents the current version of the protocol. Currently,
two versions are specified, which each possess their own ciphersuites. Accepted values:
`v1`, `v2`.

The `purpose` is a short string describing the purpose of the token. Accepted values:
`enc`, `auth`, `sign`, `seal`.

The payload is a base64url-encoded string that contains the data that is secured. It may be
encrypted. It may use public-key cryptography. It MUST be authenticated or signed. Encrypting
a message using PAST implicitly authenticates it.

## Versions

### Version 1: Compatibility Mode

* Symmetric Authentication:
  * HMAC-SHA384 with 256-bit keys
* Symmetric Encryption:
  * AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC)
  * Key-splitting: HKDF-SHA384
  * 32-byte nonce (half for AES-CTR, half for the HKDF salt)
  * The HMAC covers the header, nonce, and ciphertext
* Asymmetric Authentication (Public-Key Signatures):
  * 2048-bit RSA keys
  * RSASSA-PSS with
    * Hash function: SHA384 as the hash function
    * Mask generation function: MGF1+SHA384
    * Public exponent: 65537
* Asymmetric Encryption (Public-Key Encryption):
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

### Version 2: Recommended

* Symmetric Authentication: 
  * Authenticating: `sodium_crypto_auth()`
  * Verifying: `sodium_crypto_auth_verify()`
* Symmetric Encryption:
  * Encrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()`
  * Decrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt()`
* Asymmetric Authentication (Public-Key Signatures): 
  * Signing: `sodium_crypto_sign_detached()` 
  * Verifying: `sodium_crypto_sign_verify_detached()`
* Asymmetric Encryption (Public-Key Encryption):
  * Key exchange (`sodium_crypto_kx()`) with an ephemeral keypair,
    followed by symmetric encryption
