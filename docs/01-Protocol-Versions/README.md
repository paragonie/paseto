# Protocol Versions

This document describes the cryptography and encoding rules for Paseto protocol versions,
to assist in cross-platform library development.

## Naming Conventions

The cryptography protocol version is named using this convention: `/^Version \d$/`.
When we discuss "Version 4" spelled out, we're talking about the cryptography
without any regard to the underlying encoding format for the payload containing
the claims.

The token format is named using this convention: `/^v\d([a-z]+?)$/`. When
no optional suffix is provided, this describes a PASETO token using JSON
to encode claims, along with the corresponding Version (see previous paragraph)
to protect those claims.

The intent is that the cryptographic format ("Version 3", "Version 4") can be
reused for arbitrary payloads, but the token format ("v3", "v4") refers to a
specific encoding of claims under-the-hood.

If this is confusing, just know that most of the time, you only need to deal
with the complete token (n.b., some permutation of  {`v1`, `v2`, `v3`, `v4`}
and {`local`, `public`}). 
The cryptographic layer (`Version 1`, `Version 2`, `Version 3`, `Version 4`)
is mostly for cryptographers to argue about.

## Rules for Current and Future Protocol Versions

1. Everything must be authenticated. Attackers should never be allowed the opportunity
   to alter messages freely.
   * If encryption is specified, unauthenticated modes (e.g. AES-CBC) are forbidden.
   * The nonce or initialization vector must be covered by the authentication
     tag, not just the ciphertext.
   * Some degree of nonce-misuse resistance should be provided by any future schemes. 
2. Non-deterministic, stateful, and otherwise dangerous signature schemes (e.g. ~~ECDSA
   without RFC 6979,~~ XMSS) are forbidden.
   * ECDSA without RFC 6979 is permitted, but *only* when a CSPRNG is reliably available.
     If this cannot be guaranteed, you **MUST NOT** implement ECDSA without RFC 6979.
3. Public-key cryptography must be IND-CCA2 secure to be considered for inclusion.
   * This means no RSA with PKCS1v1.5 padding, textbook RSA, etc.
4. By default, libraries should only allow the two most recent versions in a family
   to be used.
   * The NIST family of versions is `Version 1` and `Version 3`.
   * The Sodium family of versions is `Version 2` and `Version 4`.
   * If a future post-quantum `Version 5` (NIST) and/or `Version 6` (Sodium) is defined, 
     `Version 1` and `Version 2` should no longer be accepted.
   * This is a deviation from the **original** intent of this rule, to encapsulate
     the fact that we have parallel versions. In the future, we expect this to converge
     to one family of versions.
5. New versions will be decided and formalized by the PASETO developers. 
   * User-defined homemade protocols are discouraged. If implementors wish to break
     this rule and define their own custom protocol suite, they must NOT continue
     the {`v1`, `v2`, ... } series naming convention for tokens.
   * Any version identifiers that match the regular expression, 
     `/^v[0-9\-\.]+([a-z]+?)/` are reserved by the PASETO development team.

# Versions

## Version 1: NIST Compatibility

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
      * It also covers the footer, if provided
  * Reference implementation in [Version1.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version1.php):
    * See `aeadEncrypt()` for encryption
    * See `aeadDecrypt()` for decryption
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

## Version 2: Sodium Original

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
    * See `aeadDecrypt()` for decryption
* **`v2.public`**: Asymmetric Authentication (Public-Key Signatures):
  * Ed25519 (EdDSA over Curve25519)
  * Signing: `sodium_crypto_sign_detached()` 
  * Verifying: `sodium_crypto_sign_verify_detached()`
  * Reference implementation in [Version2.php](https://github.com/paragonie/paseto/blob/master/src/Protocol/Version2.php):
    * See `sign()` for signature generation
    * See `verify()` for signature verification

See also: [Common implementation details for all versions](Common.md).

## Version 3: NIST Modern

See [the version 3 specification](Version3.md) for details. At a glance:

* **`v3.local`**: Symmetric Authenticated Encryption:
    * AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC)
    * Key-splitting: HKDF-SHA384
        * Info for encryption key: `paseto-encryption-key`
          The encryption key and implicit counter nonce are both returned
          from HKDF in this version.
        * Info for authentication key: `paseto-auth-key-for-aead`
    * 32-byte nonce (no longer prehashed), passed entirely to HKDF
      (as part of the `info` tag, rather than as a salt).
    * The HMAC covers the header, nonce, and ciphertext
      * It also covers the footer, if provided
      * It also covers the implicit assertions, if provided
* **`v3.public`**: Asymmetric Authentication (Public-Key Signatures):
    * ECDSA over NIST P-384, with SHA-384,
      using [RFC 6979 deterministic k-values](https://tools.ietf.org/html/rfc6979)
      (if reasonably practical; otherwise a CSPRNG **MUST** be used).
      Hedged signatures are allowed too.
    * The public key is also included in the PAE step, to ensure 
      `v3.public` tokens provide Exclusive Ownership.

See also: [Common implementation details for all versions](Common.md).

## Version 4: Sodium Modern

See [the version 4 specification](Version4.md) for details. At a glance:

* **`v4.local`**: Symmetric Authenticated Encryption:
    * XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC)
    * Key-splitting: BLAKE2b
        * Info for encryption key: `paseto-encryption-key`
          The encryption key and implicit counter nonce are both returned
          from BLAKE2b in this version.
        * Info for authentication key: `paseto-auth-key-for-aead`
    * 32-byte nonce (no longer prehashed), passed entirely to BLAKE2b.
    * The BLAKE2b-MAC covers the header, nonce, and ciphertext
        * It also covers the footer, if provided
        * It also covers the implicit assertions, if provided
* **`v4.public`**: Asymmetric Authentication (Public-Key Signatures):
    * Ed25519 (EdDSA over Curve25519)
    * Signing: `sodium_crypto_sign_detached()`
    * Verifying: `sodium_crypto_sign_verify_detached()`

See also: [Common implementation details for all versions](Common.md).
