# Protocol Versions

This document describes the cryptography and encoding rules for PAST protocol versions,
to assist in cross-platform library development.

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
  * Authenticating: `sodium_crypto_auth()`
  * Verifying: `sodium_crypto_auth_verify()`
* **`v2.enc`**: Symmetric Encryption:
  * Encrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()`
  * Decrypting: `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt()`
* **`v2.sign`**: Asymmetric Authentication (Public-Key Signatures): 
  * Signing: `sodium_crypto_sign_detached()` 
  * Verifying: `sodium_crypto_sign_verify_detached()`
* **`v2.seal`**: Asymmetric Encryption (Public-Key Encryption):
  * Key exchange (`sodium_crypto_kx()`) with an ephemeral keypair,
    followed by symmetric encryption

## Example

```php
<?php
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\Past\{Version1, Version2};

$key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');
$messsage = \json_encode(['data' => 'this is a signed message', 'exp' => '2039-01-01T00:00:00']);
$footer = \json_encode(['key-id' => 'gandalf0']);

$v1Token = Version1::auth($messsage, $key);
var_dump($v1Token);
// string(156) "v1.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9tHUXb9BcoicC_kXc3fxkd_jpm2Laowv7OZ4sIH0ZlKRYcO2ez_zVtp_r94dfmh3W"

$token = Version2::auth($messsage, $key, $footer);
var_dump($token);
// string(165) "v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9hClJIR0hw-ULW0zU0023NYqpdOFmUB7-7wBP8TzILYA=.eyJrZXktaWQiOiJnYW5kYWxmMCJ9"
```
