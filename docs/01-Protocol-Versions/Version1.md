# Paseto Version 1

## GetNonce

Given a message (`m`) and a nonce (`n`):

1. Calculate HMAC-SHA384 of the message `m` with `n` as the key.
2. Return the leftmost 32 bytes of step 1.

## Encrypt

Given a message `m`, key `k`, and optional footer `f`
(which defaults to empty string):

1. Set header `h` to `v1.local.`
2. Generate 32 random bytes from the OS's CSPRNG.
3. Calculate `GetNonce()` of `m` and the output of step 2
   to get the nonce, `n`.
   * This step is to ensure that an RNG failure does not result
     in a nonce-misuse condition that breaks the security of
     our stream cipher.
4. Split the key into an Encryption key (`Ek`) and Authentication key (`Ak`),
   using the leftmost 16 bytes of `n` as the HKDF salt:
   ```
   Ek = hkdf_sha384(
       len = 32
       ikm = k,
       info = "paseto-encryption-key",
       salt = n[0:16]
   );
   Ak = hkdf_sha384(
       len = 32
       ikm = k,
       info = "paseto-auth-key-for-aead",
       salt = n[0:16]
   );
   ```
5. Encrypt the message using `AES-256-CTR`, using `Ek` as the key and
   the rightmost 16 bytes of `n` as the nonce. We'll call this `c`:
   ```
   c = aes256ctr_encrypt(
       plaintext = m,
       nonce = n[16:]
       key = Ek
   );
   ```
6. Pack `h`, `n`, `c`, and `f` together using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding)
   (pre-authentication encoding). We'll call this `preAuth`
7. Calculate HMAC-SHA384 of the output of `preAuth`, using `Ak` as the
   authentication key. We'll call this `t`.
8. If `f` is:
   * Empty: return "`h` || base64url(`n` || `c` || `t`)"
   * Non-empty: return "`h` || base64url(`n` || `c` || `t`) || `.` || base64url(`f`)"
   * ...where || means "concatenate"
   * Note: `base64url()` means Base64url from RFC 4648 without `=` padding.

## Decrypt

Given a message `m`, key `k`, and optional footer `f`
(which defaults to empty string):

1. If `f` is not empty, verify that the value appended to the token matches `f`,
   using a constant-time string compare function. If it does not, throw an exception. 
2. Verify that the message begins with `v1.local.`, otherwise throw an exception.
   This constant will be referred to as `h`.
3. Decode the payload (`m` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from base64url to raw binary. Set:
   * `n` to the leftmost 32 bytes
   * `t` to the rightmost 48 bytes
   * `c` to the middle remainder of the payload, excluding `n` and `t`
4. Split the keys using the leftmost 32 bytes of `n` as the HKDF salt:
   ```
   Ek = hkdf_sha384(
       len = 32
       ikm = k,
       info = "paseto-encryption-key",
       salt = n[0:16]
   );
   Ak = hkdf_sha384(
       len = 32
       ikm = k,
       info = "paseto-auth-key-for-aead",
       salt = n[0:16]
   );
   ```
5. Pack `h`, `n`, `c`, and `f` together using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding)
   (pre-authentication encoding). We'll call this `preAuth`.
6. Recalculate HASH-HMAC384 of `preAuth` using `Ak` as the key.
   We'll call this `t2`.
7. Compare `t` with `t2` using a constant-time string compare function.
   If they are not identical, throw an exception.
8. Decrypt `c` using `AES-256-CTR`, using `Ek` as the key and
   the rightmost 16 bytes of `n` as the nonce, and return this value.
   ```
   return aes256ctr_decrypt(
       cipherext = c,
       nonce = n[16:]
       key = Ek
   );
   ```

## Sign

Given a message `m`, 2048-bit RSA secret key `sk`, and
optional footer `f` (which defaults to empty string):

1. Set `h` to `v1.public.`
2. Pack `h`, `m`, and `f` together using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding)
   (pre-authentication encoding). We'll call this `m2`.
3. Sign `m2` using RSA with the private key `sk`. We'll call this `sig`.
   ```
   sig = crypto_sign_rsa(
       message = m2,
       private_key = sk,
       padding_mode = "pss",
       public_exponent = 65537,
       hash = "sha384"
       mgf = "mgf1+sha384"
   );
   ```
   Only the above parameters are supported. PKCS1v1.5 is explicitly forbidden.
4. If `f` is:
   * Empty: return "`h` || base64url(`m` || `sig`)"
   * Non-empty: return "`h` || base64url(`m` || `sig`) || `.` || base64url(`f`)"
   * ...where || means "concatenate"
   * Note: `base64url()` means Base64url from RFC 4648 without `=` padding.

## Verify

Given a signed message `sm`, RSA public key `pk`, and optional
footer `f` (which defaults to empty string):

1. If `f` is not empty, verify that the value appended to the token matches `f`,
   using a constant-time string compare function. If it does not, throw an exception. 
2. Verify that the message begins with `v1.public.`, otherwise throw an exception.
   This constant will be referred to as `h`.
3. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from base64url to raw binary. Set:
   * `s` to the rightmost 256 bytes
   * `m` to the leftmost remainder of the payload, excluding `s`  
4. Pack `h`, `m`, and `f` together using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding)
   (pre-authentication encoding). We'll call this `m2`.
5. Use RSA to verify that the signature is valid for the message:
   ```
   valid = crypto_sign_rsa_verify(
       signature = s,
       message = m2,
       public_key = pk
   );
   ```
6. If the signature is valid, return `m`. Otherwise, throw an exception.
