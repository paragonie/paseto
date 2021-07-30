# Paseto Version 4

## Encrypt

Given a message `m`, key `k`, and optional footer `f`, and an optional
implicit assertion `i` (which defaults to empty string).

1. Set header `h` to `v4.local.`
2. Generate 32 random bytes from the OS's CSPRNG, `n`.
3. Split the key into an Encryption key (`Ek`) and Authentication key (`Ak`),
   using keyed BLAKE2b, using the domain separation constants and `n` as the
   message, and the input key as the key. The first value will be 56 bytes,
   the second will be 32 bytes.
   The derived key will be the leftmost 32 bytes of the hash output.
   The remaining 24 bytes will be used as a counter nonce (`n2`):
   ```
   tmp = crypto_generichash(
       msg = "paseto-encryption-key" || n,
       key = key,
       length = 56
   );
   Ek = tmp[0:32]
   n2 = tmp[32:]
   Ak = crypto_generichash(
       msg = "paseto-auth-key-for-aead" || n,
       key = key,
       length = 32
   );
   ```
4. Encrypt the message using XChaCha20, using `n2` from step 3 as the nonce.
   ```
   c = crypto_stream_xchacha20_xor(
       message = m
       nonce = n2
       key = k
   );
   ```
5. Pack `h`, `n`, `c`, `f`, and `i` together (in that order) using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding).
   We'll call this `preAuth`.
6. Calculate BLAKE2b-MAC of the output of `preAuth`, using `Ak` as the
   authentication key. We'll call this `t`.
   ```
   t = crypto_generichash(
       message = preAuth
       key = Ak,
       length = 32
   );
   ```
7. If `f` is:
    * Empty: return h || base64url(n || c)
    * Non-empty: return h || base64url(n || c) || `.` || base64url(f)
    * ...where || means "concatenate"

## Decrypt

Given a message `m`, key `k`, and optional footer `f`, and an optional
implicit assertion `i` (which defaults to empty string).

1. If `f` is not empty, implementations **MAY** verify that the value appended
   to the token matches some expected string `f`, provided they do so using a
   constant-time string compare function.
2. Verify that the message begins with `v4.local.`, otherwise throw an
   exception. This constant will be referred to as `h`.
   * **Future-proofing**: If a future PASETO variant allows for encodings other
     than JSON (e.g., CBOR), future implementations **MAY** also permit those 
     values at this step (e.g. `v4c.local.`).
3. Decode the payload (`m` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from base64url to raw binary. Set:
    * `n` to the leftmost 32 bytes
    * `c` to the middle remainder of the payload, excluding `n`.
4. Split the key into an Encryption key (`Ek`) and Authentication key (`Ak`),
   using keyed BLAKE2b, using the domain separation constants and `n` as the
   message, and the input key as the key. The first value will be 56 bytes,
   the second will be 32 bytes.
   The derived key will be the leftmost 32 bytes of the hash output.
   The remaining 24 bytes will be used as a counter nonce (`n2`):
   ```
   tmp = crypto_generichash(
       msg = "paseto-encryption-key" || n,
       key = key,
       length = 56
   );
   Ek = tmp[0:32]
   n2 = tmp[32:]
   Ak = crypto_generichash(
       msg = "paseto-auth-key-for-aead" || n,
       key = key,
       length = 32
   );
   ```
4. Pack `h`, `n`, `c`, `f`, and `i` together (in that order) using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding).
   We'll call this `preAuth`.
5. Re-calculate BLAKE2b-MAC of the output of `preAuth`, using `Ak` as the
   authentication key. We'll call this `t2`.
   ```
   t2 = crypto_generichash(
       message = preAuth
       key = Ak,
       length = 32
   );
   ```
6. Compare `t` with `t2` using a constant-time string compare function. If they
   are not identical, throw an exception.
    * You **MUST** use a constant-time string compare function to be compliant.
      If you do not have one available to you in your programming language/framework,
      you MUST use [Double HMAC](https://paragonie.com/blog/2015/11/preventing-timing-attacks-on-string-comparison-with-double-hmac-strategy).
7. Decrypt `c` using `XChaCha20`, store the result in `p`.
   ```
   p = crypto_stream_xchacha20_xor(
      ciphertext = c
      nonce = n2
      key = k
   );
   ```
8. If decryption failed, throw an exception. Otherwise, return `p`.

## Sign

Given a message `m`, Ed25519 secret key `sk`, and
optional footer `f` (which defaults to empty string), and an optional
implicit assertion `i` (which defaults to empty string):

1. Set `h` to `v4.public.`
2. Pack `h`, `m`, `f`, and `i` together using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding)
   (pre-authentication encoding). We'll call this `m2`.
3. Sign `m2` using Ed25519 `sk`. We'll call this `sig`.
   ```
   sig = crypto_sign_detached(
       message = m2,
       private_key = sk
   );
   ```
4. If `f` is:
    * Empty: return "`h` || base64url(`m` || `sig`)"
    * Non-empty: return "`h` || base64url(`m` || `sig`) || `.` || base64url(`f`)"
    * ...where || means "concatenate"
    * Note: `base64url()` means Base64url from RFC 4648 without `=` padding.

## Verify

Given a signed message `sm`, public key `pk`, and optional footer `f`
(which defaults to empty string), and an optional
implicit assertion `i` (which defaults to empty string):

1. If `f` is not empty, implementations **MAY** verify that the value appended
   to the token matches some expected string `f`, provided they do so using a
   constant-time string compare function.
2. Verify that the message begins with `v4.public.`, otherwise throw an exception.
   This constant will be referred to as `h`.
3. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from base64url to raw binary. Set:
    * `s` to the rightmost 64 bytes
    * `m` to the leftmost remainder of the payload, excluding `s`
4. Pack `h`, `m`, `f`, `i` together using
   [PAE](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding).
   We'll call this `m2`.
5. Use Ed25519 to verify that the signature is valid for the message:
   ```
   valid = crypto_sign_verify_detached(
       signature = s,
       message = m2,
       public_key = pk
   );
   ```
6. If the signature is valid, return `m`. Otherwise, throw an exception.
