# PAST Version 1

## GetNonce

Given a message (`m`) and a nonce (`n`):

1. Calculate HMAC-SHA384 of the message `m` with `n` as the key.
2. Return the leftmost 32 bytes of step 1.

## Encrypt

Given a message `m`, key `k`, and optional footer `f`.

1. Set header `h` to `v1.local.`
2. Generate 32 random bytes from the OS's CSPRNG.
3. Calculate `GetNonce()` of `m` and the output of step 2
   to get the nonce, `n`.
4. Split the key into an Encryption key (`Ek`) and Authentication key (`Ak`),
   using the leftmost 16 bytes of `n` as the HKDF salt:
   ```
   Ek = hkdf_sha384(
       len = 32
       ikm = k,
       info = "past-encryption-key",
       salt = n[0:16]
   );
   Ak = hkdf_sha384(
       len = 32
       ikm = k,
       info = "past-auth-key-for-aead",
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
   [PAE](https://github.com/paragonie/past/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding)
   (pre-authentication encoding). We'll call this `preAuth`
7. Calculate HMAC-SHA384 of the output of `preAuth`, using `Ak` as the
   authentication key. We'll call this `t`.
8. If `f` is:
   * Empty: return "`h` || base64url(`n` || `c` || `t`)"
   * Non-empty: return "`h` || base64url(`n` || `c` || `t`) || `.` || base64url(`f`)"
   * ...where || means "concatenate"

## Decrypt

## Sign

## Verify

