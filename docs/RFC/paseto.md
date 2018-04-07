% title = "PASETO: Platform-Agnostic SEcurity TOkens"
% abbr = "PASETO"
% category = "info"
% docname = "draft-paragonie-pasetorfc-draft00"
% keyword = ["security", "token"]
%
% date = 2018-04-05T13:00:00Z
%
% [[author]]
% initials="S."
% surname="Arciszewski"
% fullname="Scott Arciszewski"
% organization="Paragon Initiative Enterprises"
%   [author.address]
%   email = "security@paragonie.com"
%   [author.address.postal]
%   country = "United States"

.# Abstract

Platform-Agnostic SEcurity TOkens (PASETO) provides a cryptographically
secure, compact, and URL-safe representation of claims that may be
transferred between two parties. The claims in a PASETO are encoded as
a JavaScript Object (JSON), version-tagged, and either encrypted
or signed using public-key cryptography.

{mainmatter}

# Introduction

Platform-Agnostic SEcurity TOken (PASETO) is a cryptographically secure,
compact, and URL-safe representation of claims intended for space-constrained
environments such as HTTP Cookies, HTTP Authorization headers, and URI
query parameters. PASETOs encode claims to be transmitted in a JSON
[@!RFC7159] object, and is either encrypted or signed using public-key
cryptography.

## Difference Between PASETO and JOSE

The key difference between PASETO and the JOSE family of standards
(JWS [@!RFC7516], JWE [@!RFC7517], JWK [@!RFC7518], JWA [@!RFC7518], and
JWT [@!RFC7519]) is that JOSE allows implementors and users to mix and
match their own choice of cryptographig algorithms (specified by the
"alg" header in JWT), while PASETO has clearly defined protocol versions
to prevent users without a cryptography engineering background from
selecting or permitting an insecure configuration.

PASETO is defined in two pieces:

1. The PASETO Message Format, defined in (#paseto-message-format)
2. The PASETO Protocol Version, defined in (#paseto-protocol-versions)

# Notation and Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**",
"**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in RFC 2119 [@!RFC2119].

Additionally, the key words "**MIGHT**", "**COULD**", "**MAY WISH TO**", "**WOULD
PROBABLY**", "**SHOULD CONSIDER**", and "**MUST (BUT WE KNOW YOU WON'T)**" in
this document are to interpreted as described in RFC 6919 [@!RFC6919].

# PASETO Message Format

Without the Optional Footer:

~~~
version.purpose.payload
~~~

With the Optional Footer:

~~~
version.purpose.payload.footer
~~~

The **version** is a string that represents the current version of the
protocol. Currently, two versions are specified, which each possess
their own ciphersuites. Accepted values: **v1**, **v2**.

The **purpose** is a short string describing the purpose of the token. Accepted values:
**local**, **public**.

* **local**: shared-key authenticated encryption
* **public**: public-key digital signatures; **not encrypted**

Any optional data can be appended to the **footer**. This data is authenticated
through inclusion in the calculation of the authentication tag along with the header
and payload. The **footer** is NOT encrypted.

# PASETO Protocol Versions

PASETO defines two protocol versions, **v1** and **v2**. Each protocol version
strictly defines the cryptographic primitives used. Changes to the primitives
requires new protocol versions.

Both **v1** and **v2** provide authentication of the entire PASETO message,
including the **version**, **purpose**, **payload** and **footer**.

## Authentication Padding

Multi-part messages (e.g. header, content, footer) are encoded
in a specific manner before being passed to the respective
cryptographic function.

In `local` mode, this encoding is applied to the additional
associated data (AAD). In `remote` mode, which is not encrypted,
this encoding is applied to the components of the token, with
respect to the protocol version being followed.

The reference implementation resides in `Util::preAuthEncode()`.
We will refer to it as **PAE** in this document (short for
Pre-Authentication Encoding).

### PAE Definition

`PAE()` accepts an array of strings.

`LE64()` encodes a 64-bit unsigned integer into a little-endian binary
string. The most significant bit MUST be set to 0 for interoperability
with programming languages that do not have unsigned integer support.

The first 8 bytes of the output will be the number of pieces. Typically
this is a small number (3 to 5). This is calculated by `LE64()` of the
size of the array.

Next, for each piece provided, the length of the piece is encoded via
`LE64()` and prefixed to each piece before concatenation.

~~~ javascript
function LE64(n) {
    var str = '';
    for (var i = 0; i < 8; ++i) {
        if (i === 7) {
            n &= 127;
        }
        str += String.fromCharCode(n & 255);
        n = n >>> 8;
    }
    return str;
}
function PAE(pieces) {
    if (!Array.isArray(pieces)) {
        throw TypeError('Expected an array.');
    }
    var count = pieces.length;
    var output = LE64(count);
    for (var i = 0; i < count; i++) {
        output += LE64(pieces[i].length);
        output += pieces[i];
    }
    return output;
}
~~~
Figure: JavaScript implementation of Pre-Authentication Encoding

As a consequence:

* `PAE([])` will always return `\x00\x00\x00\x00\x00\x00\x00\x00`
* `PAE([''])` will always return
  `\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`
* `PAE(['test'])` will always return
  `\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test`
* `PAE('test')` will throw a `TypeError`

As a result, you cannot create a collision with only a partially controlled
plaintext. Either the number of pieces will differ, or the length of one
of the fields (which is prefixed to the input you can provide) will differ,
or both.

Due to the length being expressed as an unsigned 64-bit integer, it remains
infeasible to generate/transmit enough data to create an integer overflow.

This is not used to encode data prior to decryption, and no decoding function
is provided or specified. This merely exists to prevent canonicalization
attacks.

# Version v1

Version **v1** is a compatibility mode comprised of cryptographic primitives
likely available on legacy systems. **v1** **SHOULD NOT** be used when
all systems are able to use **v2**. **v1** **MAY** be used when
when compatibility requirements include systems unable to use cryptographic
primitives from **v2**.

**v1** messages **MUST** use a **purpose**  value of either **local** or
**public**.


## v1.local

**v1.local** messages **SHALL** be encrypted and authenticated with AES-256-CTR
and HMAC-SHA384, using an **Encrypt-then-MAC** construction.

## v1.public

**v1.public** messages **SHALL** be signed using RSASSA-PSS as defined in
[@!RFC8017].

## Version v1 Algorithms

### v1.GetNonce

Given a message (`m`) and a nonce (`n`):

1. Calculate HMAC-SHA384 of the message `m` with `n` as the key.
2. Return the leftmost 32 bytes of step 1.

### v1.Encrypt

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
6. Pack `h`, `n`, `c`, and `f` together using [PAE](#authentication-padding)
   (pre-authentication encoding). We'll call this `preAuth`
7. Calculate HMAC-SHA384 of the output of `preAuth`, using `Ak` as the
   authentication key. We'll call this `t`.
8. If `f` is:
   * Empty: return "`h` || base64url(`n` || `c` || `t`)"
   * Non-empty: return "`h` || base64url(`n` || `c` || `t`) || `.` || base64url(`f`)"
   * ...where || means "concatenate"
   * Note: `base64url()` means Base64url from RFC 4648 without `=` padding.

### v1.Decrypt

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
5. Pack `h`, `n`, `c`, and `f` together using [PAE](#authentication-padding)
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

### v1.Sign

Given a message `m`, 2048-bit RSA secret key `sk`, and
optional footer `f` (which defaults to empty string):

1. Set `h` to `v1.public.`
2. Pack `h`, `m`, and `f` together using [PAE](#authentication-padding)
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

## v1.Verify

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
4. Pack `h`, `m`, and `f` together using  [PAE](#authentication-padding)
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


# Version v2
Version **v2** is the **RECOMMENDED** protocol version. **v2** **SHOULD** be
used in preference to **v1**. Applications using PASETO **SHOULD CONSIDER**
only supporting **v1** messages.

**v2** messages **MUST** use a **purpose**  value of either **local** or
**public**.

## v2.local

**v2.local** messages **MUST** be encrypted with XChaCha20-Poly1305, a variant of
ChaCha20-Poly1305 [@!RFC7539] defined in libsodium that uses a 192-bit nonce.

The **key** **SHALL** be provided by the user. The **key** **MUST** be 32 bytes
long, and **SHOULD** be generated using a cryptographically secure source.
Implementors **SHOULD CONSIDER** providing functionality to generate this
key for users when the implementation can ensure adequate entropy. Any provided
means for generating the **key** **MUST NOT** use poor sources of randomness.

The **nonce** **SHALL** be constructed from a **BLAKE2b** [@!RFC7693]
hash of the **payload**, with a 24 byte randomly generated key parameter and an
output length of 24 bytes. Implementations **SHOULD** use the libsodium
`crypto_generichash` function when available.

The v2.local ciphertext **SHALL** be constructed using XChaCha20-Poly1305
of the **payload**, using the generated **nonce**, the generated
**Additional Associated Data**, and using the 32 byte **key**. Implementations
**SHOULD** use the libsodium `crypto_aead_xchacha20poly1305_ietf_encrypt`
and `crypto_aead_xchacha20poly1305_ietf_decrypt` functions when available.

The **v2.local output** is generated by prepending 'v2.local.' to the
base64url-encoded **v2.local ciphertext** as per the **PASETO Message Format**

## v2.public

**v2.public** messages **MUST** be signed using Ed25519 [@!RFC8032] public key
signatures. These messages provide authentication but do not prevent the
contents from being read, including by those without either the **public key**
or the **private key**.

The **public key** and **private key** **SHOULD** be a valid pair of Ed25519 keys.
Implementations **SHOULD CONSIDER** providing functions to generate the keypair
and **SHOULD** use the `crypto_sign_keypair` libsodium function to do this when
available.

The **v2.public** **signature** is created by generating a byte string containing
the **Additional Associated Data** of the public header (v2.public), the bytes
of the **data**, and the **footer**. The **Additional Associated Data** is then
signed with Ed25519 using the **private key**. Implementations **SHOULD** use
the `crypto_sign_detached` libsodium function to generate this signature when
available.

The **signed payload** is generated by appending the **signature** to the input
data bytes. It is then base64url-encoded.

The **v2.public output** is generated by prepending 'v2.public.' to the
**signed payload** as per the **PASETO Message Format**.

