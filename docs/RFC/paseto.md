% title = "PASETO: Platform-Agnostic SEcurity TOkens"
% abbr = "PASETO"
% category = "info"
% docname = "draft-paragon-paseto-rfc-01"
% workgroup = "(No Working Group)"
% keyword = ["security", "token"]
%
% date = 2018-04-19T16:00:00Z
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
% [[author]]
% initials="S."
% surname="Haussmann"
% fullname="Steven Haussmann"
% organization="Rensselaer Polytechnic Institute"
%   [author.address]
%   email = "hausss@rpi.edu"
%   [author.address.postal]
%   country = "United States"

.# Abstract

Platform-Agnostic SEcurity TOkens (PASETOs) provide a cryptographically secure,
compact, and URL-safe representation of claims that may be transferred between
two parties. The claims are encoded in JavaScript Object Notation (JSON),
version-tagged, and either encrypted using shared-key cryptography or signed
using public-key cryptography.

{mainmatter}

# Introduction

A Platform-Agnostic SEcurity TOken (PASETO) is a cryptographically secure,
compact, and URL-safe representation of claims intended for space-constrained
environments such as HTTP Cookies, HTTP Authorization headers, and URI query
parameters. A PASETO encodes claims to be transmitted in a JSON [@!RFC8259]
object, and is either encrypted symmetrically or signed using public-key
cryptography.

## Difference Between PASETO and JOSE

The key difference between PASETO and the JOSE family of standards
(JWS [@!RFC7516], JWE [@!RFC7517], JWK [@!RFC7518], JWA [@!RFC7518], and
JWT [@!RFC7519]) is that JOSE allows implementors and users to mix and match
their own choice of cryptographic algorithms (specified by the "alg" header in
JWT), while PASETO has clearly defined protocol versions to prevent unsafe
configurations from being selected.

PASETO is defined in two pieces:

1. The PASETO Message Format, defined in (#paseto-message-format)
2. The PASETO Protocol Version, defined in (#protocol-versions)

## Notation and Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**MAY**",
and "**OPTIONAL**" in this document are to be interpreted as described in
RFC 2119 [@!RFC2119].

# PASETO Message Format

PASETOs consist of three or four segments, separated by a period (the ASCII
character whose number, represented in hexadecimal, is 2E).

Without the Optional Footer:

~~~
version.purpose.payload
~~~

With the Optional Footer:

~~~
version.purpose.payload.footer
~~~

If no footer is provided, implementations **SHOULD NOT** append a trailing
period to each payload.

The **version** is a string that represents the current version of the protocol.
Currently, two versions are specified, which each possess their own
ciphersuites. Accepted values: **v1**, **v2**.

The **purpose** is a short string describing the purpose of the token. Accepted
values: **local**, **public**.

* **local**: shared-key authenticated encryption
* **public**: public-key digital signatures; **not encrypted**

The **payload** is a string that contains the token's data. In a `local` token,
this data is encrypted with a symmetric cipher. In a `public` token, this data
is *unencrypted*.

Any optional data can be appended to the **footer**. This data is authenticated
through inclusion in the calculation of the authentication tag along with the
header and payload. The **footer** **MUST NOT** be encrypted.

## Base64 Encoding

The payload and footer in a PASETO **MUST** be encoded using base64url as
defined in [@!RFC4648], without `=` padding.

In this document. `b64()` refers to this unpadded variant of base64url.

## Authentication Padding

Multi-part messages (e.g. header, content, footer) are encoded in a specific
manner before being passed to the appropriate cryptographic function.

In `local` mode, this encoding is applied to the additional associated data
(AAD). In `public` mode, which is not encrypted, this encoding is applied to the
components of the token, with respect to the protocol version being followed.

We will refer to this process as **PAE** in this document (short for
Pre-Authentication Encoding).

### PAE Definition

`PAE()` accepts an array of strings.

`LE64()` encodes a 64-bit unsigned integer into a little-endian binary string.
The most significant bit **MUST** be set to 0 for interoperability with
programming languages that do not have unsigned integer support.

The first 8 bytes of the output will be the number of pieces. Currently, this
will be 3 or 4. This is calculated by applying `LE64()` to the size of the
array.

Next, for each piece provided, the length of the piece is encoded via `LE64()`
and prefixed to each piece before concatenation.

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
Figure: JavaScript implementation of Pre-Authentication Encoding (PAE)

As a consequence:

* `PAE([])` will always return `\x00\x00\x00\x00\x00\x00\x00\x00`
* `PAE([''])` will always return
  `\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`
* `PAE(['test'])` will always return
  `\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test`
* `PAE('test')` will throw a `TypeError`

As a result, partially controlled plaintext cannot be used to create a
collision. Either the number of pieces will differ, or the length of one of the
fields (which is prefixed to user-controlled input) will differ, or both.

Due to the length being expressed as an unsigned 64-bit integer, it is
infeasible to encode enough data to create an integer overflow.

This is not used to encode data prior to decryption, and no decoding function
is provided or specified. This merely exists to prevent canonicalization
attacks.

# Protocol Versions

This document defines two protocol versions, **v1** and **v2**.

Each protocol version strictly defines the cryptographic primitives used.
Changes to the primitives requires new protocol versions. Future RFCs **MAY**
introduce new PASETO protocol versions by continuing the convention
(e.g. **v3**, **v4**, ...).

Both **v1** and **v2** provide authentication of the entire PASETO message,
including the **version**, **purpose**, **payload**, and **footer**.

The initial recommendation is to use **v2**, allowing for upgrades to
possible future versions **v3**, **v4**, etc. when they are defined in
the future.

## PASETO Protocol Guidelines

When defining future protocol versions, the following rules **SHOULD**
or **MUST** be followed:

1. Everything in a token **MUST** be authenticated. Attackers should never be
   allowed the opportunity to alter messages freely.
   * If encryption is specified, unauthenticated modes (e.g. AES-CBC without
     a MAC) are forbidden.
   * The nonce or initialization vector must be covered by the authentication
     tag, not just the ciphertext.
2. Some degree of nonce-misuse resistance **SHOULD** be provided:
   * Supporting larger nonces (longer than 128-bit) is sufficient for satisfying
     this requirement, provided the nonce is generated by a cryptographically
     secure random number generator, such as **/dev/urandom** on Linux.
   * Key-splitting and including an additional HKDF salt as part of the nonce is
     sufficient for this requirement.
   * Hashing the plaintext payload with the random nonce is an acceptable 
     strategy for mitigating random number generator failures, but a secure
     random number generator **SHOULD** be used even with this safeguard in
     place.
3. Non-deterministic, stateful, and otherwise dangerous signature schemes (e.g.
   ECDSA without deterministic signatures as in [@!RFC6979], XMSS) are
   forbidden from all PASETO protocols.
4. Public-key cryptography **MUST** be IND-CCA2 secure to be considered for
   inclusion.
   * This means that RSA with PKCS1v1.5 padding and unpadded RSA **MUST NOT**
     ever be used in a PASETO protocol.

# PASETO Protocol Version v1

Version **v1** is a compatibility mode composed of cryptographic primitives
likely available on legacy systems. **v1** **SHOULD NOT** be used when all
systems are able to use **v2**. **v1** **MAY** be used when compatibility
requirements include systems unable to use cryptographic primitives from **v2**.

**v1** messages **MUST** use a **purpose** value of either **local** or
**public**.

## v1.local

**v1.local** messages **SHALL** be encrypted and authenticated with
**AES-256-CTR** (AES-CTR from [@!RFC3686] with a 256-bit key) and
**HMAC-SHA-384** ([@!RFC4231]), using an **Encrypt-then-MAC** construction.

Encryption and authentication keys are split from the original key and half the
nonce, facilitated by HKDF [@!RFC5869] using SHA384.

Refer to the operations defined in **v1.Encrypt** and **v1.Decrypt** for a
formal definition.

## v1.public

**v1.public** messages **SHALL** be signed using RSASSA-PSS as defined in
[@!RFC8017], with 2048-bit private keys. These messages provide authentication
but do not prevent the contents from being read, including by those without
either the **public key** or the **private key**. Refer to the operations
defined in **v1.Sign** and **v1.Verify** for a formal definition.

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
3. Optionally, calculate `GetNonce()` of `m` and the output of step 2 to get the
   nonce, `n`.
   * This step is to ensure that an RNG failure does not result in a
     nonce-misuse condition that breaks the security of our stream cipher.
   * If this step is omitted, the output of step 2 is `n` instead.
4. Split the key (`k`) into an Encryption key (`Ek`) and an Authentication key
   (`Ak`), using the leftmost 16 bytes of `n` as the HKDF salt. (See below for
   pseudocode.)
   * For encryption keys, the **info** parameter for HKDF **MUST** be set to
     **paseto-encryption-key**.
   * For authentication keys, the **info** parameter for HKDF **MUST** be set to
     **paseto-auth-key-for-aead**.
   * The output length **MUST** be 32 for both keys.
5. Encrypt the message using `AES-256-CTR`, using `Ek` as the key and the
   rightmost 16 bytes of `n` as the nonce. We'll call this `c`. (See below for
   pseudocode.)
6. Pack `h`, `n`, `c`, and `f` together (in that order) using PAE (see
   (#authentication-padding)). We'll call this `preAuth`.
7. Calculate HMAC-SHA-384 of the output of `preAuth`, using `Ak` as the
   authentication key. We'll call this `t`.
8. If `f` is:
   * Empty: return h || b64(n || c || t)
   * Non-empty: return h || b64(n || c || t) || `.` || b64(f)
   * ...where || means "concatenate"

Example code:

~~~
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
~~~
Figure: Step 4: Key splitting with HKDF-SHA384 as per [@!RFC5869].

~~~
c = aes256ctr_encrypt(
    plaintext = m,
    nonce = n[16:]
    key = Ek
);
~~~
Figure: Step 5: PASETO v1 encryption (calculating `c`)

### v1.Decrypt

Given a message `m`, key `k`, and optional footer `f`
(which defaults to empty string):

1. If `f` is not empty, implementations **MAY** verify that the value appended
   to the token matches some expected string `f`, provided they do so using a
   constant-time string compare function.
2. Verify that the message begins with `v1.local.`, otherwise throw an
   exception. This constant will be referred to as `h`.
3. Decode the payload (`m` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from b64 to raw binary. Set:
   * `n` to the leftmost 32 bytes
   * `t` to the rightmost 48 bytes
   * `c` to the middle remainder of the payload, excluding `n` and `t`
4. Split the key (`k`) into an Encryption key (`Ek`) and an Authentication key
   (`Ak`), using the leftmost 16 bytes of `n` as the HKDF salt. (See below for
   pseudocode.)
   * For encryption keys, the **info** parameter for HKDF **MUST** be set to
     **paseto-encryption-key**.
   * For authentication keys, the **info** parameter for HKDF **MUST** be set to
     **paseto-auth-key-for-aead**.
   * The output length **MUST** be 32 for both keys.
5. Pack `h`, `n`, `c`, and `f` together (in that order) using PAE (see
   (#authentication-padding)). We'll call this `preAuth`.
6. Recalculate HMAC-SHA-384 of `preAuth` using `Ak` as the key. We'll call this
   `t2`.
7. Compare `t` with `t2` using a constant-time string compare function. If they
   are not identical, throw an exception.
8. Decrypt `c` using `AES-256-CTR`, using `Ek` as the key and the rightmost 16
   bytes of `n` as the nonce, and return this value.

Example code:

~~~
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
~~~
Figure: Step 4: Key splitting with HKDF-SHA384 as per [@!RFC5869].

~~~
return aes256ctr_decrypt(
   cipherext = c,
   nonce = n[16:]
   key = Ek
);
~~~
Figure: Step 8: PASETO v1 decryption

### v1.Sign

Given a message `m`, 2048-bit RSA secret key `sk`, and optional footer `f`
(which defaults to empty string):

1. Set `h` to `v1.public.`
2. Pack `h`, `m`, and `f` together (in that order) using PAE (see
   (#authentication-padding)). We'll call this `m2`.
3. Sign `m2` using RSA with the private key `sk`. We'll call this `sig`. The
   padding mode **MUST** be RSASSA-PSS [@!RFC8017]; PKCS1v1.5 is explicitly
   forbidden. The public exponent `e` **MUST** be 65537. The mask generating
   function **MUST** be MGF1+SHA384. The hash function **MUST** be SHA384.
   (See below for pseudocode.)
4. If `f` is:
   * Empty: return h || b64(m || sig)
   * Non-empty: return h || b64(m || sig) || `.` || b64(f)
   * ...where || means "concatenate"

~~~
sig = crypto_sign_rsa(
   message = m2,
   private_key = sk,
   padding_mode = "pss",
   public_exponent = 65537,
   hash = "sha384"
   mgf = "mgf1+sha384"
);
~~~
Figure: Pseudocode: RSA signature algorithm used in PASETO v1

### v1.Verify

Given a signed message `sm`, RSA public key `pk`, and optional
footer `f` (which defaults to empty string):

1. If `f` is not empty, implementations **MAY** verify that the value appended
   to the token matches some expected string `f`, provided they do so using a
   constant-time string compare function.
2. Verify that the message begins with `v1.public.`, otherwise throw an
   exception. This constant will be referred to as `h`.
3. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from b64 to raw binary. Set:
   * `s` to the rightmost 256 bytes
   * `m` to the leftmost remainder of the payload, excluding `s`
4. Pack `h`, `m`, and `f` together (in that order) using PAE (see
   (#authentication-padding)). We'll call this `m2`.
5. Use RSA to verify that the signature is valid for the message.
   The padding mode **MUST** be RSASSA-PSS [@!RFC8017]; PKCS1v1.5 is
   explicitly forbidden. The public exponent `e` **MUST** be 65537.
   The mask generating function **MUST** be MGF1+SHA384. The hash function
   **MUST** be SHA384. (See below for pseudocode.)
6. If the signature is valid, return `m`. Otherwise, throw an exception.

~~~
valid = crypto_sign_rsa_verify(
    signature = s,
    message = m2,
    public_key = pk,
    padding_mode = "pss",
    public_exponent = 65537,
    hash = "sha384"
    mgf = "mgf1+sha384"
);
~~~
Figure: Pseudocode: RSA signature validation for PASETO v1

# PASETO Protocol Version v2

Version **v2** is the **RECOMMENDED** protocol version. **v2** **SHOULD** be
used in preference to **v1**. Applications using PASETO **SHOULD** only support
**v2** messages, but **MAY** support **v1** messages if the cryptographic
primitives used in **v2** are not available on all machines.

**v2** messages **MUST** use a **purpose**  value of either **local** or
**public**.

## v2.local

**v2.local** messages **MUST** be encrypted with XChaCha20-Poly1305, a variant
of ChaCha20-Poly1305 [@!RFC7539] defined in (#aeadxchacha20poly1305). Refer
to the operations defined in **v2.Encrypt** and **v2.Decrypt** for a formal
definition.

## v2.public

**v2.public** messages **MUST** be signed using Ed25519 [@!RFC8032] public key
signatures. These messages provide authentication but do not prevent the
contents from being read, including by those without either the **public key**
or the **private key**. Refer to the operations defined in **v2.Sign** and
**v2.Verify** for a formal definition.

## Version v2 Algorithms

### v2.Encrypt

Given a message `m`, key `k`, and optional footer `f`.

1. Set header `h` to `v2.local.`
2. Generate 24 random bytes from the OS's CSPRNG.
3. Optionally, calculate BLAKE2b of the message `m` with the output of step 2 as
   the key, with an output length of 24. This will be our nonce, `n`.
   * This step is to ensure that an RNG failure does not result in a
     nonce-misuse condition that breaks the security of our stream cipher.
   * If this step is omitted, the output of step 2 is `n` instead.
4. Pack `h`, `n`, and `f` together (in that order) using PAE (see (#authentication-padding)).
   We'll call this `preAuth`.
5. Encrypt the message using XChaCha20-Poly1305, using an AEAD interface such as
   the one provided in libsodium. (See below for pseudocode.)
6. If `f` is:
   * Empty: return h || b64(n || c)
   * Non-empty: return h || b64(n || c) || `.` || b64(f)
   * ...where || means "concatenate"

~~~
c = crypto_aead_xchacha20poly1305_encrypt(
    message = m
    aad = preAuth
    nonce = n
    key = k
);
~~~
Figure: Step 5: PASETO v2 encryption (calculating `c`)

### v2.Decrypt

Given a message `m`, key `k`, and optional footer `f`.

1. If `f` is not empty, implementations **MAY** verify that the value appended
   to the token matches some expected string `f`, provided they do so using a
   constant-time string compare function.
2. Verify that the message begins with `v2.local.`, otherwise throw an
   exception. This constant will be referred to as `h`.
3. Decode the payload (`m` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from base64url to raw binary. Set:
   * `n` to the leftmost 24 bytes
   * `c` to the middle remainder of the payload, excluding `n`.
4. Pack `h`, `n`, and `f` together (in that order) using PAE (see
   (#authentication-padding)). We'll call this `preAuth`
5. Decrypt `c` using `XChaCha20-Poly1305`, store the result in `p`.
   (See below for pseudocode.)
6. If decryption failed, throw an exception. Otherwise, return `p`.

~~~
p = crypto_aead_xchacha20poly1305_decrypt(
    ciphertext = c
    aad = preAuth
    nonce = n
    key = k
);
~~~
Figure: Step 8: PASETO v2 decryption

### v2.Sign

Given a message `m`, Ed25519 secret key `sk`, and
optional footer `f` (which defaults to empty string):

1. Set `h` to `v2.public.`
2. Pack `h`, `m`, and `f` together (in that order) using PAE (see
   (#authentication-padding)).
   We'll call this `m2`.
3. Sign `m2` using Ed25519 `sk`. We'll call this `sig`.
   (See below for pseudocode.)
4. If `f` is:
   * Empty: return h || b64(m || sig)
   * Non-empty: return h || b64(m || sig) || `.` || b64(f)
   * ...where || means "concatenate"

~~~
sig = crypto_sign_detached(
    message = m2,
    private_key = sk
);
~~~
Figure: Step 3: Generating an Ed25519 with libsodium

### v2.Verify

Given a signed message `sm`, public key `pk`, and optional footer `f`
(which defaults to empty string):

1. If `f` is not empty, implementations **MAY** verify that the value appended
   to the token matches some expected string `f`, provided they do so using a
   constant-time string compare function.
2. Verify that the message begins with `v2.public.`, otherwise throw an
   exception. This constant will be referred to as `h`.
3. Decode the payload (`sm` sans `h`, `f`, and the optional trailing period
   between `m` and `f`) from base64url to raw binary. Set:
   * `s` to the rightmost 64 bytes
   * `m` to the leftmost remainder of the payload, excluding `s`
4. Pack `h`, `m`, and `f` together (in that order) using PAE (see
   (#authentication-padding)).
   We'll call this `m2`.
5. Use Ed25519 to verify that the signature is valid for the message:
   (See below for pseudocode.)
6. If the signature is valid, return `m`. Otherwise, throw an exception.

~~~
valid = crypto_sign_verify_detached(
    signature = s,
    message = m2,
    public_key = pk
);
~~~
Figure: Step 5: Validating the Ed25519 signature using libsodium.

# Payload Processing

All PASETO payloads **MUST** be a JSON object [@!RFC8259].

If non-UTF-8 character sets are desired for some fields, implementors are
encouraged to use [Base64url](https://tools.ietf.org/html/rfc4648#page-7)
encoding to preserve the original intended binary data, but still use UTF-8 for
the actual payloads.

## Type Safety with Cryptographic Keys

PASETO library implementations **MUST** implement some means of preventing type
confusion bugs between different cryptography keys. For example:

* Prepending each key in memory with a magic byte to serve as a type indicator
  (distinct for every combination of version and purpose).
* In object-oriented programming languages, using separate classes for each
  cryptography key object that may share an interface or common base class.

Cryptographic keys **MUST** require the user to state a version and a purpose
for which they will be used. Furthermore, given a cryptographic key, it
**MUST NOT** be possible for a user to use this key for any version and purpose
combination other than that which was specified during the creation of this key.

## Registered Claims

The following keys are reserved for use within PASETO. Users **SHOULD NOT**
write arbitrary/invalid data to any keys in a top-level PASETO in the list
below:

| Key  | Name      | Type   | Example                             |
| ---- | ----------| ------ | ----------------------------------- |
| iss | Issuer     | string | {"iss":"paragonie.com"}             |
| sub | Subject    | string | {"sub":"test"}                      |
| aud | Audience   | string | {"aud":"pie-hosted.com"}            |
| exp | Expiration | DtTime | {"exp":"2039-01-01T00:00:00+00:00"} |
| nbf | Not Before | DtTime | {"nbf":"2038-04-01T00:00:00+00:00"} |
| iat | Issued At  | DtTime | {"iat":"2038-03-17T00:00:00+00:00"} |
| jti | Token ID   | string | {"jti":"87IFSGFgPNtQNNuw0AtuLttP"}  |
| kid | Key-ID     | string | {"kid":"stored-in-the-footer"}      |

In the table above, DtTime means an ISO 8601 compliant DateTime string.
See [#keyid-support] for special rules about `kid` claims.

Any other claims can be freely used. These keys are only reserved in the
top-level JSON object.

The keys in the above table are case-sensitive.

Implementors (i.e. library designers) **SHOULD** provide some means to
discourage setting invalid/arbitrary data to these reserved claims.

For example: Storing any string that isn't a valid ISO 8601 DateTime in the
`exp` claim should result in an exception or error state (depending on the
programming language in question).

### Key-ID Support

Some systems need to support key rotation, but since the payloads of a *local*
token are always encrypted, it is impractical to store the key id in the
payload.

Instead, users should store Key-ID claims (*kid*) in the unencrypted footer.

For example, a footer of {"kid":"gandalf0"} can be read without needing to first
decrypt the token (which would in turn allow the user to know which key to use
to decrypt the token).

Implementations **SHOULD** provide a means to extract the footer from a PASETO
before authentication and decryption. This is possible for *local* tokens
because the contents of the footer are *not* encrypted. However, the
authenticity of the footer is only assured after the authentication tag is
verified.

While a key identifier can generally be safely used for selecting the
cryptographic key used to decrypt and/or verify payloads before verification,
provided that the *kid* is a public number that is associated with a particular
key which is not supplied by attackers, any other fields stored in the footer
**MUST** be distrusted until the payload has been verified.

IMPORTANT: Key identifiers **MUST** be independent of the actual keys used by
PASETO.

A fingerprint of the key is allowed as long as it is impractical for an attacker
to recover the key from said fingerprint.

For example, the user **MUST NOT** store the public key in the footer for a
**public** token and have the recipient use the provided public key. Doing so
would allow an attacker to replace the public key with one of their own
choosing, which will cause the recipient to accept any signature for any message
as valid, therefore defeating the security goals of public-key cryptography.

Instead, it's recommended that implementors and users use a unique identifier
for each key (independent of the cryptographic key's contents) that is used in a
database or other key-value store to select the appropriate cryptographic key.
These search operations **MUST** fail closed if no valid key is found for the
given key identifier.

# AEAD_XChaCha20_Poly1305

XChaCha20-Poly1305 is a variant of the ChaCha20-Poly1305 AEAD construction as
defined in [@!RFC7539] that uses a 192-bit nonce instead of a 64-bit nonce.

The algorithm for XChaCha20-Poly1305 is as follows:

1. Calculate a subkey from the first 16 bytes of the nonce and the key, using
   HChaCha20 ((#hchacha20)).
2. Use the subkey and remaining 8 bytes of the nonce (prefixed with 4 NUL
   bytes) with AEAD_CHACHA20_POLY1305 from [@!RFC7539] as normal.

XChaCha20-Poly1305 implementations already exist in
[libsodium](https://download.libsodium.org/doc/secret-key_cryptography/xchacha20-poly1305_construction.html),
[Monocypher](https://github.com/LoupVaillant/Monocypher),
[xsecretbox](https://github.com/jedisct1/xsecretbox),
and a standalone [Go](https://github.com/aead/chacha20) library.

## Motivation for XChaCha20-Poly1305

As long as ChaCha20-Poly1305 is a secure AEAD cipher and ChaCha is a secure
pseudorandom function (PRF), XChaCha20-Poly1305 is secure.

The nonce used by the original ChaCha20-Poly1305 is too short to safely use with
random strings for long-lived keys.

With XChaCha20-Poly1305, users can safely generate a random 192-bit nonce for
each message and not worry about nonce-reuse vulnerabilities.

## HChaCha20

**HChaCha20** is an intermediary step towards XChaCha20 based on the
construction and security proof used to create
[XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), an extended-nonce
Salsa20 variant used in [NaCl](https://nacl.cr.yp.to).

HChaCha20 is initialized the same way as the ChaCha cipher, except that
HChaCha20 uses a 128-bit nonce and has no counter.

Consider the two figures below, where each non-whitespace character represents
one nibble of information about the ChaCha states (all numbers little-endian): 

~~~
cccccccc  cccccccc  cccccccc  cccccccc
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
~~~
Figure: ChaCha20 State: c=constant k=key b=blockcount n=nonce

~~~
cccccccc  cccccccc  cccccccc  cccccccc
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn
~~~
Figure: HChaCha20 State: c=constant k=key n=nonce

After initialization, proceed through the ChaCha rounds as usual.

Once the 20 ChaCha rounds have been completed, the first 128 bits and last 128
bits of the keystream (both little-endian) are concatenated, and this 256-bit
subkey is returned.

### Test Vector for the HChaCha20 Block Function

* Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f.
  The key is a sequence of octets with no particular structure before we
  copy it into the HChaCha state.
* Nonce = (00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27)

After setting up the HChaCha state, it looks like this:

~~~
61707865 3320646e 79622d32 6b206574
03020100 07060504 0b0a0908 0f0e0d0c
13121110 17161514 1b1a1918 1f1e1d1c
09000000 4a000000 00000000 27594131
~~~
Figure: ChaCha state with the key setup.

After running 20 rounds (10 column rounds interleaved with 10
"diagonal rounds"), the HChaCha state looks like this:

~~~
82413b42 27b27bfe d30e4250 8a877d73
4864a70a f3cd5479 37cd6a84 ad583c7b
8355e377 127ce783 2d6a07e0 e5d06cbc
a0f9e4d5 8a74a853 c12ec413 26d3ecdc
~~~
Figure: HChaCha state after 20 rounds

HChaCha20 will then return only the first and last rows, resulting
in the following 256-bit key:

~~~
82413b4 227b27bfe d30e4250 8a877d73
a0f9e4d 58a74a853 c12ec413 26d3ecdc
~~~
Figure: Resultant HChaCha20 subkey

# Intended Use-Cases for PASETO

Like JWTs, PASETOs are intended to be single-use tokens, as there is no built-in
mechanism to prevent replay attacks within the token lifetime.

* **local** tokens are intended for tamper-resistant encrypted cookies or HTTP
  request parameters. A resonable example would be long-term authentication
  cookies which re-establish a new session cookie if a user checked the
  "remember me on this computer" box when authenticating. To accomplish this,
  the server would look use the `jti` claim in a database lookup to find the
  appropriate user to associate this session with. After each new browsing
  session, the `jti` would be rotated in the database and a fresh cookie would
  be stored in tbe browser.
* **public** tokens are intended for one-time authentication claims from a third
  party. For example, **public** PASETO would be suitable for a protocol like
  OpenID Connect.

# Security Considerations

PASETO was designed in part to address known deficits of the JOSE standards
that lead to insecure implementations.

PASETO uses versioned protocols, rather than runtime ciphersuite negotiation,
to prevent insecure algorithms from being selected. Mix-and-match is not a
robust strategy for usable security engineering, especially when implementations
have insecure default settings.

If a severe security vulnerability is ever discovered in one of the specified
versions, a new version of the protocol that is not affected should be decided
by a team of cryptography engineers familiar with the vulnerability in question.
This prevents users from having to rewrite and/or reconfigure their
implementations to side-step the vulnerability.

PASETO implementors should only support the two most recent protocol versions
(currently **v1** and **v2**) at any given time.

PASETO users should beware that, although footers are authenticated, they are
never encrypted. Therefore, sensitive information **MUST NOT** be stored in a
footer.

Furthermore, PASETO users should beware that, if footers are employed to
implement Key Identification (**kid**), the values stored in the footer
**MUST** be unrelated to the actual cryptographic key used in verifying the
token as discussed in (#keyid-support).

PASETO has no built-in mechanism to resist replay attacks within the token's
lifetime. Users **SHOULD NOT** attempt to use PASETO to obviate the need for
server-side data storage when designing web applications.

PASETO's cryptography features requires the availability of a secure random
number generator, such as the getrandom(2) syscall on newer Linux distributions,
/dev/urandom on most Unix-like systems, and CryptGenRandom on Windows computers.

The use of userspace pseudo-random number generators, even if seeded by the
operating system's cryptographically secure pseudo-random number generator, is
discouraged.

Implementors should use some means of identifying different key types so that
they cannot be used in the wrong context. Encapsulating each key in a different
class and type-hinting checking that:

* Only symmetric cryptography keys are used for decrypting *local* tokens
* Only asymmetric cryptography public keys are used for verifying *public*
  tokens

# IANA Considerations

The IANA should reserve a new "PASETO Headers" registry for the purpose of this
document and superseding RFCs.

This document defines a suite of string prefixes for PASETO tokens, called
"PASETO Headers" (see (#paseto-message-format)), which consists of two parts:

* **version**, with values **v1**, **v2** defined above
* **purpose**, with the values of **local** or **public**

These two values are concatenated with a single character separator, the ASCII
period character **.**.

Initial values for the "PASETO Headers" registry are given below; future
assignments are to be made through Expert Review [@!RFC8126], such as the
[CFRG].

| Value     | PASETO Header Meaning | Definition  |
| --------- | --------------------- | ----------- |
| v1.local  | Version 1, local      | (#v1local)  |
| v1.public | Version 1, public     | (#v1public) |
| v2.local  | Version 2, local      | (#v2local)  |
| v2.public | Version 2, public     | (#v2public) |
Table: PASETO Headers and their respective meanings

[CFRG]: https://irtf.org/cfrg "Crypto Forum Research Group"

{backmatter}

# PASETO Test Vectors

Note: When a nonce is given below, it refers to the value before being hashed
with the message. Typically this value is provided by a secure random number
generator.

Note: Signing may result in a different token each time, but the given token and
public key pair should validate successfully. The private key that corresponds
to this public key is as follows:

~~~
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9
GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N
02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJ
AZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNx
kRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPI
idZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3
qfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0Jo
WdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0Oy
A0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9
q33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+
1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB
42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04
FfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUV
rPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znw
AG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZ
xCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o
/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2
epTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R
3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9h
B9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHk
b9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJ
x/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT
3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwm
pcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxI
uVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy
-----END RSA PRIVATE KEY-----
~~~

## PASETO v1 Test Vectors

### v1.local (Shared-Key Encryption) Test Vectors

#### Test Vector v1-E-1

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   00000000 00000000 00000000 00000000
         00000000 00000000 00000000 00000000
Payload: {"data":"this is a signed message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUV
         vn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcj
         d_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6go
         s8fnfjJO8oKiqQMaiBP_Cqncmqw8
~~~

#### Test Vector v1-E-2

Same as v1-E-1, but with a slightly different message.

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   00000000 00000000 00000000 00000000
         00000000 00000000 00000000 00000000
Payload: {"data":"this is a secret message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkR
         GlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m
         3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzk
         Mr1RvfDI8emoPoW83q4Q60_xpHaw
~~~

#### Test Vector v1-E-3

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   26f75533 54482a1d 91d47846 27854b8d
         a6b8042a 7966523c 2b404e8d bbe7f7f2
Payload: {"data":"this is a signed message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c
         v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs
         0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHe
         JUYk4IK_JEdUeo_uFRqAIgHsiGCg
~~~

#### Test Vector v1-E-4

Same as v1-E-3, but with a slightly different message.

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   26f75533 54482a1d 91d47846 27854b8d
         a6b8042a 7966523c 2b404e8d bbe7f7f2
Payload: {"data":"this is a secret message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb
         pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq
         GNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbH
         XUTWXchFEi0etJ4u6tqgxZSklcec
~~~

#### Test Vector v1-E-5

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   26f75533 54482a1d 91d47846 27854b8d
         a6b8042a 7966523c 2b404e8d bbe7f7f2
Payload: {"data":"this is a signed message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:  {"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}
Token:   v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c
         v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs
         0aFc3ejjOR mKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJ
         ZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRn
         A2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9
~~~

#### Test Vector v1-E-6

Same as v1-E-5, but with a slightly different message.

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   26f75533 54482a1d 91d47846 27854b8d
         a6b8042a 7966523c 2b404e8d bbe7f7f2
Payload: {"data":"this is a secret message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:  {"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}
Token:   v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb
         pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq
         GNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9
         v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA
         2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9
~~~

### v1.public (Public-Key Authentication) Test Vectors

#### Test Vector v1-S-1

~~~
Token:      v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw
            iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5k
            iAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEt
            m2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJ
            zVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96Sf
            Q6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1
            QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtp
            flZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw
Public Key: -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p
            5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd
            74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g
            mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU
            5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5
            IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc
            p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB
            -----END PUBLIC KEY-----
Payload:    {"data":"this is a secret message",
            "exp":"2019-01-01T00:00:00+00:00"}
Footer:
~~~

#### Test Vector v1-S-2

~~~
Token:      v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw
            iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4mis
            AuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X
            8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S
            1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthq
            az7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJM
            pixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C
            0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJ
            kWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVx
            biJ9
Public Key: -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p
            5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd
            74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g
            mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU
            5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5
            IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc
            p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB
            -----END PUBLIC KEY-----
Payload:    {"data":"this is a secret message",
            "exp":"2019-01-01T00:00:00+00:00"}
Footer:     {"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}
~~~

## PASETO v2 Test Vectors

### v2.local (Shared-Key Encryption) Test Vectors

#### Test Vector v2-E-1

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   00000000 00000000 00000000 00000000
         00000000 00000000
Payload: {"data":"this is a signed message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4Pn
         W8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVOD
         yfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ
~~~

#### Test Vector v2-E-2

Same as v2-E-1, but with a slightly different message.

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   00000000 00000000 00000000 00000000
         00000000 00000000
Payload: {"data":"this is a secret message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg
         3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7
         J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w
~~~

#### Test Vector v2-E-3

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   45742c97 6d684ff8 4ebdc0de 59809a97
         cda2f64c 84fda19b
Payload: {"data":"this is a signed message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb
         jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6
         Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA
~~~

#### Test Vector v2-E-4

Same as v2-E-3, but with a slightly different message.

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   45742c97 6d684ff8 4ebdc0de 59809a97
         cda2f64c 84fda19b
Payload: {"data":"this is a secret message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:
Token:   v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7
         cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr
         Iu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ
~~~

#### Test Vector v2-E-5

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   45742c97 6d684ff8 4ebdc0de 59809a97
         cda2f64c 84fda19b
Payload: {"data":"this is a signed message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:  {"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}
Token:   v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb
         jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6
         Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlm
         UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
~~~

#### Test Vector v2-E-6

Same as v2-E-5, but with a slightly different message.

~~~
Key:     70717273 74757677 78797a7b 7c7d7e7f
         80818283 84858687 88898a8b 8c8d8e8f
Nonce:   45742c97 6d684ff8 4ebdc0de 59809a97
         cda2f64c 84fda19b
Payload: {"data":"this is a secret message",
         "exp":"2019-01-01T00:00:00+00:00"}
Footer:  {"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}
Token:   v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7
         cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr
         Iu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlm
         UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
~~~

### v2.public (Public-Key Authentication) Test Vectors

#### Test Vector v2-S-1

~~~
Token:       v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi
             wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGnt
             Tu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_Dj
             JK2ZXC2SUYuOFM-Q_5Cw
Private Key: b4cbfb43 df4ce210 727d953e 4a713307
             fa19bb7d 9f850414 38d9e11b 942a3774
             1eb9dbbb bc047c03 fd70604e 0071f098
             7e16b28b 757225c1 1f00415d 0e20b1a2
Public Key:  1eb9dbbb bc047c03 fd70604e 0071f098
             7e16b28b 757225c1 1f00415d 0e20b1a2
Payload:     {"data":"this is a signed message",
             "exp":"2019-01-01T00:00:00+00:00"}
Footer:
~~~

#### Test Vector v2-S-2

~~~
Token:       v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi
             wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYC
             R0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601
             tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q
             3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
Private Key: b4cbfb43 df4ce210 727d953e 4a713307
             fa19bb7d 9f850414 38d9e11b 942a3774
             1eb9dbbb bc047c03 fd70604e 0071f098
             7e16b28b 757225c1 1f00415d 0e20b1a2
Public Key:  1eb9dbbb bc047c03 fd70604e 0071f098
             7e16b28b 757225c1 1f00415d 0e20b1a2
Payload:     {"data":"this is a signed message",
             "exp":"2019-01-01T00:00:00+00:00"}
Footer:      {"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}
~~~
