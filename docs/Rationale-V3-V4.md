# Rationale for V3/V4

This document aims to capture the rationale for specifying new modes
(v3 to succeed v1, v4 to succeed v2) for PASETO.

## Primary Motivations for New Versions

### v4.local

v2.local was originally specified to use XChaCha20-Poly1305, a boring
AEAD mode that's obviously secure. However, we've since learned about
key- and message-commitment, which is an important security property 
in systems with multiple possible symmetric keys.

Since PASETO added footers to support key-ids and key rotation
strategies, this means we MUST take attacks that depend on 
[random-key robustness](https://eprint.iacr.org/2020/1491) seriously.

PASETO v4.local uses XChaCha20 to encrypt the message, but then uses
a keyed BLAKE2b hash (which acts as HMAC) for the authentication tag.

### v3.public

We specified RSA for PASETO v1.public tokens, under the assumption that
applications that must ONLY support NIST algorithms (e.g. because they
MUST only use FIPS 140-2 validated modules to maintain compliance) would
be adequately served by RSA signatures.

To better meet the needs of applications that are NIST-dependent, PASETO
v3.public tokens will support ECDSA over NIST's P-384 curve, with SHA-384,
and RFC 6979 deterministic signatures.

### v3.local / v4.public

No specific changes were needed from (v1.local, v2.public) respectively.
See below for some broader changes.

## Beneficial Changes to V3/V4

### No More Nonce-Hashing (Change)

The initial motivation for hashing the random nonce with the message was
to create an SIV-like construction to mitigate the consequences of weak
random number generators, such as OpenSSL's (which isn't fork-safe).

However, this creates an unfortunate failure mode: If your RNG fails,
the resultant nonce is a hash of your message, which can be used to
perform offline attacks on the plaintext.

To avoid this failure mode, neither v3.local nor v4.local will pre-hash 
the message and random value to derive a nonce. Instead, it will trust
the CSPRNG to be secure.

### Implicit Assertions (Feature)

PASETO v3 and v4 tokens will support optional additional authenticated
data that **IS NOT** stored in the token, but **IS USED** to calculate the
authentication tag (local) or signature (public).

These are called **implicit assertions**. These can be any application-specific
data that must be provided when validating tokens, but isn't appropriate to
store in the token itself (e.g. sensitive internal values).

One example where implicit assertions might be desirable is ensuring that a PASETO
is only used by a specific user in a multi-tenant system. Simply providing the
user's account ID when minting and consuming PASETOs will bind the token to the
desired context.

### Better Use of HKDF Salts (Change)

With v1.local, half of the 32-byte random value was used as an HKDF salt and
half was used as an AES-CTR nonce. This is tricky to analyze and didn't extend
well for the v4.local proposal.

For the sake of consistency and easy-to-analyze security designs, in both v3.local
and v4.local, we now use the entire 32-byte salt in the HKDF step. The nonce
used by AES-256-CTR and XChaCha20 will be derived from the HKDF output (which
is now 48 bytes for v3.local and 56 bytes for v4.local).

Local PASETOs in v3 and v4 will always have a predictable storage size, and the
security of these constructions is more obvious:

* The probability space for either mode is 256-bits of salt + 256-bits of key,
  for a total of 512 bits.
  * The HKDF output in v3.local is 384 bits.
  * The HKDF output in v4.local is 448 bits.
  * Neither of these output sizes reduces the security against collisions.
* A single key can be used for 2^112 PASETOs before rotation is necessary.
* The actual nonce passed to AES-CTR and XChaCha is not revealed publicly.
