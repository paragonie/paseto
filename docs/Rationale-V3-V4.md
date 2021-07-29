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
be adequately served by RSA signatures. This assumption turned out to be
incorrect, and elliptic curve cryptography is now preferred.

To better meet the needs of applications that are NIST-dependent, PASETO
v3.public tokens will support ECDSA over NIST's P-384 curve, with SHA-384,
and (preferably) using RFC 6979 deterministic signatures. (RFC 6979 is a
**SHOULD**, not a **MUST**, due to library availability issues and
[fault attacks](https://eprint.iacr.org/2017/1014).)

#### ECDSA Security

ECDSA is much more dangerous to implement than Ed25519:

1. You have to ensure the one-time secret `k` is never reused for different
   messages, or you leak your secret key.
2. If you're not generating `k` deterministically, you have to take extra
   care to ensure your random number generator isn't biased. If you fail
   to ensure this, attackers can determine your secret key through
   [lattice attacks](https://eprint.iacr.org/2019/023).
3. The computing `k^-1 (mod p)` must be constant-time to avoid leaking `k`.
    * Most bignum libraries **DO NOT** provide a constant-time modular
      inverse function, but cryptography libraries often do. This is something
      a security auditor will need to verify for each implementation.

There are additional worries with ECDSA [with different curves](https://safecurves.cr.yp.to/),
but we side-step most of these problems by hard-coding *one* NIST curve and
refusing to support any others. The outstanding problems are:

* The NIST curve P-384 [is not rigid](https://safecurves.cr.yp.to/rigid.html).
    * If you're concerned about NSA backdoors, don't use v3 (which only uses
      NIST-approved algorithms). Use v4 instead.
* Weierstrass curves (such as P-384) historically did not use a
  [constant-time ladder](https://safecurves.cr.yp.to/ladder.html) or offer
  [complete addition formulas](https://safecurves.cr.yp.to/complete.html).
    * This is more of a problem for ECDH than ECDSA.
    * [Complete addition formulas for P-384 exist](https://eprint.iacr.org/2015/1060).

There are additional protocol-level security concerns for ECDSA, namely:

* Invalid Curve Attacks, which are known to break ECDH.
    * This is solved in PASETO through requiring support for
      [Point Compression](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf).
    * Implementations **MAY** also optionally support PEM encoding of
      uncompressed public key points, but if they do, they **MUST** validate
      that the public key is a point on the curve.
    * Point compression used to be patented, but it expired. It's high time
      we stopped avoiding its usage as an industry.
* Exclusive Ownership. [See below.](#v3-signatures-prove-exclusive-ownership-enhancement)

Because of these concerns, we previously forbid any implementation of ECDSA
*without* RFC 6979 deterministic k-values in a future version.

However, given the real-world requirements of applications and systems that
must comply with NIST guidance on cryptography algorithms, we've relaxed this
requirement.

Additionally, deterministic k-values make signers more susceptible to fault
attacks than randomized signatures. If you're implementing PASETO signing in
embedded devices, or environments where fault injection may be a practical
risk, there are two things you can do:

1. Don't use deterministic signatures because of your specific threat model.
2. Hedged signatures: Inject additional randomness into the RFC 6979 step.
   This randomness doesn't need to be signed.

#### Questions For Security Auditors

Due to the risks inherent to ECDSA, security assessors should take care to
cover the following questions in any review of a PASETO implementation that
supports `v3.public` tokens (in addition to their own investigations).

1. Is RFC 6979 supported and used by the implementation?
    1. If not, is a cryptographically secure random number generator used?
    2. If the answer to both questions is "No", fail.
2. Is modular inversion (`k^-1 (mod p)`) constant-time?
    1. If not, fail.
3. Are public keys expressed as compressed points?
    1. If not, is the public key explicitly validated to be on the correct
       curve (P-384)?
    2. If the answer to both questions is "No", fail.
4. Does the underlying cryptography library use complete addition formulas
   for NIST P-384?
    1. If not, investigate how the library ensures that scalar multiplication
       is constant-time. (This affects the security of key generation.)

Affirmative answers to these questions should provide assurance that the
ECDSA implementation is safe to use with P-384, and security auditors can
focus their attention on other topics of interest.

### v3.local / v4.public

No specific changes were needed from (v1.local, v2.public) respectively.
See below for some broader changes.

## Beneficial Changes to V3/V4

### No More Nonce-Hashing (Change)

The initial motivation for hashing the random nonce with the message was
to create an SIV-like construction to mitigate the consequences of weak
random number generators, such as OpenSSL's (which isn't
[fork-safe](https://github.com/ramsey/uuid/issues/80)).

However, this creates an unfortunate failure mode: If your RNG fails,
the resultant nonce is a hash of your message, which can be used to
perform offline attacks on the plaintext. This was first discovered by
[Thái Dương](https://twitter.com/XorNinja/status/1157882553610563585).

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
and v4.local, we now use the entire 32-byte random value in the HKDF step.

Instead of being used as a salt, however, it will be appended to the info tag.
This subtle change allows us to use the 
[standard security definition for HKDF](https://eprint.iacr.org/2010/264)
in arguments for PASETO's security, rather than treating it as just a
pseudo-random function (PRF). This security definition requires only one salt
to be used, but for many contexts (info tags).

The nonce used by AES-256-CTR and XChaCha20 will be derived from the HKDF output
(which is now 48 bytes for v3.local and 56 bytes for v4.local). The first 32
bytes of each HKDF output will be used as the key. The remaining bytes will be 
used as the nonce for the underlying cipher.

Local PASETOs in v3 and v4 will always have a predictable storage size, and the
security of these constructions is more obvious:

* The probability space for either mode is 256-bits of randomness + 256-bits of
  key, for a total of 512 bits.
    * The HKDF output in v3.local is 384 bits.
    * The HKDF output in v4.local is 448 bits.
    * Neither of these output sizes reduces the security against collisions.
      (If they were larger than the input domain of 512 bits, that would be a
      blunder.)
* A single key can be used for 2^112 PASETOs before rotation is necessary.
    * The birthday bound for a 256-bit salt is 2^128 (for a 50% chance of
      a single collision occurring). Setting the safety threshold to 2^-32
      (which is roughly a 1 in 4 billion chance) for a space of 2^256
      yields 2^112.
* The actual nonce passed to AES-CTR and XChaCha is not revealed publicly.

### V3 Signatures Prove Exclusive Ownership (Enhancement)

RSA and ECDSA signatures [do not prove Exclusive Ownership](http://www.bolet.org/~pornin/2005-acns-pornin+stern.pdf).
This is almost never a problem for most protocols, unless you *expect* this property
to hold when it doesn't.

Section 3.3 of the paper linked above describes how to achieve Universal Exclusive
Ownership (UEO) without increasing the signature size: Always include the public
key in the message that's being signed.

Consequently, `v3.public` PASETOs will include the raw bytes of the public
key in the PAE step for calculating signatures. The public key is always a
compressed point (`0x02` or `0x03`, followed by the X coordinate, for a total
of 49 bytes).

We decided to use point compression in the construction of the tokens as a
forcing function so that all PASETO implementations support compressed points
(and don't just phone it in with PEM-encoded uncompressed points).

[Ed25519, by design, does not suffer from this](https://eprint.iacr.org/2020/823),
since Ed25519 already includes public key with the hash function when signing
messages. Therefore, we can safely omit this extra step in `v4.public` tokens.

## Miscellaneous Changes

### Define Mechanism for Extending PASETO for non-JSON Encodings

PASETO serializes its payload as a JSON string. Future documents **MAY** specify using
PASETO with non-JSON encoding. When this happens, a suffix will be appended to the version tag
when a non-JSON encoding rule is used.

> For example, a future PASETO-CBOR proposal might define its versions as `v1c`, `v2c`, `v3c`,
> and `v4c`. The underlying cryptography will be the same as `v1`, `v2`, `v3`, and `v4`
> respectively. Keys **SHOULD** be portable across different underlying encodings, but tokens
> **MUST NOT** be transmutable between encodings without access to the symmetric key (`local` tokens)
> or secret key (`public` tokens).

## Questions and Answers

### Why Not AES-GCM in `v3.local`?

While it's true that AES-GCM is more broadly supported in environments that use
NIST and FIPS-approved cryptography, GMAC is neither
[message-committing nor key-committing](https://eprint.iacr.org/2019/016).

The techniques for turning an AEAD scheme into an AEAD scheme [is well known](https://eprint.iacr.org/2020/1153),
but it requires publishing an additional SHA2 hash (or KDF output) of the
key being used.

Using GCM would require us to also publish an additional hash *anyway*. At
that point, it doesn't offer any clear advantage over CTR+HMAC.

CTR+HMAC (with separate keys and PAE) is a secure construction and provides
the cryptographic properties we need to use PASETO in threat models where
multiple keys are used or [partitioning oracles](https://eprint.iacr.org/2020/1491)
are possible.

### Why P-384 in `v3.public` instead of P-256 or P-521?

Security experts that work heavily with NIST algorithms expressed a
slight preference for P-384 over P-521 and P-256 when we asked. This is also
congruent for our choice of SHA-384 as a hash function over SHA-256 or SHA-512.

The [security considerations](#ecdsa-security) for the NIST curves are mostly
congruent (albeit the ECDLP security and performance differs a bit).

If you want smaller tokens or better performance than P-384, make sure Ed25519
lands in FIPS 186-5 and use `v4.public` instead.
