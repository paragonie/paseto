# Implementation Details

## PAST Message Format:

### Without the Optional Footer

```
version.purpose.payload.footer
```

The `version` is a string that represents the current version of the protocol. Currently,
two versions are specified, which each possess their own ciphersuites. Accepted values:
`v1`, `v2`.

The `purpose` is a short string describing the purpose of the token. Accepted values:
`local`, `public`.

* `local`: shared-key authenticated encryption
* `public`: public-key digital signatures; **not encrypted**

Any optional data can be appended to the end. This information is NOT encrypted, but it
is used in calculating the authentication tag for the payload. It's always base64url-encoded.

 * For local tokens, it's included in the associated data alongside the nonce.
 * For public tokens, it's appended to the message during the actual
   authentication/signing step, in accordance to
   [our standard format](https://github.com/paragonie/past/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding).

Thus, if you want unencrypted, but authenticated, tokens, you can simply set your payload
to an empty string and your footer to the message you want to authenticate.

## Versions and their Respective Purposes

See [Protocol Versions](01-Protocol-Versions) for specifics.

## How to use the Reference Implementation

See [the PHP library documentation](https://github.com/paragonie/past/blob/master/docs/02-PHP-Library).

## What are PAST's design goals?

### 1. Resistance to Implementation Error / Misuse

While it will be possible for motivated developers to discover novel ways to
make any tool insecure, PAST attempts to make it easier to develop secure
implementations than to develop insecure implementations of the standard.

To accomplish this goal, we cast aside runtime protocol negotiation and
so-called "algorithm agility" in favor of pre-negotiated protocols with
version identifiers.

For `local` tokens, we encrypt them exclusively using authenticated encryption
with additional data (AEAD) modes that are also nonce-misuse resistant (NMR).
This means even if implementations fail to use a secure random number generator
for the large nonces, message confidentiality isn't imperiled.

### 2. Usability

Developers who are already familiar with JSON Web Tokens (JWT) should be able
to, intuitively, use PAST in their software with minimal friction.

Additionally, developers who are not already familiar with JWT should be able
to pick up PAST and use it successfully without introducing security flaws
into their application.

### 3. Flexibility

Although our library aims to maximize JWT compatibility, out cryptography
protocols operate over binary strings rather than JSON objects, thereby
allowing PAST to be used with other serialization standards.

To define these other wire formats, the name of the encoding should be
suffixed:

* **PAST-JSON** is the default format for payload serialization
* **PAST-Protobuf** means PAST cryptography using Protobuf serialization
* **PAST-Raw** uses the cryptography features directly over raw strings
* **PAST-XML** means PAST cryptography using XML serialization

## Was "Stateless Session Tokens" one of PAST's Design Goals?

No, neither PAST nor JWT were designed for
[stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/),
which is largely an anti-pattern. 

## How should we pronounce PAST?

Like the English word "pasta" without the final "a". It rhymes with "frost"
and the first syllable in "roster".

Pronouncing it like the English word "past" is acceptable, but
politely discouraged.

Implementations in other languages are encouraged, but not required,
to make pasta puns in their naming convention.
