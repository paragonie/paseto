# Implementation Details

## Paseto Message Format:

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
   [our standard format](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding).

Thus, if you want unencrypted, but authenticated, tokens, you can simply set your payload
to an empty string and your footer to the message you want to authenticate.

## Versions and their Respective Purposes

See [Protocol Versions](01-Protocol-Versions) for specifics.

## How to use the Reference Implementation

See [the PHP library documentation](https://github.com/paragonie/paseto/blob/master/docs/02-PHP-Library).

## What are Paseto's design goals?

### 1. Resistance to Implementation Error / Misuse

While it will be possible for motivated developers to discover novel ways to
make any tool insecure, Paseto attempts to make it easier to develop secure
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
to, intuitively, use Paseto in their software with minimal friction.

Additionally, developers who are not already familiar with JWT should be able
to pick up Paseto and use it successfully without introducing security flaws
into their application.

## Was "Stateless Session Tokens" one of Paseto's Design Goals?

No, neither Paseto nor JWT were designed for
[stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/),
which is largely an anti-pattern.
