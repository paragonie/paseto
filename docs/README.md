# Implementation Details

## Paseto Message Format:

### Without the Optional Footer

```
version.purpose.payload
```

### With the Optional Footer

```
version.purpose.payload.footer
```

The `version` is a string that represents the current version of the protocol. Currently,
two versions are specified, which each possess their own ciphersuites. Accepted values:
`v1`, `v2`, `v3`, `v4`.

PASETO serializes its payload as a JSON string. Future documents **MAY** specify using 
PASETO with non-JSON encoding. When this happens, a suffix will be appended to the version tag
when a non-JSON encoding rule is used.

> For example, a future PASETO-CBOR proposal might define its versions as `v1c`, `v2c`, `v3c`,
> and `v4c`. The underlying cryptography will be the same as `v1`, `v2`, `v3`, and `v4`
> respectively. Keys **SHOULD** be portable across different underlying encodings, but tokens
> **MUST NOT** be transmutable between encodings without access to the symmetric key (`local` tokens)
> or secret key (`public` tokens).

The `purpose` is a short string describing the purpose of the token. Accepted values:
`local`, `public`.

* `local`: shared-key authenticated encryption
* `public`: public-key digital signatures; **not encrypted**

#### Versions 3 and 4

In versions 3 and 4, if the `footer` is non-empty, it **MUST** be valid JSON string.

If you wish to use Versions 3 or 4 with arbitrary data, it **MUST** be serialized into
a JSON string and its value **SHOULD** be base64url-encoded.

#### Versions 1 and 2

In versions 1 and 2, any optional data can be appended to the end. 
This information is NOT encrypted, but it is used in calculating the authentication tag
for the payload. It's always base64url-encoded.

 * For local tokens, it's included in the associated data alongside the nonce.
 * For public tokens, it's appended to the message during the actual
   authentication/signing step, in accordance to
   [our standard format](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding).

Thus, if you want unencrypted, but authenticated, tokens, you can simply set your payload
to an empty string, then your footer to the message you want to authenticate, and use a
local token.

Conversely, if you want to support key rotation, you can use the unencrypted footer to store
the Key-ID.

If you want public-key encryption, check out [PASERK](https://github.com/paseto-standard/paserk).

### Implicit Assertions

PASETO `v3` and `v4` tokens support a feature called **implicit assertions**, which are used
in the calculation of the MAC (`local` tokens) or digital signature (`public` tokens), but
**NOT** stored in the token. (Thus, its implicitness.)

An implicit assertion MUST be provided by the caller explicitly when validating a PASETO token
if it was provided at the time of creation.

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
with additional data (AEAD) modes.

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

There is no built-in mechanism to defeat replay attacks within the validity
window, should a token become compromised, without server-side persistent
data storage.

Therefore, neither PASETO nor JWT should be used in any attempt to obviate the
need for server-side persistent data storage. 

### What Should We Use PASETO For?

Some example use-cases:

1. (`local`): Tamper-proof, short-lived immutable data stored on client machines.
   * e.g. "remember me on this computer" cookies, which secure a unique ID that
     are used in a database lookup upon successful validation to provide long-term
     user authentication across multiple browsing sessions.
2. (`public`): Transparent claims provided by a third party.
   * e.g. Authentication and authorization protocols (OAuth 2, OIDC).

## Does PASETO Guarantee the Order of Keys in Its Payload?

**No.** Consistently guaranteeing a given order to a deserialized JSON string is
nontrivial across programming languages. You should not rely on this ordering behavior
when using PASETO.

Although ordering is not guaranteed, the contents will be cryptographically verified,
and the thing that gets authenticated is a JSON string, not a deserialized object, so
this non-guarantee will not affect the security of the token.
