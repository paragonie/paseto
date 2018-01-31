# PASETO: Platform-Agnostic SEcurity TOkens

[![Build Status](https://travis-ci.org/paragonie/past.svg?branch=master)](https://travis-ci.org/paragonie/past)
[![Latest Stable Version](https://poser.pugx.org/paragonie/past/v/stable)](https://packagist.org/packages/paragonie/past)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/past/v/unstable)](https://packagist.org/packages/paragonie/past)
[![License](https://poser.pugx.org/paragonie/past/license)](https://packagist.org/packages/paragonie/past)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/past.svg)](https://packagist.org/packages/paragonie/past)

PAST is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

What follows is a reference implementation. **Requires PHP 7 or newer.**

# What is Paseto?

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation
for secure stateless tokens.

## Key Differences between Paseto and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, Paseto only allows secure operations. JWT gives you "algorithm agility",
PAST gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use PAST in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor PAST were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> PAST is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself.

### Pasteo

#### Paseto Example 1

```
v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz
```

This decodes to:

* Version: `v2`
* Purpose: `local` (shared-key authenticated encryption)
* Payload (hex-encoded):
  ```
  942961cd53aeb1e09661ea78e2a6c0f2b997af2eba954ba9c843628d7dfbfc8f
  f3df81223a57f2bb0a882213a317e7bd9b627e42cd7b1acf81a63a4b961df37f
  e277ee7ed8187a8c055e86e710f669e20aa5c93aae17f01e9185dfc2fbaf262e
  cee51eaa63e0f17a3349f5383ee3e9f68f
  ```
  * Nonce: `942961cd53aeb1e09661ea78e2a6c0f2b997af2eba954ba9`
  * Authentication tag: `e51eaa63e0f17a3349f5383ee3e9f68f`
* Decrypted Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00+00:00"
  }
  ```
  * Key used in this example (hex-encoded):
    ```
    707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f  
    ``` 
* Footer:
  ```
  Paragon Initiative Enterprises
  ```

#### Paseto Example 2

```
v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz
```

This decodes to:

* Version: `v2`
* Purpose: `public` (public-key digital signature)
* Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00+00:00"
  }
  ```
* Signature (hex-encoded):
  ```
  70c623a1468461702dcd30f095c3a5c5d719588669f2a6606b78c54bc2707448
  c4beead986ce809935376d15b9a41f5f390c26e37af39a26d95dc02443803342
  ```

To learn what each version means, please see [this page in the documentation](https://github.com/paragonie/past/tree/master/docs/01-Protocol-Versions).

### JWT

An example JWT ([taken from JWT.io](https://jwt.io)) might look like this:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ 
```

This decodes to:

**Header**:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Body**:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

**Signature**:  
```
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

## Motivation 

As you can see, with JWT, you get to specify an `alg` header. There are a lot of options to
choose from (including `none`).

There have been ways to exploit JWT libraries by replacing RS256 with HS256 and using
the known public key as the HMAC-SHA256 key, thereby allowing arbitrary token forgery. 

With Paseto, your options are `version` and a `purpose`. There are two possible
values for `purpose`:

* `local` -- shared-key authenticated encrypted
* `public` -- public-key authentication (a.k.a. digital signatures)

Paseto only allows you to use [authenticated modes](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken).

Regardless of the purpose selected, the header (and an optional footer, which is always
cleartext but base64url-encoded) is included in the signature or authentication tag.

## How to Use this Library

See [the documentation](https://github.com/paragonie/paseto/tree/master/docs).

The section dedicated to [this PHP implementation](https://github.com/paragonie/paseto/tree/master/docs/02-PHP-Library)
may be more relevant.
