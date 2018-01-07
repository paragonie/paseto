# PAST: Platform-Agnostic Security Tokens

[![Build Status](https://travis-ci.org/paragonie/past.svg?branch=master)](https://travis-ci.org/paragonie/past)
[![Latest Stable Version](https://poser.pugx.org/paragonie/past/v/stable)](https://packagist.org/packages/paragonie/past)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/past/v/unstable)](https://packagist.org/packages/paragonie/past)
[![License](https://poser.pugx.org/paragonie/past/license)](https://packagist.org/packages/paragonie/past)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/past.svg)](https://packagist.org/packages/paragonie/past)

PAST is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

What follows is a reference implementation. **Requires PHP 7 or newer.**

# What is PAST?

PAST (Platform-Agnostic Security Tokens) is a specification and reference implementation
for secure stateless tokens.

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, PAST only allows secure operations. JWT gives you "algorithm agility",
PAST gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use PAST in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries). 

## Key Differences between PAST and JWT

### PAST

```
v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDAifSP9sWhZXlg_XlJk9EKntAK2C3GQ8KvT464avRt3tUlVglkyvKUpSMvER0DO708rdLGg0ZJPhAKU_7TPzAcisww.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz
```

This decodes to:

* Version: `v2`
* Purpose: `public` (public-key digital signature)
* Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00"
  }
  ```
* Signature (hex-encoded):
  ```
  23fdb168595e583f5e5264f442a7b402b60b7190f0abd3e3ae1abd1b77b54955
  825932bca52948cbc44740ceef4f2b74b1a0d1924f840294ffb4cfcc0722b30c
  ```
* Footer:
  ```
  Paragon Initiative Enterprises
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

With PAST, your options are `version` and a `purpose`. There are two possible
values for `purpose`:

* `local` -- shared-key authenticated encrypted
* `public` -- public-key authentication (a.k.a. digital signatures)

PAST only allows you to use [authenticated modes](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken).

Regardless of the purpose selected, the header (and an optional footer, which is always
cleartext but base64url-encoded) is included in the signature or authentication tag.

## How to Use this Library

See [the documentation](https://github.com/paragonie/past/tree/master/docs).

The section dedicated to [this PHP implementation](https://github.com/paragonie/past/tree/master/docs/02-PHP-Library)
may be more relevant.
