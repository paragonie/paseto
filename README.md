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

## Key Differences between PAST and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, PAST only allows secure operations. JWT gives you "algorithm agility",
PAST gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use PAST in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor PAST were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/). 

### PAST

#### PAST Example 1

```
v2.local.wvbu1sWg-Td2nDxn7vyAVAEzTGqtzn_zfzaiGjAkQzfa5-l2PaAK1QA0IZjrWdKP8Xqi7DHHlu6F8E5BXoarTSfmrgkMEOeiasRhuZ3GWDUtmD2K027gjgalkjMZJE7lNfkOSdKr65Fo0_8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz
```

This decodes to:

* Version: `v2`
* Purpose: `local` (shared-key authenticated encryption)
* Payload (hex-encoded):
  ```
  c2f6eed6c5a0f937769c3c67eefc805401334c6aadce7ff37f36a21a30244337
  dae7e9763da00ad500342198eb59d28ff17aa2ec31c796ee85f04e415e86ab4d
  27e6ae090c10e7a26ac461b99dc658352d983d8ad36ee08e06a5923319244ee5
  35f90e49d2abeb9168d3ff
  ```
  * Nonce: `c2f6eed6c5a0f937769c3c67eefc805401334c6aadce7ff3`
  * Authentication tag: `3319244ee535f90e49d2abeb9168d3ff`
* Decrypted Payload:
  ```json
  {
    "data": "this is a signed message",
    "exp": "2039-01-01T00:00:00"
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

#### PAST Example 2

```
v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDAifTFKh7pKx_o_cq9RP2a0imXCEB8LSq5E3675v0IbDM0-pGg8pymrySBVEM_JUCj6WwB7cdsZIE0-F3cHnnFpRQU
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
  314a87ba4ac7fa3f72af513f66b48a65c2101f0b4aae44dfaef9bf421b0ccd3e
  a4683ca729abc9205510cfc95028fa5b007b71db19204d3e1777079e71694505
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
