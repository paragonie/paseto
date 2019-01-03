# PASETO: Platform-Agnostic Security Tokens

[![Build Status](https://travis-ci.org/paragonie/paseto.svg?branch=master)](https://travis-ci.org/paragonie/paseto)
[![Latest Stable Version](https://poser.pugx.org/paragonie/paseto/v/stable)](https://packagist.org/packages/paragonie/paseto)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/paseto/v/unstable)](https://packagist.org/packages/paragonie/paseto)
[![License](https://poser.pugx.org/paragonie/paseto/license)](https://packagist.org/packages/paragonie/paseto)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/paseto.svg)](https://packagist.org/packages/paragonie/paseto)

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

What follows is a reference implementation. **Requires PHP 7 or newer.**

# What is Paseto?

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation
for secure stateless tokens.

## Key Differences between Paseto and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, Paseto only allows secure operations. JWT gives you "algorithm agility",
Paseto gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use Paseto in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor Paseto were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> Paseto is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself.

### Paseto

#### Paseto Example 1

```
v2.local.QAxIpVe-ECVNI1z4xQbm_qQYomyT3h8FtV8bxkz8pBJWkT8f7HtlOpbroPDEZUKop_vaglyp76CzYy375cHmKCW8e1CCkV0Lflu4GTDyXMqQdpZMM1E6OaoQW27gaRSvWBrR3IgbFIa0AkuUFw.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz
```

This decodes to:

* Version: `v2`
* Purpose: `local` (shared-key authenticated encryption)
* Payload (hex-encoded):
  ```
  400c48a557be10254d235cf8c506e6fea418a26c93de1f05b55f1bc64cfca412
  56913f1fec7b653a96eba0f0c46542a8a7fbda825ca9efa0b3632dfbe5c1e628
  25bc7b5082915d0b7e5bb81930f25cca9076964c33513a39aa105b6ee06914af
  581ad1dc881b1486b4024b9417
  ```
  * Nonce: `400c48a557be10254d235cf8c506e6fea418a26c93de1f05`
  * Authentication tag: `6914af581ad1dc881b1486b4024b9417`
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
v2.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZGF0YSI6InRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSJ91gC7-jCWsN3mv4uJaZxZp0btLJgcyVwL-svJD7f4IHyGteKe3HTLjHYTGHI1MtCqJ-ESDLNoE7otkIzamFskCA
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
  d600bbfa3096b0dde6bf8b89699c59a746ed2c981cc95c0bfacbc90fb7f8207c
  86b5e29edc74cb8c761318723532d0aa27e1120cb36813ba2d908cda985b2408
  ```
* Public key (hex-encoded):
  ```
  11324397f535562178d53ff538e49d5a162242970556b4edd950c87c7d86648a
  ```

To learn what each version means, please see [this page in the documentation](https://github.com/paragonie/paseto/tree/master/docs/01-Protocol-Versions).

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

* `local` -- shared-key encryption (symmetric-key, [AEAD](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken))
* `public` -- public-key digital signatures (asymmetric-key)

Paseto only allows you to use [authenticated modes](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken).

Regardless of the purpose selected, the header (and an optional footer, which is always
cleartext but base64url-encoded) is included in the signature or authentication tag.

## How to Use this Library

See [the documentation](https://github.com/paragonie/paseto/tree/master/docs).

The section dedicated to [this PHP implementation](https://github.com/paragonie/paseto/tree/master/docs/02-PHP-Library)
may be more relevant.

## Other Implementations

The curation of other implementations has been moved to [paseto.io](https://paseto.io).
See https://github.com/paragonie/paseto-io for the website source code.

## Support Contracts

If your company uses this library in their products or services, you may be
interested in [purchasing a support contract from Paragon Initiative Enterprises](https://paragonie.com/enterprise).
