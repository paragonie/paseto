# PASETO: Platform-Agnostic Security Tokens

[![Build Status](https://github.com/paragonie/paseto/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/paseto/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/paseto/v/stable)](https://packagist.org/packages/paragonie/paseto)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/paseto/v/unstable)](https://packagist.org/packages/paragonie/paseto)
[![License](https://poser.pugx.org/paragonie/paseto/license)](https://packagist.org/packages/paragonie/paseto)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/paseto.svg)](https://packagist.org/packages/paragonie/paseto)

Paseto (pɔːsɛtəʊ, paw-set-oh) is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

This library is a reference implementation of PASETO in the PHP language.
Please refer to the [**PASETO Specification**](https://github.com/paseto-standard/paseto-spec)
for design considerations.

## How to Use this Library

See [the documentation](https://github.com/paragonie/paseto/tree/master/docs).

The [PASETO specification](https://github.com/paseto-standard/paseto-spec) may also be useful
for understanding why things are designed the way they are.

### PASETO Extensions

#### PASERK

For key wrapping, serialization, and canonical identification, please see the
[PHP implementation of PASERK](https://github.com/paragonie/paserk-php).

If you're not sure what that means, please refer to the
[PASERK specification](https://github.com/paseto-standard/paserk).

Since PASERK is a PASETO extension, PASERK support is not automatically included
with PASETO, but PASETO is bundled with PASERK.

### Requirements

#### PHP PASETO Library Version 3

* Requires PHP 8.1 or newer.
* For v3 tokens, the GMP and OpenSSL extensions are required.
* For v4 tokens, the Sodium extension is strongly recommended (but this library will use
  [sodium_compat](https://github.com/paragonie/sodium_compat) if it's not).
* PASETO Protocol versions: `v3`, `v4`

#### PHP PASETO Library Version 2

* Requires PHP 7.1 or newer.
* For v3 tokens, the GMP and OpenSSL extensions are required.
* For v4 tokens, the Sodium extension is strongly recommended (but this library will use
  [sodium_compat](https://github.com/paragonie/sodium_compat) if it's not).
* PASETO Protocol versions: `v1`, `v2`, `v3`, `v4`

#### PHP PASETO Library Version 1

* Requires PHP 7.0 or newer.
* For v1 tokens, the OpenSSL extension is required.
* For v2 tokens, the Sodium extension is strongly recommended (but this library will use
  [sodium_compat](https://github.com/paragonie/sodium_compat) if it's not).
* PASETO Protocol versions: `v1`, `v2`

## Support Contracts

If your company uses this library in their products or services, you may be
interested in [purchasing a support contract from Paragon Initiative Enterprises](https://paragonie.com/enterprise).
