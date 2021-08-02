# PASETO Features

PASETO is a security token format that uses protocol versioning instead of in-band
negotiation to provide maximum security but still allow seamless migrations.
As of this writing, there are [four Versions defined](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions#versions).

Within each **Protocol Version**, there are two types of tokens (one for each **Purpose**):

* `local` tokens are *encrypted* and intended for local systems, where the entities
  that can accept a token are also capable of creating tokens
* `public` tokens are *unencrypted* and intended for distributed systems, where the
  entity that can accept a token CANNOT mint a token that others accept

Some systems find "local" tokens appropriate, but do not wish to encrypt their claims.
For those systems, investigate whether the [optional footer](#optional-footer) is appropriate
for storing your claims.

Other systems find "public" tokens appropriate, but want to encrypt the token's
contents. For these systems, public-key encryption has been defined in a PASETO
extension called [PASERK](https://github.com/paseto-standard/paserk).

Since there are 4 versions of PASETO, and each version has 2 purposes available, that
means only 8 possible PASETOs can exist in the wild (where version and purpose are
joined by a period character).

* v1.local
* v1.public
* v2.local
* v2.public
* v3.local
* v3.public
* v4.local
* v4.public

By default, PASETO uses JSON for encoding claims. In the future, someone may define PASETO
with a different encoding schema. This will be registered as a unique identifier that is
suffixed to the version.

For example, PASETO over CBOR might be defined as `c`, yielding `v4c.local` and `v4c.public`
when used with Version 4. This will **NOT** change the underlying cryptography (beyond
the fact that the header is always authenticated, and the suffix exists in the header).

## Specifying Version and Purpose

In PASETO, the Version and Purpose are a part of the cryptographic material's identity 
(not just its raw bytes). That means that each key can be used with at most one of the
8 combinations of version and purpose.

The Builder and Parser features similarly expect a specific version and purpose to be
defined.

This can be visualized as follows:

```php
<?php
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\SymmetricKey;

$key = SymmetricKey::v4();
$builder = Builder::getLocal($key);
```

## Optional Footer

PASETO tokens typically have this format:

    [version].[purpose].[data]

However, it's possible to append optional data to the end of a PASETO, which will also be 
authenticated. This yields the following format:

    [version].[purpose].[data].[footer]

The PASETO spec imposes no restrictions on *what* goes into the footer, but the Builder and
Parser classes in this library assumes that you want to store arrays (which are encoded
as JSON strings).

```php
<?php
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\SymmetricKey;

/** @var SymmetricKey $key */
$builder = Builder::getLocal($key)
    ->setFooterArray([
        'foo' => 'bar'
    ]);
```

Because JSON stored in the footer is at risk of being decoded *before* the token has been
cryptographically verified, it's strongly recommended that you specify a FooterJSON rule
in your Parsers.

For example:

```php
<?php
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Rules\FooterJSON;

/** @var SymmetricKey $key */
$parser = Parser::getLocal($key)
    ->addRule(
        (new FooterJSON())
            ->setMaxLength(1024) // Maximum length of JSON payload in footer
            ->setMaxKeys(16)     // Maximum number of object keys
            ->setMaxDepth(3)     // Recursive depth to JSON structure
    );

/** @var string $untrusted */
$parsed = $parser->parse($untrusted);
```

## Implicit Assertions

**Implicit Assertions** (not available in Version 1 or 2) are authenticated like the optional
footer, but never stored in the PASETO token. [Read more here](https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md#implicit-assertions-feature).

You can set the implicit assertions in the Builder...

```php
<?php
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\SymmetricKey;

/** @var SymmetricKey $key */
$builder = Builder::getLocal($key)
    ->setImplicitAssertions([
        'customer-id' => 123456
    ]);
$token = $builder->toString();
```

...and then define them in the Parser:

```php
<?php
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Rules\FooterJSON;

/**
 * @var SymmetricKey $key
 * @var string $untrusted ($token from above snippet)
 */
$parser = Parser::getLocal($key)
    ->setImplicitAssertions([
        'customer-id' => 234567
    ]);
/* This will throw because customer-id is wrong. */
$parser->parse($untrusted);
```

And now your application is protected against [confused deputy attacks](https://cloud.google.com/kms/docs/additional-authenticated-data#confused_deputy_attack_example)
across different Customer IDs *without* disclosing said IDs to the user.
