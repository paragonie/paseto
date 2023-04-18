# PASETO (PHP) Documentation

If you're not already familiar with PASETO, you can learn more about its features
[here](Features.md). If you were using an older version of PASETO, the
[migration guide](Migration.md) is worth a read. 

Most of the supporting documentation has been moved to the 
[PASETO specification](https://github.com/paseto-standard/paseto-spec) repository.

## How to use the PHP library

The first thing you should know about this library is it tries to accomplish
type-safety by wrapping cryptographic keys inside of objects. For example:

```php
<?php
use ParagonIE\Paseto\Keys\{Base\AsymmetricSecretKey,Base\SymmetricKey};

$privateKey = new AsymmetricSecretKey(sodium_crypto_sign_keypair());
$publicKey = $privateKey->getPublicKey();

$sharedKey = new SymmetricKey(random_bytes(32));
```

You can access the key's internal strings by invoking `$key->raw()`.

## Storing asymmetric keys

If you need to store the keys on your server, you can encode/decode the key.

```php
<?php
use ParagonIE\Paseto\Keys\Base\{AsymmetricPublicKey, AsymmetricSecretKey};

$privateKey = new AsymmetricSecretKey(sodium_crypto_sign_keypair());
$publicKey = $privateKey->getPublicKey();

$privateKeyEncoded = $privateKey->encode();
$publicKeyEncoded = $publicKey->encode();

$privateKeyDecoded = AsymmetricSecretKey::fromEncodedString($privateKeyEncoded);
$publicKeyDecoded = AsymmetricPublicKey::fromEncodedString($publicKeyEncoded);
```

Or export as PEM format, and reimport from PEM.

```php
<?php
use ParagonIE\Paseto\Keys\Base\{AsymmetricPublicKey, AsymmetricSecretKey};

$privateKey = new AsymmetricSecretKey(sodium_crypto_sign_keypair());
$publicKey = $privateKey->getPublicKey();

$privateKeyEncoded = $privateKey->encodePem();
$publicKeyEncoded = $publicKey->encodePem();

$privateKeyDecoded = AsymmetricSecretKey::importPem($privateKeyEncoded);
$publicKeyDecoded = AsymmetricPublicKey::importPem($publicKeyEncoded);
```

No version of the protocol will let you misuse a key by accident.
This will generate a `TypeError`:

```php
<?php
use ParagonIE\Paseto\Keys\Base\SymmetricKey;use ParagonIE\Paseto\Protocol\Version4;

/**
 * We assume the same key $sharedKey was used from above.
 * @var SymmetricKey $sharedKey
 */
 
$token = Version4::sign('some arbitrary data', $sharedKey);
```

## Building and Verifying Pasetos

The simplest use-case is to use shared-key authentication
to achieve tamper-resistant tokens:

```php
<?php
use ParagonIE\Paseto\Builder;use ParagonIE\Paseto\Keys\Base\SymmetricKey;use ParagonIE\Paseto\Protocol\Version4;use ParagonIE\Paseto\Purpose;

/**
 * We assume the same key $sharedKey was used from above.
 * @var SymmetricKey $sharedKey
 */
$token = Builder::getLocal($sharedKey, new Version4);

$token = (new Builder())
    ->setKey($sharedKey)
    ->setVersion(new Version4)
    ->setPurpose(Purpose::local())
    // Set it to expire in one day
    ->setIssuedAt()
    ->setNotBefore()
    ->setExpiration(
        (new DateTime())->add(new DateInterval('P01D'))
    )
    // Store arbitrary data
    ->setClaims([
        'example' => 'Hello world',
        'security' => 'Now as easy as PIE'
    ]);
echo $token; // Converts automatically to a string
```

### Decoding tokens

First, you need to define your `Parser` rules.

* Which versions of the protocol do you wish to allow? If you're only
  using v2 in your app, you should specify this.

```php
<?php
use ParagonIE\Paseto\Exception\PasetoException;use ParagonIE\Paseto\JsonToken;use ParagonIE\Paseto\Keys\Base\SymmetricKey;use ParagonIE\Paseto\Parser;use ParagonIE\Paseto\ProtocolCollection;use ParagonIE\Paseto\Purpose;use ParagonIE\Paseto\Rules\{IssuedBy,ValidAt};

/**
 * We assume the same key $sharedKey was used from above.
 * $providedToken is $token (as a string) from the previous snippet.
 *
 * @var string $providedToken
 * @var SymmetricKey $sharedKey
 */
$parser = Parser::getLocal($sharedKey, ProtocolCollection::v4())
    ->addRule(new ValidAt)
    ->addRule(new IssuedBy('issuer defined during creation'));

// This is the same as:
$parser = (new Parser())
    ->setKey($sharedKey)
    // Adding rules to be checked against the token
    ->addRule(new ValidAt)
    ->addRule(new IssuedBy('issuer defined during creation'))
    ->setPurpose(Purpose::local())
    // Only allow version 4
    ->setAllowedVersions(ProtocolCollection::v4());

try {
    $token = $parser->parse($providedToken);
} catch (PasetoException $ex) {
    /* Handle invalid token cases here. */
}
var_dump($token instanceof JsonToken);
// bool(true)
```

## Key Rings

A key ring is a set of named cryptographic keys.

> Support for key rings is **totally optional.** If you don't need them, don't build support for them
in your application. If you do need support for them, we've provided a first-class implementation.

Key rings are useful for integrating with multiple third-party identity providers, or adding
mechanisms to enforce key-rotation with a window of overlap between two keys.

Here's an example:

```php
<?php
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey;use ParagonIE\Paseto\Keys\Base\SymmetricKey;use ParagonIE\Paseto\Protocol\Version4;use ParagonIE\Paseto\Purpose;use ParagonIE\Paseto\ReceivingKeyRing;

/**
 * @var SymmetricKey $localKey
 * @var AsymmetricPublicKey $pk1
 * @var AsymmetricPublicKey $pk2
 */
$keyring = (new ReceivingKeyRing())
    ->setVersion(new Version4)
    ->setPurpose(Purpose::public())
    ->addKey('gandalf0', $pk1)
    ->addKey('legolas1', $pk2);

$otherKeyring = (new ReceivingKeyRing())
    ->setVersion(new Version4)
    ->setPurpose(Purpose::local())
    ->addKey('boromir2', $localKey);
```

As you can see, each `KeyRing` object can be locked down to a given version and purpose.
If you try to add an `AsymmetricPublicKey` to `$otherKeyring`, it will throw an exception.

```
$otherKeyring->addKey('gandalf0', $pk1); // throws
```

There is also a `SendingKeyRing` class, which behaves mostly the same way as `ReceivingKeyRing`,
but only allows Sending Keys (`SymmetricKey`, `AsymmetricSecretKey`).

### Using Key Rings in Builders and Parsers

The Parser and Builder classes both support Key Rings without additional logic necessary.
Users are only responsible for correctly configuring their Key Ring to specify which version
and purpose is permitted.

```php
<?php
use ParagonIE\Paseto\{
    Builder,
    Parser,
    ReceivingKeyRing,
    SendingKeyRing
};
/**
 * @var Builder $builder
 * @var Parser $parser
 * @var ReceivingKeyRing $rcvKeyRing
 * @var SendingKeyRing $sendKeyRing
 */

// Building a token with a SendingKeyRing
$builder->setKey($sendKeyRing);
$token = $builder->toString();

// Parsing a token with a ReceivingKeyRing
$parser->setKey($rcvKeyRing);
$valid = $parser->parse($token);
```
