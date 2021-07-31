# How to use the PHP library

The first thing you should know about Paseto is that it tries to accomplish
type-safety by wrapping cryptographic keys inside of objects. For example:

```php
<?php
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey    
};

$privateKey = new AsymmetricSecretKey(sodium_crypto_sign_keypair());
$publicKey = $privateKey->getPublicKey();

$sharedKey = new SymmetricKey(random_bytes(32));
```

You can access the key's internal strings by invoking `$key->raw()`. 

No version of the protocol will let you misuse a key by accident.
This will generate a `TypeError`:

```php
<?php
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;

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
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;

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
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\JsonToken;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Rules\{
    IssuedBy,
    ValidAt
};
use ParagonIE\Paseto\ProtocolCollection;

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
