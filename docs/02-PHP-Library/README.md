# How to use the PHP library

The first thing you should know about PAST is that it tries to accomplish
type-safety by wrapping cryptographic keys inside of objects. For example:

```php
<?php
use ParagonIE\PAST\Keys\{
    AsymmetricSecretKey,
    SymmetricAuthenticationKey,
    SymmetricEncryptionKey    
};

$privateKey = new AsymmetricSecretKey(sodium_crypto_sign_keypair());
$publicKey = $privateKey->getPublicKey();

$sharedEncKey = new SymmetricEncryptionKey(random_bytes(32));
$sharedAuthKey = new SymmetricAuthenticationKey(random_bytes(32));
```

You can access the key's internal strings by invoking `$key->raw()`. 

No version of the protocol will let you misuse a key by accident.
This will generate a `TypeError`:

```php
<?php
use ParagonIE\PAST\Protocol\Version2;

$token = Version2::encrypt('some arbitrary data', $sharedAuthkey); 
// TypeError: Expected SymmetricEncryptionKey, got SymmetricAuthenticationKey.
```

## Building and Verifying PASTs

The simplest use-case is to use shared-key authentication
to achieve tamper-resistant tokens:

```php
<?php
use ParagonIE\PAST\JsonToken;
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\PAST\Protocol\Version2;

/**
 * @var SymmetricAuthenticationKey $sharedAuthKey
 */
$token = (new JsonToken())
    ->setKey($sharedAuthKey)
    ->setVersion(Version2::HEADER)
    ->setPurpose('auth')
    // Set it to expire in one day
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
use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\PAST\Parser;

/**
 * @var string $providedToken
 * @var SymmetricAuthenticationKey $sharedAuthKey
 */
$parser = (new Parser())
    ->setKey($sharedAuthKey)
    ->setPurpose('auth')
    // Only allow version 2
    ->setAllowedVarsions(['v2']);

try {
    $token = $parser->parse($providedToken);
} catch (PastException $ex) {
    /* Handle invalid token cases here. */
}
var_dump($token instanceof \ParagonIE\PAST\JsonToken);
// bool(true)
```

## Using the Protocol Directly

Unlike JWT, we don't force you to use JSON. You can store arbitrary binary
data in a PAST, by invoking the Protocol classes directly. This is an advanced
usage, of course.

```php
<?php
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\Past\Protocol\{Version1, Version2};

$key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');
$messsage = \json_encode(['data' => 'this is a signed message', 'exp' => '2039-01-01T00:00:00']);
$footer = \json_encode(['key-id' => 'gandalf0']);

$v1Token = Version1::auth($messsage, $key);
var_dump($v1Token);
// string(156) "v1.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9tHUXb9BcoicC_kXc3fxkd_jpm2Laowv7OZ4sIH0ZlKRYcO2ez_zVtp_r94dfmh3W"

$token = Version2::auth($messsage, $key, $footer);
var_dump($token);
// string(165) "v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9hClJIR0hw-ULW0zU0023NYqpdOFmUB7-7wBP8TzILYA=.eyJrZXktaWQiOiJnYW5kYWxmMCJ9"
```
