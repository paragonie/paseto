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
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;

/**
 * @var SymmetricAuthenticationKey $sharedAuthKey
 */
$token = Version2::encrypt('some arbitrary data', $sharedAuthKey); 
SymmetricKey
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
    ->setAllowedVersions(['v2']);

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
use ParagonIE\PAST\Protocol\{Version1, Version2};

$key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');
$message = 'This is a signed, non-JSON message.';
$footer = 'key-id:gandalf0';

# Version 1:
$v1Token = Version1::auth($message, $key);
var_dump((string) $v1Token);
// string(119) "v1.auth.VGhpcyBpcyBhIHNpZ25lZCwgbm9uLUpTT04gbWVzc2FnZS7oOqvKH5vRLbtFUt9aCpj07IQ0xep-XyaUitfocuZHI4KTE2XvvPxxFwpprODHu48"
var_dump(Version1::authVerify($v1Token, $key));
// string(35) "This is a signed, non-JSON message."

$v1Token = Version1::auth($message, $key, $footer);
var_dump((string) $v1Token);
// string(140) "v1.auth.VGhpcyBpcyBhIHNpZ25lZCwgbm9uLUpTT04gbWVzc2FnZS4-OUI1gPNfKbXnlri80cOL09sAeDPufbFZPtDJtBYJHvw-paFOJB7c_idufcwFxYs.a2V5LWlkOmdhbmRhbGYw"
var_dump(Version1::authVerify($v1Token, $key, $footer));
// string(35) "This is a signed, non-JSON message."

# Version 2:
$v2Token = Version2::auth($message, $key);
var_dump((string) $v2Token);
// string(98) "v2.auth.VGhpcyBpcyBhIHNpZ25lZCwgbm9uLUpTT04gbWVzc2FnZS6oHEOlDwiHeyJ2gKEISXF24i2ZraSPyNXUTYQX-V3siA"
var_dump(Version2::authVerify($v2Token, $key));
// string(35) "This is a signed, non-JSON message."

$v2Token = Version2::auth($message, $key, $footer);
var_dump((string) $v2Token);
// string(119) "v2.auth.VGhpcyBpcyBhIHNpZ25lZCwgbm9uLUpTT04gbWVzc2FnZS7NoNXmf0CVrTmfso33FW1FCXOevPgWvvZoAvyu1d07wA.a2V5LWlkOmdhbmRhbGYw"
var_dump(Version2::authVerify($v2Token, $key, $footer));
// string(35) "This is a signed, non-JSON message."
```
