# How to use the PHP library

The first thing you should know about PAST is that it tries to accomplish
type-safety by wrapping cryptographic keys inside of objects. For example:

```php
<?php
use ParagonIE\PAST\Keys\{
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
use ParagonIE\PAST\Protocol\Version2;
use ParagonIE\PAST\Keys\SymmetricKey;

/**
 * @var SymmetricKey $sharedAuthKey
 */
$token = Version2::sign('some arbitrary data', $sharedAuthKey);
```

## Building and Verifying PASTs

The simplest use-case is to use shared-key authentication
to achieve tamper-resistant tokens:

```php
<?php
use ParagonIE\PAST\JsonToken;
use ParagonIE\PAST\Keys\SymmetricKey;
use ParagonIE\PAST\Protocol\Version2;

/**
 * @var SymmetricKey $sharedAuthKey
 */
$token = (new JsonToken())
    ->setKey($sharedAuthKey)
    ->setVersion(Version2::HEADER)
    ->setPurpose('local')
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
use ParagonIE\PAST\Keys\SymmetricKey;
use ParagonIE\PAST\Parser;

/**
 * @var string $providedToken
 * @var SymmetricKey $sharedAuthKey
 */
$parser = (new Parser())
    ->setKey($sharedAuthKey)
    ->setPurpose('local')
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
use ParagonIE\PAST\Keys\SymmetricKey;
use ParagonIE\PAST\Protocol\{Version1, Version2};

$key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
$message = 'This is a signed, non-JSON message.';
$footer = 'key-id:gandalf0';

# Version 1:
$v1Token = Version1::encrypt($message, $key);
var_dump((string) $v1Token);
// string(163) "v1.local.WeSsfqWpfg5jyqQoL088HOGTL4YrcA3JInC4C8HGalnHUtQfdV1YjT8HGgZJbKS4tlXFoA0Z8zifikuTAbZDVI1Psr7LbQL5IXoFgLwsH8Map0iy1WedX-RgfpGZAyQsY03kVLmmW6J2-S4I4FC0821rOQ"
var_dump(Version1::decrypt($v1Token, $key));
// string(35) "This is a signed, non-JSON message."

$v1Token = Version1::encrypt($message, $key, $footer);
var_dump((string) $v1Token);
// string(184) "v1.local.8I9kDLv3gNd7WGyp55wCnswLY0ur0Fd0qOI10VTmCDopehilRF_qejheQFSxyb0nu5Jkc45RmCnMbkcHSqEBYwqPMFnE2N94lbKsR8jtRFD6MgYOebPZAKrhlnLsZz_G7gD88ntX7OgXDAxbcrnKKZPeeQ.a2V5LWlkOmdhbmRhbGYw"
var_dump(Version1::decrypt($v1Token, $key, $footer));
// string(35) "This is a signed, non-JSON message."

# Version 2:
$v2Token = Version2::encrypt($message, $key);
var_dump((string) $v2Token);
// string(109) "v2.local.-p1d4Ja8DVNMLwOkK77zrlkj2q2loIdo4ypd26AKgqUrrzei4LwAeGXF3ivpTrluSMEBLf04F8mSFO00tU_FOgCLHWTGz_3oYF67"
var_dump(Version2::decrypt($v2Token, $key));
// string(35) "This is a signed, non-JSON message."

$v2Token = Version2::encrypt($message, $key, $footer);
var_dump((string) $v2Token);
// string(130) "v2.local.37Q1fN7K0t_EUOtqhvES1WHkJw8eIex2m-5vP0JQeAWZ-1gMBPm6GMFVSnGIq0zK2eApeHSoxyj1bymI8OOjpFD8NkqheUuY0QSJ.a2V5LWlkOmdhbmRhbGYw"
var_dump(Version2::decrypt($v2Token, $key, $footer));
// string(35) "This is a signed, non-JSON message."

// Explicit nonces (for unit testing):
$nonce = str_repeat("\0", 24);
$v2Token = ParagonIE\PAST\Protocol\Version2::encrypt($message, $key, $footer, $nonce);
var_dump((string) $v2Token);
// string(130) "v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9E5lZQlE2rYJH6S-N1z-jnKpXy1hd6BDNEnjProJ6HFZPY_6AtK3ldQrOzHvVZzqiqK2.a2V5LWlkOmdhbmRhbGYw"
```
