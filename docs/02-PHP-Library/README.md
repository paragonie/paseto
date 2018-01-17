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
 * @var SymmetricKey $sharedKey
 */
$token = Version2::sign('some arbitrary data', $sharedKey);
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
 * @var SymmetricKey $sharedKey
 */
$token = JsonToken::getLocal($sharedKey, Version2::HEADER);

$token = (new JsonToken())
    ->setKey($sharedKey)
    ->setVersion(Version2::HEADER)
    ->setPurpose('local')
    // Store arbitrary data
    ->setClaim('security', 'Hello world')
        'security' => 'Now as easy as PIE'
    ])
    // Set it to expire in one day
    ->setExpiration(
        (new DateTime())->add(new DateInterval('P01D'))
    );
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
use ParagonIE\PAST\Protocol\Version2;

/**
 * @var string $providedToken
 * @var SymmetricKey $sharedKey
 */
$parser = Parser::getLocal($sharedKey, [Version2::HEADER]);
// This is the same as:
$parser = (new Parser())
    ->setKey($sharedKey)
    ->setPurpose('local')
    // Only allow version 2
    ->setAllowedVersions([Version2::HEADER]);

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
// string(163) "v1.local.B0VgDOyAtKza1ZCsPzlwQZGTfrpbo1vgzUwCvyxLiSM-gw3TC_KtMqX8woy8BuuE9-pRQNmnTGAru5OmVLzPDnDBHXbd8Sz5rssiTz5TZKLqSyYHsgBzfc53PqsTxLvw09QAy5KBSpKErPX_EfF0Od6-Ig"
var_dump(Version1::decrypt($v1Token, $key));
// string(35) "This is a signed, non-JSON message."

$v1Token = Version1::encrypt($message, $key, $footer);
var_dump((string) $v1Token);
// string(184) "v1.local.vu2ZV_apVDvIhExdenX6rm5w13E3LraRbgN9tabtspSR6KQQt5XdGY5Hho64VRj6Pa6gd-5w5XwmRZbnrxfSVYyvXrVfyDJC7pqQDgae8-MHDg5rZul7kFiH6ExXWx-1hJupWSkRnfQy168PzwS14xiTgw.a2V5LWlkOmdhbmRhbGYw"
var_dump(Version1::decrypt($v1Token, $key, $footer));
// string(35) "This is a signed, non-JSON message."

# Version 2:
$v2Token = Version2::encrypt($message, $key);
var_dump((string) $v2Token);
// string(109) "v2.local.0qOisotef_M2W1gK0b6SiUrO4fkPb24Se0eNJAkALmDvS3IlVu-72birx07hIqU4MYtrCrTJTTElYaWxOyz5Wx8wXh8cQUOF6wOo"
var_dump(Version2::decrypt($v2Token, $key));
// string(35) "This is a signed, non-JSON message."

$v2Token = Version2::encrypt($message, $key, $footer);
var_dump((string) $v2Token);
// string(130) "v2.local.b6ClQBYz-s8k7CC-dEYz2sf3zQFqES4xNUP6K-lzQTRnxVlZFxNnT5I6ouSwYe1d-t9OTnjM9d46MEt__GJvHbNO1wwIfnf1Ear-.a2V5LWlkOmdhbmRhbGYw"
var_dump(Version2::decrypt($v2Token, $key, $footer));
// string(35) "This is a signed, non-JSON message."

// Explicit nonces (for unit testing):
$nonce = str_repeat("\0", 24);
$v2Token = ParagonIE\PAST\Protocol\Version2::encrypt($message, $key, $footer, $nonce);
var_dump((string) $v2Token);
// string(130) "v2.local.oFcz6G4gkzMlx3qF2-FnFeUNBwUG0TqR7aoIN8TwsJ1h3xSBKEBsKomYhDsEXHuB3_rVUpzXR45KtDvAzAMPmxZdrWU3SCO9kO_M.a2V5LWlkOmdhbmRhbGYw"
```
