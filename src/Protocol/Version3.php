<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Protocol;

use FG\ASN1\Exception\ParserException as ASN1ParserException;
use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Keys\Version3\{
    AsymmetricSecretKey as V3AsymmetricSecretKey,
    SymmetricKey as V3SymmetricKey
};
use ParagonIE\Paseto\Exception\{
    InvalidVersionException,
    PasetoException,
    SecurityException
};
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\ECDSA\{
    PublicKey,
    SecretKey
};
use ParagonIE\Paseto\{
    ProtocolInterface,
    Util
};
use ParagonIE\Paseto\Parsing\{
    Header,
    PasetoMessage
};

/**
 * Class Version1
 * @package ParagonIE\Paseto\Protocol
 */
class Version3 implements ProtocolInterface
{
    const HEADER = 'v3';
    const CIPHER_MODE = 'aes-256-ctr';
    const HASH_ALGO = 'sha384';
    const CURVE = 'P384';

    const SYMMETRIC_KEY_BYTES = 32;

    const NONCE_SIZE = 32;
    const MAC_SIZE = 48;
    const SIGN_SIZE = 96; // 384-bit ECDSA = 96-byte signature

    /**
     * Must be constructable with no arguments so an instance may be passed
     * around in a type safe way.
     */
    public function __construct()
    {
    }

    /**
     * @return int
     */
    public static function getSymmetricKeyByteLength(): int
    {
        return (int) static::SYMMETRIC_KEY_BYTES;
    }

    /**
     * @return AsymmetricSecretKey
     * @throws \Exception
     * @throws \TypeError
     */
    public static function generateAsymmetricSecretKey(): AsymmetricSecretKey
    {
        return V3AsymmetricSecretKey::generate(new static);
    }

    /**
     * @return SymmetricKey
     * @throws \Exception
     * @throws \TypeError
     */
    public static function generateSymmetricKey(): SymmetricKey
    {
        return V3SymmetricKey::generate(new static);
    }

    /**
     * A unique header string with which the protocol can be identified.
     *
     * @return string
     */
    public static function header(): string
    {
        return self::HEADER;
    }

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     * @throws PasetoException
     */
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        return self::__encrypt($data, $key, $footer, $implicit);
    }

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @param string $nonceForUnitTesting
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    protected static function __encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = '',
        string $nonceForUnitTesting = ''
    ): string {
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.'
            );
        }
        return self::aeadEncrypt(
            $data,
            self::HEADER . '.local.', // PASETO v3 - Encrypt - Step 1
            $key,
            $footer,
            $implicit,
            $nonceForUnitTesting
        );
    }

    /**
     * Decrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string|null $footer
     * @param string $implicit
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        string $footer = null,
        string $implicit = ''
    ): string {
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        // PASETO v3 - Decrypt - Step 1:
        if (\is_null($footer)) {
            $footer = Util::extractFooter($data);
            $data = Util::removeFooter($data);
        } else {
            $data = Util::validateAndRemoveFooter($data, $footer);
        }
        return self::aeadDecrypt(
            $data,
            self::HEADER . '.local.',
            $key,
            (string) $footer,
            $implicit
        );
    }

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     *
     * @throws PasetoException
     * @throws \TypeError
     * @throws InvalidVersionException
     * @throws SecurityException
     * @throws \SodiumException
     */
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        // PASETO v3 - Sign - Step 1:
        $header = self::HEADER . '.public.';
        $easyEcc = new EasyECC(self::CURVE);
        // PASETO v3 - Sign - Step 2 & 3:
        $pk = Hex::decode($key->getPublicKey()->raw());
        $signature = Hex::decode($easyEcc->sign(
            Util::preAuthEncode($pk, $header, $data, $footer, $implicit),
            SecretKey::importPem($key->raw()),
            true
        ));
        // PASETO v3 - Sign - Step 4:
        return (new PasetoMessage(
            Header::fromString($header),
            $data . $signature,
            $footer
        ))->toString();
    }

    /**
     * Verify a signed message. Public-key digital signatures.
     *
     * @param string $signMsg
     * @param AsymmetricPublicKey $key
     * @param string|null $footer
     * @param string $implicit
     * @return string
     *
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws ASN1ParserException
     * @throws \SodiumException
     */
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        string $footer = null,
        string $implicit = ''
    ): string {
        // PASETO v3 - Verify - Step 1:
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        if (\is_null($footer)) {
            $footer = Util::extractFooter($signMsg);
        } else {
            $signMsg = Util::validateAndRemoveFooter($signMsg, $footer);
        }
        $signMsg = Util::removeFooter($signMsg);

        // PASETO v3 - Verify - Step 2:
        $expectHeader = self::HEADER . '.public.';
        $givenHeader = Binary::safeSubstr($signMsg, 0, 10);
        if (!\hash_equals($expectHeader, $givenHeader)) {
            throw new PasetoException('Invalid message header.');
        }

        // PASETO v3 - Verify - Step 3:
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, 10));
        $len = Binary::safeStrlen($decoded);
        $message = Binary::safeSubstr($decoded, 0, $len - self::SIGN_SIZE);
        $signature = Binary::safeSubstr($decoded, $len - self::SIGN_SIZE);

        $easyEcc = new EasyECC(self::CURVE);

        // PASETO v3 - Verify - Step 4 & 5:
        $pk = Hex::decode($key->raw());
        $valid = $easyEcc->verify(
            Util::preAuthEncode($pk, $givenHeader, $message, $footer, $implicit),
            PublicKey::fromString($key->raw(), 'P384'),
            Hex::encode($signature),
            true
        );

        // PASETO v3 - Verify - Step 6:
        if (!$valid) {
            throw new PasetoException('Invalid signature for this message');
        }
        return $message;
    }

    /**
     * Authenticated Encryption with Associated Data -- Encryption
     *
     * Algorithm: AES-256-CTR + HMAC-SHA384 (Encrypt then MAC)
     *
     * @param string $plaintext
     * @param string $header
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @param string $nonceForUnitTesting
     * @return string
     * @throws PasetoException
     * @throws SecurityException
     */
    public static function aeadEncrypt(
        string $plaintext,
        string $header,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = '',
        string $nonceForUnitTesting = ''
    ): string {
        // PASETO v3 - Encrypt - Step 2:
        if ($nonceForUnitTesting) {
            $nonce = $nonceForUnitTesting;
        } else {
            $nonce = \random_bytes(self::NONCE_SIZE);
        }
        // PASETO v3 - Encrypt - Step 3:
        list($encKey, $authKey, $nonce2) = $key->splitV3($nonce);

        /** @var string|bool $ciphertext */
        // PASETO v3 - Encrypt - Step 4:
        $ciphertext = \openssl_encrypt(
            $plaintext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            $nonce2
        );
        \sodium_memzero($encKey);
        if (!\is_string($ciphertext)) {
            throw new PasetoException('Encryption failed.');
        }
        // PASETO v3 - Encrypt - Step 5 & 6:
        $mac = \hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer, $implicit),
            $authKey,
            true
        );
        \sodium_memzero($authKey);

        // PASETO v3 - Encrypt - Step 7:
        return (new PasetoMessage(
            Header::fromString($header),
            $nonce . $ciphertext . $mac,
            $footer
        ))->toString();
    }

    /**
     * Authenticated Encryption with Associated Data -- Decryption
     *
     * @param string $message
     * @param string $header
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function aeadDecrypt(
        string $message,
        string $header,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        $expectedLen = Binary::safeStrlen($header);
        $givenHeader = Binary::safeSubstr($message, 0, $expectedLen);

        // PASETO v3 - Decrypt - Step 2:
        if (!\hash_equals($header, $givenHeader)) {
            throw new PasetoException('Invalid message header.');
        }

        // PASETO v3 - Decrypt - Step 3:
        try {
            $decoded = Base64UrlSafe::decode(Binary::safeSubstr($message, $expectedLen));
        } catch (\Throwable $ex) {
            throw new PasetoException('Invalid encoding detected', 0, $ex);
        }
        $len = Binary::safeStrlen($decoded);
        $nonce = Binary::safeSubstr($decoded, 0, self::NONCE_SIZE);
        $ciphertext = Binary::safeSubstr(
            $decoded,
            self::NONCE_SIZE,
            $len - (self::NONCE_SIZE + self::MAC_SIZE)
        );
        $mac = Binary::safeSubstr($decoded, $len - self::MAC_SIZE);

        // PASETO v3 - Decrypt - Step 4:
        list($encKey, $authKey, $nonce2) = $key->splitV3($nonce);

        // PASETO v3 - Decrypt - Step 5 & 6:
        $calc = \hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer, $implicit),
            $authKey,
            true
        );
        \sodium_memzero($authKey);

        // PASETO v3 - Decrypt - Step 7:
        if (!\hash_equals($calc, $mac)) {
            throw new SecurityException('Invalid MAC for given ciphertext.');
        }

        // PASETO v3 - Decrypt - Step 8:
        /** @var string|bool $plaintext */
        $plaintext = \openssl_decrypt(
            $ciphertext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            $nonce2
        );
        \sodium_memzero($encKey);

        if (!\is_string($plaintext)) {
            throw new PasetoException('Encryption failed.');
        }

        return $plaintext;
    }
}
