<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Protocol;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Exception\{
    InvalidVersionException,
    PasetoException,
    SecurityException
};
use ParagonIE\Paseto\{
    ProtocolInterface,
    Util
};
use ParagonIE\Paseto\Parsing\{
    Header,
    PasetoMessage
};
use phpseclib\Crypt\RSA;

/**
 * Class Version1
 * @package ParagonIE\Paseto\Protocol
 */
class Version1 implements ProtocolInterface
{
    const HEADER = 'v1';
    const CIPHER_MODE = 'aes-256-ctr';
    const HASH_ALGO = 'sha384';

    const NONCE_SIZE = 32;
    const MAC_SIZE = 48;
    const SIGN_SIZE = 256; // 2048-bit RSA = 256 byte signature

    /** @var RSA */
    protected static $rsa;

    /**
     * Must be constructable with no arguments so an instance may be passed
     * around in a type safe way.
     */
    public function __construct() {}

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
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = ''
    ): string {
        return self::__encrypt($data, $key, $footer);
    }

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $nonceForUnitTesting
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    protected static function __encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $nonceForUnitTesting = ''
    ): string {
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        return self::aeadEncrypt(
            $data,
            self::HEADER . '.local.',
            $key,
            $footer,
            $nonceForUnitTesting
        );
    }

    /**
     * Decrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function decrypt(string $data, SymmetricKey $key, string $footer = ''): string
    {
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        return self::aeadDecrypt(
            Util::validateAndRemoveFooter($data, $footer),
            self::HEADER . '.local.',
            $key,
            $footer
        );
    }

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function sign(string $data, AsymmetricSecretKey $key, string $footer = ''): string
    {
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        $header = self::HEADER . '.public.';
        $rsa = self::getRsa();
        $rsa->loadKey($key->raw());
        $signature = $rsa->sign(
            Util::preAuthEncode($header, $data, $footer)
        );

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
     * @param string $footer
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function verify(string $signMsg, AsymmetricPublicKey $key, string $footer = ''): string
    {
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        $signMsg = Util::validateAndRemoveFooter($signMsg, $footer);
        $expectHeader = self::HEADER . '.public.';
        $givenHeader = Binary::safeSubstr($signMsg, 0, 10);
        if (!\hash_equals($expectHeader, $givenHeader)) {
            throw new PasetoException('Invalid message header.');
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, 10));
        $len = Binary::safeStrlen($decoded);
        $message = Binary::safeSubstr($decoded, 0, $len - self::SIGN_SIZE);
        $signature = Binary::safeSubstr($decoded, $len - self::SIGN_SIZE);

        $rsa = self::getRsa();
        $rsa->loadKey($key->raw());
        $valid = $rsa->verify(
            Util::preAuthEncode($givenHeader, $message, $footer),
            $signature
        );
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
     * @param string $nonceForUnitTesting
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */

    public static function aeadEncrypt(
        string $plaintext,
        string $header,
        SymmetricKey $key,
        string $footer = '',
        string $nonceForUnitTesting = ''
    ): string {
        if ($nonceForUnitTesting) {
            $nonce = self::getNonce($plaintext, $nonceForUnitTesting);
        } else {
            $nonce = self::getNonce($plaintext, \random_bytes(self::NONCE_SIZE));
        }
        list($encKey, $authKey) = $key->split(
            Binary::safeSubstr($nonce, 0, 16)
        );
        /** @var string|bool $ciphertext */
        $ciphertext = \openssl_encrypt(
            $plaintext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );
        if (!\is_string($ciphertext)) {
            throw new PasetoException('Encryption failed.');
        }
        $mac = \hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer),
            $authKey,
            true
        );

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
     * @return string
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function aeadDecrypt(
        string $message,
        string $header,
        SymmetricKey $key,
        string $footer = ''
    ): string {
        $expectedLen = Binary::safeStrlen($header);
        $givenHeader = Binary::safeSubstr($message, 0, $expectedLen);
        if (!\hash_equals($header, $givenHeader)) {
            throw new PasetoException('Invalid message header.');
        }
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

        list($encKey, $authKey) = $key->split(
            Binary::safeSubstr($nonce, 0, 16)
        );

        $calc = \hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer),
            $authKey,
            true
        );
        if (!\hash_equals($calc, $mac)) {
            throw new SecurityException('Invalid MAC for given ciphertext.');
        }

        /** @var string|bool $plaintext */
        $plaintext = \openssl_decrypt(
            $ciphertext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );
        if (!\is_string($plaintext)) {
            throw new PasetoException('Encryption failed.');
        }

        return $plaintext;
    }

    /**
     * Calculate a nonce from the message and a random nonce.
     * Mitigation against nonce-misuse.
     *
     * @param string $m
     * @param string $n
     * @return string
     * @throws \TypeError
     */
    public static function getNonce(string $m, string $n): string
    {
        $nonce = \hash_hmac(self::HASH_ALGO, $m, $n, true);
        return Binary::safeSubstr($nonce, 0, 32);
    }

    /**
     * Get the PHPSecLib RSA provider for signing
     *
     * @return RSA
     */
    public static function getRsa(): RSA
    {
        $rsa = new RSA();
        $rsa->setHash('sha384');
        $rsa->setMGFHash('sha384');
        $rsa->setEncryptionMode(RSA::SIGNATURE_PSS);
        return $rsa;
    }

    /**
     * Version 1 specific: Get the RSA public key for the given SA private key.
     *
     * @param string $keyData
     * @return string
     */
    public static function RsaGetPublicKey(string $keyData): string
    {
        $res = \openssl_pkey_get_private($keyData);
        /** @var array<string, string> $pubkey */
        $pubkey = \openssl_pkey_get_details($res);
        return \rtrim(
            \str_replace("\n", "\r\n", $pubkey['key']),
            "\r\n"
        );
    }
}
