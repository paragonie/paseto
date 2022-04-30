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
use ParagonIE\Paseto\Keys\Version1\{
    AsymmetricSecretKey as V1AsymmetricSecretKey,
    SymmetricKey as V1SymmetricKey
};
use ParagonIE\Paseto\Exception\{
    ExceptionCode,
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

use Exception;
use TypeError;
use Throwable;
use function define,
    defined,
    hash_equals,
    hash_hmac,
    is_null,
    is_string,
    openssl_decrypt,
    openssl_encrypt,
    openssl_pkey_get_details,
    openssl_pkey_get_private,
    random_bytes,
    rtrim;

/**
 * Class Version1
 * @package ParagonIE\Paseto\Protocol
 *
 * @deprecated See Version3 instead.
 */
class Version1 implements ProtocolInterface
{
    const HEADER = 'v1';
    const CIPHER_MODE = 'aes-256-ctr';
    const HASH_ALGO = 'sha384';

    const SYMMETRIC_KEY_BYTES = 32;

    const NONCE_SIZE = 32;
    const MAC_SIZE = 48;
    const SIGN_SIZE = 256; // 2048-bit RSA = 256 byte signature

    /** @var RSA */
    protected static $rsa;

    /** @var bool $checked */
    private static $checked = false;

    /**
     * Must be constructable with no arguments so an instance may be passed
     * around in a type safe way.
     *
     * @throws SecurityException
     */
    public function __construct()
    {
        if (!self::$checked) {
            self::checkPhpSecLib();
        }
    }

    /**
     * Get the number of bytes in a symmetric key.
     *
     * @return positive-int
     */
    public static function getSymmetricKeyByteLength(): int
    {
        return static::SYMMETRIC_KEY_BYTES;
    }

    /**
     * Generate an asymmetric secret key for use with v1.public tokens.
     *
     * @return AsymmetricSecretKey
     * @throws Exception
     * @throws TypeError
     */
    public static function generateAsymmetricSecretKey(): AsymmetricSecretKey
    {
        return V1AsymmetricSecretKey::generate(new static);
    }

    /**
     * Generate a symmetric key for use with v1.local tokens.
     *
     * @return SymmetricKey
     * @throws SecurityException
     * @throws Exception
     * @throws TypeError
     */
    public static function generateSymmetricKey(): SymmetricKey
    {
        return V1SymmetricKey::generate(new static);
    }

    /**
     * A unique header string with which the protocol can be identified.
     *
     * @return string
     */
    public static function header(): string
    {
        return (string) static::HEADER;
    }

    /**
     * Does this protocol support implicit assertions?
     * No.
     *
     * @return bool
     */
    public static function supportsImplicitAssertions(): bool
    {
        return false;
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
     * @throws TypeError
     */
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        return self::__encrypt($data, $key, $footer);
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
     *
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws TypeError
     */
    protected static function __encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = '',
        string $nonceForUnitTesting = ''
    ): string {
        /*
         * PASETO Version 1 - Encrypt - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v1 tokens only.
         */
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        return self::aeadEncrypt(
            $data,
            static::header() . '.local.', // PASETO Version 1 - Encrypt - Step 2
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
     * @param string|null $footer
     * @param string $implicit
     * @return string
     *
     * @throws PasetoException
     * @throws TypeError
     * @throws InvalidVersionException
     */
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        string $footer = null,
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 1 - Decrypt - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v1 tokens only.
         */
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        // PASETO Version 1 - Decrypt - Step 2:
        if (is_null($footer)) {
            $footer = Util::extractFooter($data);
            $data = Util::removeFooter($data);
        } else {
            $data = Util::validateAndRemoveFooter($data, $footer);
        }
        return self::aeadDecrypt(
            $data,
            static::header() . '.local.',
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
     * @param string $implicit
     * @return string
     *
     * @throws TypeError
     * @throws InvalidVersionException
     * @throws SecurityException
     */
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 1 - Sign - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v1 tokens only.
         */
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        // PASETO Version 1 - Sign - Step 2:
        $header = self::HEADER . '.public.';
        $rsa = self::getRsa();
        $rsa->loadKey($key->raw());
        // PASETO Version 1 - Sign - Step 3, 4:
        $signature = $rsa->sign(
            Util::preAuthEncode($header, $data, $footer)
        );

        // PASETO Version 1 - Sign - Step 5:
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
     * @throws PasetoException
     * @throws TypeError
     */
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        string $footer = null,
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 1 - Verify - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v1 tokens only.
         */
        if (!($key->getProtocol() instanceof Version1)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }

        // PASETO Version 1 - Verify - Step 2:
        if (is_null($footer)) {
            $footer = Util::extractFooter($signMsg);
        } else {
            $signMsg = Util::validateAndRemoveFooter($signMsg, $footer);
        }
        $signMsg = Util::removeFooter($signMsg);

        // PASETO Version 1 - Verify - Step 3:
        $expectHeader = static::header() . '.public.';
        $headerLength = Binary::safeStrlen($expectHeader);
        $givenHeader = Binary::safeSubstr($signMsg, 0, $headerLength);
        if (!hash_equals($expectHeader, $givenHeader)) {
            throw new PasetoException(
                'Invalid message header.',
                ExceptionCode::INVALID_HEADER
            );
        }

        // PASETO Version 1 - Verify - Step 4:
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, $headerLength));
        $len = Binary::safeStrlen($decoded);

        if ($len <= self::SIGN_SIZE) {
            throw new PasetoException(
                'Invalid message length.',
                ExceptionCode::INVALID_MESSAGE_LENGTH
            );
        }

        $message = Binary::safeSubstr($decoded, 0, $len - self::SIGN_SIZE);
        $signature = Binary::safeSubstr($decoded, $len - self::SIGN_SIZE);

        // PASETO Version 1 - Verify - Step 5, 6:
        $rsa = self::getRsa();
        $rsa->loadKey($key->raw());
        $valid = $rsa->verify(
            Util::preAuthEncode($givenHeader, $message, $footer),
            $signature
        );

        // PASETO Version 1 - Verify - Step 7:
        if (!$valid) {
            throw new PasetoException(
                'Invalid signature for this message',
                ExceptionCode::INVALID_SIGNATURE
            );
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
     *
     * @throws Exception
     * @throws PasetoException
     * @throws TypeError
     */
    public static function aeadEncrypt(
        string $plaintext,
        string $header,
        SymmetricKey $key,
        string $footer = '',
        string $nonceForUnitTesting = ''
    ): string {
        // PASETO Version 1 - Encrypt - Step 3, 4:
        if ($nonceForUnitTesting) {
            $nonce = self::getNonce($plaintext, $nonceForUnitTesting);
        } else {
            $nonce = self::getNonce($plaintext, random_bytes(self::NONCE_SIZE));
        }
        // PASETO Version 1 - Encrypt - Step 5:
        list($encKey, $authKey) = $key->split(
            Binary::safeSubstr($nonce, 0, 16)
        );

        // PASETO Version 1 - Encrypt -Step 6:
        /** @var string|bool $ciphertext */
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );
        Util::wipe($encKey);
        if (!is_string($ciphertext)) {
            throw new PasetoException(
                'Encryption failed.',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }
        // PASETO Version 1 - Encrypt - Step 7, 8:
        $mac = hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer),
            $authKey,
            true
        );
        Util::wipe($authKey);

        // PASETO Version 1 - Encrypt - Step 9:
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
     *
     * @throws PasetoException
     * @throws TypeError
     */
    public static function aeadDecrypt(
        string $message,
        string $header,
        SymmetricKey $key,
        string $footer = ''
    ): string {
        // PASETO Version 1 - Decrypt - Step 3:
        $expectedLen = Binary::safeStrlen($header);
        $givenHeader = Binary::safeSubstr($message, 0, $expectedLen);
        if (!hash_equals($header, $givenHeader)) {
            throw new PasetoException(
                'Invalid message header.',
                ExceptionCode::INVALID_HEADER
            );
        }
        // PASETO Version 1 - Decrypt - Step 4:
        try {
            $decoded = Base64UrlSafe::decode(
                Binary::safeSubstr($message, $expectedLen)
            );
        } catch (Throwable $ex) {
            throw new PasetoException(
                'Invalid encoding detected',
                ExceptionCode::INVALID_BASE64URL,
                $ex
            );
        }
        $len = Binary::safeStrlen($decoded);

        if ($len <= self::NONCE_SIZE + self::MAC_SIZE) {
            throw new PasetoException(
                'Invalid message length.',
                ExceptionCode::INVALID_MESSAGE_LENGTH
            );
        }

        $nonce = Binary::safeSubstr($decoded, 0, self::NONCE_SIZE);
        $ciphertext = Binary::safeSubstr(
            $decoded,
            self::NONCE_SIZE,
            $len - (self::NONCE_SIZE + self::MAC_SIZE)
        );
        $mac = Binary::safeSubstr($decoded, $len - self::MAC_SIZE);

        // PASETO Version 1 - Decrypt - Step 5:
        list($encKey, $authKey) = $key->split(
            Binary::safeSubstr($nonce, 0, 16)
        );

        // PASETO Version 1 - Decrypt - Step 6, 7:
        $calc = hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer),
            $authKey,
            true
        );
        Util::wipe($authKey);

        // PASETO Version 1 - Decrypt - Step 8:
        if (!hash_equals($calc, $mac)) {
            Util::wipe($encKey);
            throw new SecurityException(
                'Invalid MAC for given ciphertext.',
                ExceptionCode::INVALID_MAC
            );
        }

        // PASETO Version 1 - Decrypt - Step 9:
        /** @var string|bool $plaintext */
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );
        Util::wipe($encKey);
        if (!is_string($plaintext)) {
            throw new PasetoException(
                'Encryption failed.',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
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
     *
     * @throws TypeError
     */
    public static function getNonce(string $m, string $n): string
    {
        $nonce = hash_hmac(self::HASH_ALGO, $m, $n, true);
        return Binary::safeSubstr($nonce, 0, 32);
    }

    /**
     * Get the PHPSecLib RSA provider for signing
     *
     * Hard-coded: RSASSA-PSS with MGF1+SHA384 and SHA384, with e = 65537
     *
     * @return RSA
     */
    public static function getRsa(): RSA
    {
        $rsa = new RSA();
        $rsa->setHash('sha384');
        $rsa->setMGFHash('sha384');
        $rsa->setSignatureMode(RSA::SIGNATURE_PSS);
        return $rsa;
    }

    /**
     * Is phpseclib configured correctly?
     *
     * @throws SecurityException
     */
    public static function checkPhpSecLib(): bool
    {
        if (self::$checked) {
            return true;
        }
        if (!defined('CRYPT_RSA_EXPONENT')) {
            define('CRYPT_RSA_EXPONENT', 65537);
        } elseif (CRYPT_RSA_EXPONENT != 65537) {
            throw new SecurityException(
                'RSA Public Exponent must be equal to 65537; it is set to ' .
                CRYPT_RSA_EXPONENT,
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }
        self::$checked = true;
        return true;
    }

    /**
     * Version 1 specific:
     * Get the RSA public key for the given RSA private key.
     *
     * @param string $keyData
     * @return string
     */
    public static function RsaGetPublicKey(string $keyData): string
    {
        $res = openssl_pkey_get_private($keyData);
        if (!$res) {
            throw new PasetoException("Invalid RSA secret key");
        }
        /** @var array<string, string> $pubkey */
        $pubkey = openssl_pkey_get_details($res);
        return rtrim(
            Util::dos2unix($pubkey['key']),
            "\n"
        );
    }
}
