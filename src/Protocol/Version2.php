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
use ParagonIE\Paseto\Keys\Version2\{
    AsymmetricSecretKey as V2AsymmetricSecretKey,
    SymmetricKey as V2SymmetricKey
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
use Exception;
use SodiumException;
use Throwable;
use TypeError;
use function hash_equals,
    is_null,
    is_string,
    sodium_crypto_generichash,
    sodium_crypto_aead_xchacha20poly1305_ietf_decrypt,
    sodium_crypto_aead_xchacha20poly1305_ietf_encrypt,
    sodium_crypto_sign_detached,
    sodium_crypto_sign_verify_detached;

/**
 * Class Version1
 * @package ParagonIE\Paseto\Protocol
 *
 * @deprecated See Version4 instead.
 */
class Version2 implements ProtocolInterface
{
    /** @const string HEADER */
    const HEADER = 'v2';
    const SYMMETRIC_KEY_BYTES = 32;

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
     * @return positive-int
     */
    public static function getSymmetricKeyByteLength(): int
    {
        return static::SYMMETRIC_KEY_BYTES;
    }

    /**
     * Generate an asymmetric secret key for use with v2.public tokens.
     *
     * @return AsymmetricSecretKey
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function generateAsymmetricSecretKey(): AsymmetricSecretKey
    {
        return V2AsymmetricSecretKey::generate(new static);
    }

    /**
     * Generate a symmetric key for use with v2.local tokens.
     *
     * @return SymmetricKey
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function generateSymmetricKey(): SymmetricKey
    {
        return V2SymmetricKey::generate(new static);
    }

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit (Unused)
     * @return string
     *
     * @throws PasetoException
     * @throws SodiumException
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
     * @param string $implicit (Unused)
     * @param string $nonceForUnitTesting
     * @return string
     *
     * @throws PasetoException
     * @throws SodiumException
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
         * PASETO Version 2 - Encrypt - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v2 tokens only.
         */
        if (!($key->getProtocol() instanceof Version2)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        return static::aeadEncrypt(
            $data,
            static::header() . '.local.', // // PASETO Version 2 - Encrypt - Step 2
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
     * @param string $implicit (Unused)
     * @return string
     *
     * @throws PasetoException
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        string $footer = null,
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 2 - Decrypt - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v2 tokens only.
         */
        if (!($key->getProtocol() instanceof Version2)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        // PASETO Version 2 - Decrypt - Step 2:
        if (is_null($footer)) {
            $footer = Util::extractFooter($data);
            $data = Util::removeFooter($data);
        } else {
            $data = Util::validateAndRemoveFooter($data, $footer);
        }
        $message = self::aeadDecrypt(
            $data,
            static::header() . '.local.',
            $key,
            $footer
        );
        if (!is_string($message)) {
            throw new PasetoException(
                'Invalid message decryption',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }

        return $message;
    }

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @param string $implicit (Unused)
     * @return string
     *
     * @throws PasetoException
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 2 - Sign - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v2 tokens only.
         */
        if (!($key->getProtocol() instanceof Version2)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }

        // PASETO Version 2 - Sign - Step 2:
        $header = static::header() . '.public.';

        // PASETO Version 2 - Sign - Step 3, 4:
        $signature = sodium_crypto_sign_detached(
            Util::preAuthEncode($header, $data, $footer),
            $key->raw()
        );

        // PASETO Version 2 - Sign - Step 5:
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
     * @param string $implicit (Unused)
     * @return string
     *
     * @throws PasetoException
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        string $footer = null,
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 2 - Verify - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v2 tokens only.
         */
        if (!($key->getProtocol() instanceof Version2)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }

        // PASETO Version 2 - Verify - Step 2:
        if (is_null($footer)) {
            $footer = Util::extractFooter($signMsg);
        } else {
            $signMsg = Util::validateAndRemoveFooter($signMsg, $footer);
        }
        $signMsg = Util::removeFooter($signMsg);

        // PASETO Version 2 - Verify - Step 3:
        $expectHeader = static::header() . '.public.';
        $headerLength = Binary::safeStrlen($expectHeader);
        $givenHeader = Binary::safeSubstr($signMsg, 0, $headerLength);
        if (!hash_equals($expectHeader, $givenHeader)) {
            throw new PasetoException(
                'Invalid message header.',
                ExceptionCode::INVALID_HEADER
            );
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, $headerLength));
        $len = Binary::safeStrlen($decoded);

        if ($len <= SODIUM_CRYPTO_SIGN_BYTES) {
            throw new PasetoException(
                'Invalid message length.',
                ExceptionCode::INVALID_MESSAGE_LENGTH
            );
        }

        // PASETO Version 2 - Verify - Step 4:
        // Separate the decoded bundle into the message and signature.
        $message = Binary::safeSubstr(
            $decoded,
            0,
            $len - SODIUM_CRYPTO_SIGN_BYTES
        );
        $signature = Binary::safeSubstr(
            $decoded,
            $len - SODIUM_CRYPTO_SIGN_BYTES
        );

        // PASETO Version 2 - Verify - Step 5, 6:
        $valid = sodium_crypto_sign_verify_detached(
            $signature,
            Util::preAuthEncode($givenHeader, $message, $footer),
            $key->raw()
        );

        // PASETO Version 2 - Verify - Step 7:
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
     * Algorithm: XChaCha20-Poly1305
     *
     * @param string $plaintext
     * @param string $header
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $nonceForUnitTesting
     * @return string
     *
     * @throws Exception
     * @throws SecurityException
     * @throws SodiumException
     * @throws TypeError
     */
    public static function aeadEncrypt(
        string $plaintext,
        string $header,
        SymmetricKey $key,
        string $footer = '',
        string $nonceForUnitTesting = ''
    ): string {

        // PASETO Version 2 - Encrypt - Step 3:
        if ($nonceForUnitTesting) {
            $nonce = $nonceForUnitTesting;
        } else {
            $nonce = random_bytes(
                SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            );
        }

        // PASETO Version 2 - Encrypt - Step 4:
        $nonce = sodium_crypto_generichash(
            $plaintext,
            $nonce,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        // PASETO Version 2 - Encrypt - Step 5, 6:
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            Util::preAuthEncode($header, $nonce, $footer),
            $nonce,
            $key->raw()
        );

        // PASETO Version 2 - Encrypt - Step 7:
        return (new PasetoMessage(
            Header::fromString($header),
            $nonce . $ciphertext,
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
     * @return bool|string
     *
     * @throws PasetoException
     * @throws SodiumException
     * @throws TypeError
     */
    public static function aeadDecrypt(
        string $message,
        string $header,
        SymmetricKey $key,
        string $footer = ''
    ) {
        // PASETO Version 2 - Decrypt - Step 3:
        $expectedLen = Binary::safeStrlen($header);
        $givenHeader = Binary::safeSubstr($message, 0, $expectedLen);
        if (!hash_equals($header, $givenHeader)) {
            throw new PasetoException(
                'Invalid message header.',
                ExceptionCode::INVALID_HEADER
            );
        }

        // PASETO Version 2 - Decrypt - Step 4:
        try {
            $decoded = Base64UrlSafe::decode(Binary::safeSubstr($message, $expectedLen));
        } catch (Throwable $ex) {
            throw new PasetoException(
                'Invalid encoding detected',
                ExceptionCode::INVALID_BASE64URL,
                $ex
            );
        }
        $len = Binary::safeStrlen($decoded);

        if ($len <= SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new PasetoException(
                'Invalid message length.',
                ExceptionCode::INVALID_MESSAGE_LENGTH
            );
        }

        $nonce = Binary::safeSubstr(
            $decoded,
            0,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );
        $ciphertext = Binary::safeSubstr(
            $decoded,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
            $len - SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );
        // PASETO Version 2 - Decrypt - Step  5, 6, 7:
        return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            Util::preAuthEncode($header, $nonce, $footer),
            $nonce,
            $key->raw()
        );
    }
}
