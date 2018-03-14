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
    PasetoException
};
use ParagonIE\Paseto\{
    ProtocolInterface,
    Util
};

/**
 * Class Version1
 * @package ParagonIE\Paseto\Protocol
 */
class Version2 implements ProtocolInterface
{
    /** @const string HEADER */
    const HEADER = 'v2';

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
     * @throws \SodiumException
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
     * @throws \SodiumException
     * @throws \TypeError
     */
    protected static function __encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $nonceForUnitTesting = ''
    ): string {
        if (!($key->getProtocol() instanceof Version2)) {
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
     *
     * @throws PasetoException
     * @throws \SodiumException
     * @throws \TypeError
     */
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        string $footer = ''
    ): string {
        if (!($key->getProtocol() instanceof Version2)) {
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
     *
     * @throws PasetoException
     * @throws \TypeError
     */
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = ''
    ): string {
        if (!($key->getProtocol() instanceof Version2)) {
            throw new InvalidVersionException('The given key is not intended for this version of PASETO.');
        }
        $header = self::HEADER . '.public.';
        $signature = \sodium_crypto_sign_detached(
            Util::preAuthEncode($header, $data, $footer),
            $key->raw()
        );
        if ($footer) {
            return $header .
                Base64UrlSafe::encodeUnpadded($data . $signature) .
                '.' .
                Base64UrlSafe::encodeUnpadded($footer);
        }
        return $header . Base64UrlSafe::encodeUnpadded($data . $signature);
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
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        string $footer = ''
    ): string {
        if (!($key->getProtocol() instanceof Version2)) {
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

        $valid = \sodium_crypto_sign_verify_detached(
            $signature,
            Util::preAuthEncode($givenHeader, $message, $footer),
            $key->raw()
        );
        if (!$valid) {
            throw new PasetoException('Invalid signature for this message');
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
     * @throws \SodiumException
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
            $nonce = $nonceForUnitTesting;
        } else {
            $nonce = \random_bytes(
                \ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            );
        }
        $nonce = \sodium_crypto_generichash(
            $plaintext,
            $nonce,
            \ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );
        $ciphertext = \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            Util::preAuthEncode($header, $nonce, $footer),
            $nonce,
            $key->raw()
        );
        if ($footer) {
            return $header .
                Base64UrlSafe::encodeUnpadded($nonce . $ciphertext) .
                '.' .
                Base64UrlSafe::encodeUnpadded($footer);
        }
        return $header . Base64UrlSafe::encodeUnpadded($nonce . $ciphertext);
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
     * @throws \SodiumException
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
        $nonce = Binary::safeSubstr(
            $decoded,
            0,
            \ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );
        $ciphertext = Binary::safeSubstr(
            $decoded,
            \ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
            $len - \ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );
        return \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            Util::preAuthEncode($header, $nonce, $footer),
            $nonce,
            $key->raw()
        );
    }
}
