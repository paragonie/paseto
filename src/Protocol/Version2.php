<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Protocol;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\PAST\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricAuthenticationKey,
    SymmetricEncryptionKey
};
use ParagonIE\PAST\{
    ProtocolInterface,
    Util
};

/**
 * Class Version1
 * @package ParagonIE\PAST\Protocol
 */
class Version2 implements ProtocolInterface
{
    /** @const string HEADER */
    const HEADER = 'v2';

    /**
     * Authenticate a message with a shared key.
     *
     * @param string $data
     * @param SymmetricAuthenticationKey $key
     * @param string $footer
     * @return string
     */
    public static function auth(
        string $data,
        SymmetricAuthenticationKey $key,
        string $footer = ''
    ): string {
        $header = self::HEADER . '.auth.';
        $mac = \sodium_crypto_auth(
            Util::preAuthEncode([$header, $data, $footer]),
            $key->raw()
        );
        if ($footer) {
            return $header .
                Base64UrlSafe::encode($data . $mac) .
                '.' .
                Base64UrlSafe::encode($footer);
        }
        return $header . Base64UrlSafe::encode($data . $mac);
    }

    /**
     * Verify a message with a shared key.
     *
     * @param string $authMsg
     * @param SymmetricAuthenticationKey $key
     * @param string $footer
     * @return string
     * @throws \Exception
     * @throws \TypeError
     */
    public static function authVerify(
        string $authMsg,
        SymmetricAuthenticationKey $key,
        string $footer = ''
    ): string {
        $authMsg = Util::validateAndRemoveFooter($authMsg, $footer);
        $expectHeader = self::HEADER . '.auth.';
        $givenHeader = Binary::safeSubstr($authMsg, 0, 8);
        if (!\hash_equals($expectHeader, $givenHeader)) {
            throw new \Exception('Invalid message header.');
        }

        $body = Binary::safeSubstr($authMsg, 8);
        $decoded = Base64UrlSafe::decode($body);
        $len = Binary::safeStrlen($decoded);

        $message = Binary::safeSubstr($decoded, 0, $len - 32);
        $mac = Binary::safeSubstr($decoded, $len - 32);
        $valid = \sodium_crypto_auth_verify(
            $mac,
            Util::preAuthEncode([$givenHeader, $message, $footer]),
            $key->raw()
        );
        if (!$valid) {
            throw new \Exception('Invalid MAC');
        }
        return $message;
    }

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricEncryptionKey $key
     * @param string $footer
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public static function encrypt(
        string $data,
        SymmetricEncryptionKey $key,
        string $footer = ''
    ): string
    {
        return self::aeadEncrypt(
            $data,
            self::HEADER . '.enc.',
            $key,
            $footer
        );
    }

    /**
     * Decrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricEncryptionKey $key
     * @param string $footer
     * @return string
     * @throws \Exception
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function decrypt(string $data, SymmetricEncryptionKey $key, string $footer = ''): string
    {
        return self::aeadDecrypt(
            Util::validateAndRemoveFooter($data, $footer),
            self::HEADER . '.enc.',
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
     */
    public static function sign(string $data, AsymmetricSecretKey $key, string $footer = ''): string
    {
        $header = self::HEADER . '.sign.';
        $signature = \sodium_crypto_sign_detached(
            Util::preAuthEncode([$header, $data, $footer]),
            $key->raw()
        );
        if ($footer) {
            return $header .
                Base64UrlSafe::encode($data . $signature) .
                '.' .
                Base64UrlSafe::encode($footer);
        }
        return $header . Base64UrlSafe::encode($data . $signature);
    }

    /**
     * Verify a signed message. Public-key digital signatures.
     *
     * @param string $signMsg
     * @param AsymmetricPublicKey $key
     * @param string $footer
     * @return string
     * @throws \Exception
     * @throws \TypeError
     */
    public static function signVerify(string $signMsg, AsymmetricPublicKey $key, string $footer = ''): string
    {
        $signMsg = Util::validateAndRemoveFooter($signMsg, $footer);
        $expectHeader = self::HEADER . '.sign.';
        $givenHeader = Binary::safeSubstr($signMsg, 0, 8);
        if (!\hash_equals($expectHeader, $givenHeader)) {
            throw new \Exception('Invalid message header.');
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, 8));
        $len = Binary::safeStrlen($decoded);
        $message = Binary::safeSubstr($decoded, 0, $len - SODIUM_CRYPTO_SIGN_BYTES);
        $signature = Binary::safeSubstr($decoded, $len - SODIUM_CRYPTO_SIGN_BYTES);

        $valid = \sodium_crypto_sign_verify_detached(
            $signature,
            Util::preAuthEncode([$givenHeader, $message, $footer]),
            $key->raw()
        );
        if (!$valid) {
            throw new \Exception('Invalid signature for this message');
        }
        return $message;
    }

    /**
     * @param string $plaintext
     * @param string $header
     * @param SymmetricEncryptionKey $key
     * @param string $footer
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public static function aeadEncrypt(
        string $plaintext,
        string $header,
        SymmetricEncryptionKey $key,
        string $footer = ''
    ): string {
        $nonce = \random_bytes(\ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            Util::preAuthEncode([$header, $nonce, $footer]),
            $nonce,
            $key->raw()
        );
        if ($footer) {
            return $header .
                Base64UrlSafe::encode($nonce . $ciphertext) .
                '.' .
                Base64UrlSafe::encode($footer);
        }
        return $header . Base64UrlSafe::encode($nonce . $ciphertext);
    }

    /**
     * @param string $message
     * @param string $header
     * @param SymmetricEncryptionKey $key
     * @param string $footer
     * @return string
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function aeadDecrypt(
        string $message,
        string $header,
        SymmetricEncryptionKey $key,
        string $footer = ''
    ): string {
        $expectedLen = Binary::safeStrlen($header);
        $givenHeader = Binary::safeSubstr($message, 0, $expectedLen);
        if (!\hash_equals($header, $givenHeader)) {
            throw new \Exception('Invalid message header.');
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($message, $expectedLen));
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
            Util::preAuthEncode([$header, $nonce, $footer]),
            $nonce,
            $key->raw()
        );
    }
}
