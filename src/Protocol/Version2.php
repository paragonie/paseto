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
use phpseclib\Crypt\RSA;

/**
 * Class Version1
 * @package ParagonIE\PAST\Protocol
 */
class Version2 implements ProtocolInterface
{
    /** @const string HEADER */
    const HEADER = 'v2';

    /**
     * @param string $data
     * @param SymmetricAuthenticationKey $key
     * @return string
     */
    public static function auth(string $data, SymmetricAuthenticationKey $key): string
    {
        $header = self::HEADER . '.auth.';
        $mac = \sodium_crypto_auth(
            $header . $data,
            $key->raw()
        );
        return $header . Base64UrlSafe::encode($data . $mac);
    }

    /**
     * @param string $authMsg
     * @param SymmetricAuthenticationKey $key
     * @return string
     * @throws \Exception
     * @throws \TypeError
     */
    public static function authVerify(string $authMsg, SymmetricAuthenticationKey $key): string
    {
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
        if (!\sodium_crypto_auth_verify($mac, $givenHeader . $message, $key->raw())) {
            throw new \Exception('Invalid MAC');
        }
        return $message;
    }

    /**
     * @param string $data
     * @param SymmetricEncryptionKey $key
     * @return string
     * @throws \Error
     * @throws \TypeError
     */
    public static function encrypt(string $data, SymmetricEncryptionKey $key): string
    {
        $header = self::HEADER . '.enc.';
        return self::aeadEncrypt($data, $header, $key);
    }

    /**
     * @param string $data
     * @param SymmetricEncryptionKey $key
     * @return string
     * @throws \Exception
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function decrypt(string $data, SymmetricEncryptionKey $key): string
    {
        $header = self::HEADER . '.enc.';
        return self::aeadDecrypt($data, $header, $key);
    }

    /**
     * @param string $data
     * @param AsymmetricPublicKey $key
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public static function seal(string $data, AsymmetricPublicKey $key): string
    {
        $header = self::HEADER . '.seal.';

        $recipPublic = \sodium_crypto_sign_ed25519_pk_to_curve25519($key->raw());

        // Ephemeral keypairs
        $ephKeypair = \sodium_crypto_box_keypair();
        $ephSecret = \sodium_crypto_box_secretkey($ephKeypair);
        $ephPublic = \sodium_crypto_box_publickey($ephKeypair);
        try {
            \sodium_memzero($ephKeypair);
        } catch (\Throwable $ex) {
        }

        $symmetricKey = new SymmetricEncryptionKey(
            \ParagonIE_Sodium_Compat::crypto_kx(
                $ephSecret,
                $recipPublic,
                $ephPublic,
                $recipPublic
            )
        );

        try {
            \sodium_memzero($ephKeypair);
            \sodium_memzero($ephSecret);
        } catch (\Throwable $ex) {
        }

        $header .= Base64UrlSafe::encode($ephPublic) . '.';

        return self::aeadEncrypt($data, $header, $symmetricKey);
    }

    /**
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @return string
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function unseal(string $data, AsymmetricSecretKey $key): string
    {
        $header = self::HEADER . '.seal.';
        $givenHeader = Binary::safeSubstr($data, 0, 8);
        if (!\hash_equals($header, $givenHeader)) {
            throw new \Exception('Invalid message header.');
        }

        $pieces = \explode('.', $data);
        if (\count($pieces) !== 4) {
            throw new \Exception('Invalid sealed message');
        }
        $ephPublic = Base64UrlSafe::decode($pieces[2]);

        $mySecret = \sodium_crypto_sign_ed25519_sk_to_curve25519($key->raw());
        $myPublic = \sodium_crypto_box_publickey_from_secretkey($mySecret);

        $symmetricKey = new SymmetricEncryptionKey(
            \ParagonIE_Sodium_Compat::crypto_kx(
                $mySecret,
                $ephPublic,
                $ephPublic,
                $myPublic
            )
        );

        $header .= Base64UrlSafe::encode($ephPublic) . '.';
        return self::aeadDecrypt(
            $data,
            $header,
            $symmetricKey
        );
    }

    /**
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @return string
     */
    public static function sign(string $data, AsymmetricSecretKey $key): string
    {
        $header = self::HEADER . '.sign.';
        $signature = \sodium_crypto_sign_detached($header . $data, $key->raw());
        return $header . Base64UrlSafe::encode($data . $signature);
    }

    /**
     * @param string $signMsg
     * @param AsymmetricPublicKey $key
     * @return string
     * @throws \Exception
     * @throws \TypeError
     */
    public static function signVerify(string $signMsg, AsymmetricPublicKey $key): string
    {
        $expectHeader = self::HEADER . '.sign.';
        $givenHeader = Binary::safeSubstr($signMsg, 0, 8);
        if (!\hash_equals($expectHeader, $givenHeader)) {
            throw new \Exception('Invalid message header.');
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signMsg, 8));
        $len = Binary::safeStrlen($decoded);
        $message = Binary::safeSubstr($decoded, 0, $len - SODIUM_CRYPTO_SIGN_BYTES);
        $signature = Binary::safeSubstr($decoded, $len - SODIUM_CRYPTO_SIGN_BYTES);

        if (!\sodium_crypto_sign_verify_detached($signature, $givenHeader . $message, $key->raw())) {
            throw new \Exception('Invalid signature for this message');
        }
        return $message;
    }

    /**
     * @param string $plaintext
     * @param string $aad
     * @param SymmetricEncryptionKey $key
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public static function aeadEncrypt(string $plaintext, string $aad, SymmetricEncryptionKey $key): string
    {
        $nonce = \random_bytes(\ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $aad . $nonce,
            $nonce,
            $key->raw()
        );
        return $aad . Base64UrlSafe::encode($nonce . $ciphertext);
    }

    /**
     * @param string $message
     * @param string $aad
     * @param SymmetricEncryptionKey $key
     * @return string
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function aeadDecrypt(string $message, string $aad, SymmetricEncryptionKey $key): string
    {
        $expectedLen = Binary::safeStrlen($aad);
        $givenHeader = Binary::safeSubstr($message, 0, $expectedLen);
        if (!\hash_equals($aad, $givenHeader)) {
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
            $aad . $nonce,
            $nonce,
            $key->raw()
        );
    }
}
