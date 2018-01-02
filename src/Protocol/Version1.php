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
class Version1 implements ProtocolInterface
{
    const HEADER = 'v1';
    const CIPHER_MODE = 'aes-256-ctr';
    const HASH_ALGO = 'sha384';

    const NONCE_SIZE = 32;
    const MAC_SIZE = 48;
    const SIGN_SIZE = 256; // 2048-bit RSA = 256 byte signature

    /**
     * @param string $data
     * @param SymmetricAuthenticationKey $key
     * @return string
     */
    public static function auth(string $data, SymmetricAuthenticationKey $key): string
    {
        $header = self::HEADER . '.auth.';
        $mac = \hash_hmac(
            self::HASH_ALGO,
            $header . $data,
            $key->raw(),
            true
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

        $message = Binary::safeSubstr($decoded, 0, $len - 48);
        $mac = Binary::safeSubstr($decoded, $len - 48);
        $calc = \hash_hmac(
            self::HASH_ALGO,
            $givenHeader . $message,
            $key->raw(),
            true
        );
        if (!\hash_equals($calc, $mac)) {
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
     * @throws \Error
     * @throws \TypeError
     */
    public static function seal(string $data, AsymmetricPublicKey $key): string
    {
        $header = self::HEADER . '.seal.';

        $rsa = self::getRsa(false);
        $rsa->loadKey($key->raw());

        // Random encryption key
        $randomKey = \random_bytes(32);

        // Use RSA to encrypt the random key
        $rsaOut = $rsa->encrypt($randomKey);

        // Use HKDF-SHA384 to derive a new key for this message:
        $symmetricKey = new SymmetricEncryptionKey(
            Util::HKDF(self::HASH_ALGO, $rsaOut, 32, 'rsa kem+dem', $randomKey)
        );

        $header .= Base64UrlSafe::encode($rsaOut) . '.';

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
        $rsaCipher = Base64UrlSafe::decode($pieces[2]);

        $rsa = self::getRsa(false);
        $rsa->loadKey($key->raw());
        $randomKey = $rsa->decrypt($rsaCipher);

        // Use HKDF-SHA384 to derive a new key for this message:
        $symmetricKey = new SymmetricEncryptionKey(
            Util::HKDF(self::HASH_ALGO, $rsaCipher, 32, 'rsa kem+dem', $randomKey)
        );
        $header .= Base64UrlSafe::encode($rsaCipher) . '.';

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
        $rsa = self::getRsa(true);
        $rsa->loadKey($key->raw());
        $signature = $rsa->sign($header . $data);
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
        $message = Binary::safeSubstr($decoded, 0, $len - self::SIGN_SIZE);
        $signature = Binary::safeSubstr($decoded, $len - self::SIGN_SIZE);

        $rsa = self::getRsa(true);
        $rsa->loadKey($key->raw());
        if (!$rsa->verify($givenHeader . $message, $signature)) {
            throw new \Exception('Invalid signature for this message');
        }
        return $message;
    }

    /**
     * @param string $plaintext
     * @param string $aad
     * @param SymmetricEncryptionKey $key
     * @return string
     * @throws \Error
     * @throws \TypeError
     */
    public static function aeadEncrypt(string $plaintext, string $aad, SymmetricEncryptionKey $key): string
    {
        $nonce = \random_bytes(self::NONCE_SIZE);
        list($encKey, $authKey) = $key->split(
            Binary::safeSubstr($nonce, 0, 16)
        );
        $ciphertext = \openssl_encrypt(
            $plaintext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );
        $mac = \hash_hmac(
            self::HASH_ALGO,
            $aad . $nonce . $ciphertext,
            $authKey,
            true
        );
        return $aad . Base64UrlSafe::encode($nonce . $ciphertext . $mac);
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
            $aad . $nonce . $ciphertext,
            $authKey,
            true
        );
        if (!\hash_equals($calc, $mac)) {
            throw new \Exception('Invalid MAC');
        }

        $plaintext = \openssl_decrypt(
            $ciphertext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );

        return $plaintext;
    }

    /** @var RSA */
    protected static $rsa;

    /**
     * Get the PHPSecLib RSA provider
     *
     * @param bool $signing
     * @return RSA
     */
    public static function getRsa(bool $signing): RSA
    {
        $rsa = new RSA();
        $rsa->setHash('sha384');
        $rsa->setMGFHash('sha384');
        if ($signing) {
            $rsa->setEncryptionMode(RSA::SIGNATURE_PSS);
        } else {
            $rsa->setEncryptionMode(RSA::ENCRYPTION_OAEP);
        }
        return $rsa;
    }

    /**
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
