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
     * Authenticate a message with a shared key.
     *
     * @param string $data
     * @param SymmetricAuthenticationKey $key
     * @param string $footer
     * @return string
     */
    public static function auth(string $data, SymmetricAuthenticationKey $key, string $footer = ''): string
    {
        $header = self::HEADER . '.auth.';
        $mac = \hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode([$header, $data, $footer]),
            $key->raw(),
            true
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
    public static function authVerify(string $authMsg, SymmetricAuthenticationKey $key, string $footer = ''): string
    {
        $authMsg = Util::validateAndRemoveFooter($authMsg, $footer);
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
            Util::preAuthEncode([$givenHeader, $message, $footer]),
            $key->raw(),
            true
        );
        if (!\hash_equals($calc, $mac)) {
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
     * @throws \Error
     * @throws \TypeError
     */
    public static function encrypt(string $data, SymmetricEncryptionKey $key, string $footer = ''): string
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
     * Encrypt a message using a recipient's public key.
     *
     * @param string $data
     * @param AsymmetricPublicKey $key
     * @param string $footer
     * @return string
     * @throws \Error
     * @throws \TypeError
     */
    public static function seal(string $data, AsymmetricPublicKey $key, string $footer = ''): string
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

        return self::aeadEncrypt($data, $header, $symmetricKey, $footer);
    }

    /**
     * Decrypt a message using your private key.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @return string
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function unseal(string $data, AsymmetricSecretKey $key, string $footer = ''): string
    {
        $data = Util::validateAndRemoveFooter($data, $footer);
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

        return self::aeadDecrypt($data, $header, $symmetricKey, $footer);
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
        $rsa = self::getRsa(true);
        $rsa->loadKey($key->raw());
        $signature = $rsa->sign(
            Util::preAuthEncode([$header, $data, $footer])
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
        $message = Binary::safeSubstr($decoded, 0, $len - self::SIGN_SIZE);
        $signature = Binary::safeSubstr($decoded, $len - self::SIGN_SIZE);

        $rsa = self::getRsa(true);
        $rsa->loadKey($key->raw());
        $valid = $rsa->verify(
            Util::preAuthEncode([$givenHeader, $message, $footer]),
            $signature
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
     * @throws \Error
     * @throws \TypeError
     */
    public static function aeadEncrypt(
        string $plaintext,
        string $header,
        SymmetricEncryptionKey $key,
        string $footer = ''
    ): string {
        $nonce = \random_bytes(self::NONCE_SIZE);
        list($encKey, $authKey) = $key->split(
            Binary::safeSubstr($nonce, 0, 16)
        );
        /** @var string $ciphertext */
        $ciphertext = \openssl_encrypt(
            $plaintext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );
        if (!\is_string($ciphertext)) {
            throw new \Error('Encryption failed.');
        }
        $mac = \hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode([$header, $nonce, $ciphertext, $footer]),
            $authKey,
            true
        );
        if ($footer) {
            return $header .
                Base64UrlSafe::encode($nonce . $ciphertext . $mac) .
                '.' .
                Base64UrlSafe::encode($footer);
        }
        return $header . Base64UrlSafe::encode($nonce . $ciphertext . $mac);
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
            Util::preAuthEncode([$header, $nonce, $ciphertext, $footer]),
            $authKey,
            true
        );
        if (!\hash_equals($calc, $mac)) {
            throw new \Exception('Invalid MAC');
        }

        /** @var string $plaintext */
        $plaintext = \openssl_decrypt(
            $ciphertext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            Binary::safeSubstr($nonce, 16, 16)
        );
        if (!\is_string($plaintext)) {
            throw new \Error('Encryption failed.');
        }

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
