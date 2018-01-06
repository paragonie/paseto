<?php
declare(strict_types=1);
namespace ParagonIE\PAST;

use ParagonIE\PAST\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricAuthenticationKey,
    SymmetricKey
};

/**
 * Interface ProtocolInterface
 * @package ParagonIE\PAST
 */
interface ProtocolInterface
{
    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $nonceForUnitTesting
     * @return string
     */
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $nonceForUnitTesting = ''
    ): string;

    /**
     * Decrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @return string
     * @throws \Exception
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function decrypt(string $data, SymmetricKey $key, string $footer = ''): string;

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @return string
     */
    public static function sign(string $data, AsymmetricSecretKey $key, string $footer = ''): string;

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
    public static function verify(string $signMsg, AsymmetricPublicKey $key, string $footer = ''): string;
}
