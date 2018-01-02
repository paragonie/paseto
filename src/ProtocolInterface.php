<?php
declare(strict_types=1);
namespace ParagonIE\PAST;

use ParagonIE\PAST\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricAuthenticationKey,
    SymmetricEncryptionKey
};

/**
 * Interface ProtocolInterface
 * @package ParagonIE\PAST
 */
interface ProtocolInterface
{
    /**
     * @param string $data
     * @param SymmetricAuthenticationKey $key
     * @return string
     */
    public static function auth(string $data, SymmetricAuthenticationKey $key): string;

    /**
     * @param string $authMsg
     * @param SymmetricAuthenticationKey $key
     * @return string
     * @throws \Exception
     * @throws \TypeError
     */
    public static function authVerify(string $authMsg, SymmetricAuthenticationKey $key): string;

    /**
     * @param string $data
     * @param SymmetricEncryptionKey $key
     * @return string
     */
    public static function encrypt(string $data, SymmetricEncryptionKey $key): string;

    /**
     * @param string $data
     * @param SymmetricEncryptionKey $key
     * @return string
     * @throws \Exception
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function decrypt(string $data, SymmetricEncryptionKey $key): string;

    /**
     * @param string $data
     * @param AsymmetricPublicKey $key
     * @return string
     * @throws \Error
     * @throws \TypeError
     */
    public static function seal(string $data, AsymmetricPublicKey $key): string;

    /**
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @return string
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public static function unseal(string $data, AsymmetricSecretKey $key): string;
}
