<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};

/**
 * Interface ProtocolInterface
 * @package ParagonIE\Paseto
 */
interface ProtocolInterface
{
    /**
     * Must be constructable with no arguments so an instance may be passed
     * around in a type safe way.
     */
    public function __construct();

    /**
     * A unique header string with which the protocol can be identified.
     *
     * @return string
     */
    public static function header(): string;

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
