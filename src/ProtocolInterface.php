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
     * @return AsymmetricSecretKey
     */
    public static function generateAsymmetricSecretKey(): AsymmetricSecretKey;

    /**
     * @return SymmetricKey
     */
    public static function generateSymmetricKey(): SymmetricKey;

    /**
     * @return int
     */
    public static function getSymmetricKeyByteLength(): int;

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @return string
     */
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = ''
    ): string;

    /**
     * Decrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string|null $footer
     * @return string
     */
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        string $footer = null
    ): string;

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @return string
     */
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = ''
    ): string;

    /**
     * Verify a signed message. Public-key digital signatures.
     *
     * @param string $signMsg
     * @param AsymmetricPublicKey $key
     * @param string|null $footer
     * @return string
     */
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        string $footer = null
    ): string;
}
