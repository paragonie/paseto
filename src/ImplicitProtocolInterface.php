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
interface ImplicitProtocolInterface extends ProtocolInterface
{
    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     */
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = ''
    ): string;

    /**
     * Decrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string|null $footer
     * @param string $implicit
     * @return string
     */
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        string $footer = null,
        string $implicit = ''
    ): string;

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     */
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = '',
        string $implicit = ''
    ): string;

    /**
     * Verify a signed message. Public-key digital signatures.
     *
     * @param string $signMsg
     * @param AsymmetricPublicKey $key
     * @param string|null $footer
     * @param string $implicit
     * @return string
     */
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        string $footer = null,
        string $implicit = ''
    ): string;
}
