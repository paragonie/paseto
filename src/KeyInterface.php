<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

/**
 * Interface KeyInterface
 * @package ParagonIE\Paseto
 */
interface KeyInterface
{
    /**
     * The intended version for this protocol. Currently only meaningful
     * in asymmetric cryptography.
     *
     * @return ProtocolInterface
     */
    public function getProtocol(): ProtocolInterface;

    /**
     * @return string
     */
    public function raw();

    /**
     * @return array
     */
    public function __debugInfo();
}
