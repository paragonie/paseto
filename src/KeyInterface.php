<?php
declare(strict_types=1);
namespace ParagonIE\PAST;

/**
 * Interface KeyInterface
 * @package ParagonIE\PAST
 */
interface KeyInterface
{
    /**
     * The intended version for this protocol. Currently only meaningful
     * in asymmetric cryptography.
     *
     * @return string
     */
    public function getProtocol(): string;

    /**
     * @return string
     */
    public function raw();

    /**
     * @return array
     */
    public function __debugInfo();
}
