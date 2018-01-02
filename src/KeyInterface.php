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
