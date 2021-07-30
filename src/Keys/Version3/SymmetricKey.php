<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Version3;

use ParagonIE\Paseto\Keys\SymmetricKey as BaseSymmetricKey;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class SymmetricKey
 * @package ParagonIE\Paseto\Keys\Version3
 */
class SymmetricKey extends BaseSymmetricKey
{
    /**
     * SymmetricKey constructor.
     *
     * @param string $keyMaterial
     * @param ProtocolInterface|null $protocol
     */
    public function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol = null
    ) {
        return parent::__construct($keyMaterial, new Version3());
    }
}
