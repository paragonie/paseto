<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Version3;

use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\SymmetricKey as BaseSymmetricKey;
use ParagonIE\Paseto\Protocol\Version3;

/**
 * Class SymmetricKey.php
 * @package ParagonIE\Paseto\Keys\Version3
 * @api
 */
class SymmetricKey extends BaseSymmetricKey
{
    /**
     * SymmetricKey.php constructor.
     *
     * @param string $keyMaterial
     * @throws PasetoException
     */
    public function __construct(
        string $keyMaterial
    ) {
        parent::__construct($keyMaterial, new Version3());
    }
}
