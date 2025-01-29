<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Version4;

use ParagonIE\Paseto\Keys\SymmetricKey as BaseSymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;

/**
 * Class SymmetricKey.php
 * @package ParagonIE\Paseto\Keys\Version4
 */
class SymmetricKey extends BaseSymmetricKey
{
    /**
     * SymmetricKey.php constructor.
     */
    public function __construct(
        string $keyMaterial
    ) {
        parent::__construct($keyMaterial, new Version4());
    }
}
