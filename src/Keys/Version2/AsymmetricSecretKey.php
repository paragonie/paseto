<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Version2;

use ParagonIE\Paseto\Keys\AsymmetricSecretKey as BaseSecretKey;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\Paseto\Keys\Version2
 */
class AsymmetricSecretKey extends BaseSecretKey
{
    /**
     * AsymmetricSecretKey constructor.
     *
     * @param string $keyData
     * @param ProtocolInterface|null $protocol
     *
     * @throws \Exception
     * @throws \TypeError
     */
    public function __construct(string $keyData, ProtocolInterface $protocol = null)
    {
        parent::__construct($keyData, new Version2());
    }
}
