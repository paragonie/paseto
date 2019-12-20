<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys\Version2;

use ParagonIE\Paseto\Keys\AsymmetricPublicKey as BasePublicKey;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\Paseto\Keys\Version2
 */
class AsymmetricPublicKey extends BasePublicKey
{
    /**
     * AsymmetricPublicKey constructor.
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
