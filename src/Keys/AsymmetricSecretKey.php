<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\Paseto\Exception\{
    InvalidVersionException,
    PasetoException
};
use ParagonIE\Paseto\Keys\Base\{
    AsymmetricPublicKey,
    AsymmetricSecretKey as BaseAsymmetricSecretKey
};
use ParagonIE\Paseto\Keys\Version3\AsymmetricSecretKey as V3AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey as V4AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use Exception;

class AsymmetricSecretKey extends BaseAsymmetricSecretKey
{
    public function __construct(
        string $keyData,
        ProtocolInterface $protocol = null
    ) {
        if (is_null($protocol)) {
            $protocol = new Version4();
        }
        parent::__construct($keyData, $protocol);
    }

    /**
     * @return string
     *
     * @throws Exception
     * @throws InvalidVersionException
     */
    public function encode(): string
    {
        if ($this->protocol instanceof Version3) {
            return (new V3AsymmetricSecretKey($this->key))->encode();
        }
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricSecretKey($this->key))->encode();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @return string
     * @throws Exception
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function encodePem(): string
    {
        if ($this->protocol instanceof Version3) {
            return (new V3AsymmetricSecretKey($this->key))->encodePem();
        }
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricSecretKey($this->key))->encodePem();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @return AsymmetricPublicKey
     *
     * @throws \Exception
     * @throws InvalidVersionException
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        if ($this->protocol instanceof Version3) {
            return (new V3AsymmetricSecretKey($this->key))->getPublicKey();
        }
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricSecretKey($this->key))->getPublicKey();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }
}
