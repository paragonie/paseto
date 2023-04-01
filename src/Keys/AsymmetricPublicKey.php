<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use FG\ASN1\Exception\ParserException;
use ParagonIE\Paseto\Exception\{
    InvalidVersionException,
    PasetoException
};
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey as BaseAsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version3\AsymmetricPublicKey as V3AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey as V4AsymmetricPublicKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use Exception;

class AsymmetricPublicKey extends BaseAsymmetricPublicKey
{
    public function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol
    ) {
        parent::__construct($keyMaterial, $protocol);
    }

    /**
     * @return string
     * @throws Exception
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function encode(): string
    {
        if ($this->protocol instanceof Version3) {
            return (new V3AsymmetricPublicKey($this->key))->encode();
        }
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricPublicKey($this->key))->encode();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @return string
     * @throws Exception
     * @throws InvalidVersionException
     */
    public function encodePem(): string
    {
        if ($this->protocol instanceof Version3) {
            return (new V3AsymmetricPublicKey($this->key))->encodePem();
        }
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricPublicKey($this->key))->encodePem();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @return string
     * @throws Exception
     * @throws InvalidVersionException
     * @throws ParserException
     */
    public function toHexString(): string
    {
        if ($this->protocol instanceof Version3) {
            return (new V3AsymmetricPublicKey($this->key))->toHexString();
        }
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricPublicKey($this->key))->toHexString();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }
}
