<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Keys;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\PAST\KeyInterface;
use ParagonIE\PAST\Protocol\Version2;

/**
 * Class SymmetricAuthenticationKey
 * @package ParagonIE\PAST\Keys
 */
class SymmetricAuthenticationKey implements KeyInterface
{
    /** @var string $key */
    protected $key = '';

    /** @var string $protocol */
    protected $protocol = Version2::HEADER;

    /**
     * SymmetricAuthenticationKey constructor.
     * @param string $keyMaterial
     * @param string $protocol
     */
    public function __construct(string $keyMaterial, string $protocol = Version2::HEADER)
    {
        $this->key = $keyMaterial;
        $this->protocol = $protocol;
    }

    /**
     * @return string
     */
    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    /**
     * @param string $encoded
     * @return self
     */
    public static function fromEncodedString(string $encoded): self
    {
        $decoded = Base64UrlSafe::decode($encoded);
        return new self($decoded);
    }

    /**
     * @return string
     */
    public function getProtocol(): string
    {
        return $this->protocol;
    }

    /**
     * @return string
     */
    public function raw()
    {
        return $this->key;
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [];
    }
}
