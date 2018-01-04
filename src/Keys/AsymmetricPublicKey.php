<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Keys;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\PAST\KeyInterface;
use ParagonIE\PAST\Protocol\Version2;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\PAST\Keys
 */
class AsymmetricPublicKey implements KeyInterface
{
    /** @var string $key */
    protected $key = '';

    /** @var string $protocol */
    protected $protocol = Version2::HEADER;

    /**
     * AsymmetricPublicKey constructor.
     * @param string $keyMaterial
     * @param string $protocol
     * @throws \Exception
     */
    public function __construct(string $keyMaterial, string $protocol = Version2::HEADER)
    {
        if (\hash_equals($protocol, Version2::HEADER)) {
            $len = Binary::safeStrlen($keyMaterial);
            if ($len !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new \Exception('Public keys must be 32 bytes long; ' . $len . ' given.');
            }
        }
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
