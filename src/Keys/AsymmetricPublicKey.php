<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paseto\{
    ReceivingKey,
    ProtocolInterface
};
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2
};

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\Paseto\Keys
 */
class AsymmetricPublicKey implements ReceivingKey
{
    /** @var string $key */
    protected $key = '';

    /** @var ProtocolInterface $protocol */
    protected $protocol;

    /**
     * AsymmetricPublicKey constructor.
     * @param string $keyMaterial
     * @param ProtocolInterface $protocol
     * @throws \Exception
     */
    public function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol = null
    ) {
        $protocol = $protocol ?? new Version2;

        if (\hash_equals($protocol::header(), Version2::HEADER)) {
            $len = Binary::safeStrlen($keyMaterial);
            if ($len !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new \Exception(
                    'Public keys must be 32 bytes long; ' . $len . ' given.'
                );
            }
        }
        $this->key = $keyMaterial;
        $this->protocol = $protocol;
    }

    /**
     * @param string $keyMaterial
     *
     * @return self
     * @throws \Exception
     */
    public static function v1(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version1());
    }

    /**
     * @param string $keyMaterial
     *
     * @return self
     * @throws \Exception
     */
    public static function v2(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version2());
    }

    /**
     * @return string
     * @throws \TypeError
     */
    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    /**
     * @param string $encoded
     * @param ProtocolInterface|null $version
     *
     * @return self
     * @throws \Exception
     * @throws \TypeError
     */
    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        $decoded = Base64UrlSafe::decode($encoded);
        return new self($decoded, $version);
    }

    /**
     * @return ProtocolInterface
     */
    public function getProtocol(): ProtocolInterface
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
