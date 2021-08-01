<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\Paseto\{
    Exception\ExceptionCode,
    Exception\PasetoException,
    ReceivingKey,
    ProtocolInterface
};
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use Exception;
use TypeError;
use function hash_equals;

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
     *
     * @param string $keyMaterial
     * @param ProtocolInterface|null $protocol
     *
     * @throws Exception
     */
    public function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol = null
    ) {
        $protocol = $protocol ?? new Version4;

        if (
            hash_equals($protocol::header(), Version2::HEADER)
                ||
            hash_equals($protocol::header(), Version4::HEADER)
        ) {
            $len = Binary::safeStrlen($keyMaterial);
            if ($len === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES << 1) {
                // Try hex-decoding
                $keyMaterial = Hex::decode($keyMaterial);
            } else if ($len !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new PasetoException(
                    'Public keys must be 32 bytes long; ' . $len . ' given.',
                    ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
                );
            }
        }
        $this->key = $keyMaterial;
        $this->protocol = $protocol;
    }

    /**
     * Initialize a v1 public key.
     *
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
     * Initialize a v2 public key.
     *
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
     * Initialize a v3 public key.
     *
     * @param string $keyMaterial
     *
     * @return self
     * @throws \Exception
     */
    public static function v3(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version3());
    }

    /**
     * Initialize a v4 public key.
     *
     * @param string $keyMaterial
     *
     * @return self
     * @throws \Exception
     */
    public static function v4(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version4());
    }

    /**
     * Returns the base64url-encoded public key.
     *
     * @return string
     * @throws \TypeError
     */
    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    /**
     * Initialize a public key from a base64url-encoded string.
     *
     * @param string $encoded
     * @param ProtocolInterface|null $version
     * @return self
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        $decoded = Base64UrlSafe::decode($encoded);
        return new static($decoded, $version);
    }

    /**
     * Get the version of PASETO that this key is intended for.
     *
     * @return ProtocolInterface
     */
    public function getProtocol(): ProtocolInterface
    {
        return $this->protocol;
    }

    /**
     * Get the raw key contents.
     *
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
