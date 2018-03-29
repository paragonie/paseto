<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Paseto\{
    ReceivingKey,
    SendingKey,
    ProtocolInterface,
    Protocol\Version1,
    Protocol\Version2,
    Util
};

/**
 * Class SymmetricKey
 * @package ParagonIE\Paseto\Keys
 */
class SymmetricKey implements ReceivingKey, SendingKey
{
    const INFO_ENCRYPTION = 'paseto-encryption-key';
    const INFO_AUTHENTICATION = 'paseto-auth-key-for-aead';

    /** @var string $key */
    protected $key = '';

    /** @var ProtocolInterface $protocol */
    protected $protocol;

    /**
     * SymmetricKey constructor.
     *
     * @param string $keyMaterial
     * @param ProtocolInterface|null $protocol
     */
    public function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol = null
    ) {
        $this->key = $keyMaterial;
        $this->protocol = $protocol ?? new Version2;
    }

    /**
     * @param ProtocolInterface|null $protocol
     *
     * @return SymmetricKey
     */
    public static function generate(ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version2;
        return new static(
            \random_bytes($protocol::getSymmetricKeyByteLength()),
            $protocol
        );
    }

    /**
     * @param string $keyMaterial
     *
     * @return self
     * @throws \Exception
     * @throws \TypeError
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
     * @throws \TypeError
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
     * @return self
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
    public function raw(): string
    {
        return $this->key;
    }

    /**
     * Split this key into two 256-bit keys, using HKDF-SHA384
     * (with the given salt)
     *
     * @param string|null $salt
     * @return array<int, string>
     *
     * @throws \ParagonIE\Paseto\Exception\PasetoException
     * @throws \TypeError
     */
    public function split(string $salt = null): array
    {
        $encKey = Util::HKDF(
            'sha384',
            $this->key,
            32,
            self::INFO_ENCRYPTION,
            $salt
        );
        $authKey = Util::HKDF(
            'sha384',
            $this->key,
            32,
            self::INFO_AUTHENTICATION,
            $salt
        );
        return [$encKey, $authKey];
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [];
    }
}
