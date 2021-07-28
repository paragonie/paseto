<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\{
    Exception\PasetoException,
    ReceivingKey,
    SendingKey,
    ProtocolInterface,
    Protocol\Version1,
    Protocol\Version2,
    Protocol\Version3,
    Protocol\Version4,
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
     * @param string $keyMaterial
     *
     * @return self
     * @throws \Exception
     * @throws \TypeError
     */
    public static function v3(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version3());
    }

    /**
     * @param string $keyMaterial
     *
     * @return self
     * @throws \Exception
     * @throws \TypeError
     */
    public static function v4(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version4());
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
        return new static($decoded, $version);
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
     * Split this key into two 256-bit keys and a nonce, using HKDF-SHA384
     * (with the given salt)
     *
     * Used in version 3
     *
     * @param string|null $salt
     * @return array<int, string>
     *
     * @throws PasetoException
     * @throws \TypeError
     */
    public function splitV3(string $salt = null): array
    {
        $tmp = Util::HKDF(
            'sha384',
            $this->key,
            48,
            self::INFO_ENCRYPTION,
            $salt
        );
        $encKey = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 16);
        $authKey = Util::HKDF(
            'sha384',
            $this->key,
            32,
            self::INFO_AUTHENTICATION,
            $salt
        );
        return [$encKey, $authKey, $nonce];
    }


    /**
     * Split this key into two 256-bit keys and a nonce, using BLAKE2b-MAC
     * (with the given salt)
     *
     * Used in version 4
     *
     * @param string|null $salt
     * @return array<int, string>
     *
     * @throws \SodiumException
     */
    public function splitV4(string $salt = null): array
    {
        $tmp = \sodium_crypto_generichash(
            self::INFO_ENCRYPTION . ($salt ?? ''),
            $this->key,
            56
        );
        $encKey = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 24);
        $authKey = \sodium_crypto_generichash(
            self::INFO_AUTHENTICATION . ($salt ?? ''),
            $this->key
        );
        return [$encKey, $authKey, $nonce];
    }

    /**
     * Split this key into two 256-bit keys, using HKDF-SHA384
     * (with the given salt)
     *
     * @param string|null $salt
     * @return array<int, string>
     *
     * @throws PasetoException
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
