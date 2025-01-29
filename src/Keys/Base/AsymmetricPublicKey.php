<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Base;

use Exception;
use FG\ASN1\Exception\ParserException;
use ParagonIE\Paseto\{
    Exception\ExceptionCode,
    Exception\InvalidVersionException,
    Exception\PasetoException,
    ProtocolInterface,
    ReceivingKey,
    Util
};
use ParagonIE\Paseto\Keys\{
    Version3\AsymmetricPublicKey as V3AsymmetricPublicKey,
    Version4\AsymmetricPublicKey as V4AsymmetricPublicKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use TypeError;
use function hash_equals;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\Paseto\Keys
 */
abstract class AsymmetricPublicKey implements ReceivingKey
{
    protected string $key;
    protected ProtocolInterface $protocol;

    /**
     * AsymmetricPublicKey constructor.
     *
     * @param string $keyMaterial
     * @param ProtocolInterface $protocol
     *
     * @throws Exception
     */
    protected function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol
    ) {
        $this->key = $keyMaterial;
        $this->protocol = $protocol;
    }

    /**
     * Wipe secrets before freeing memory
     */
    public function __destruct()
    {
        Util::wipe($this->key);
    }

    /**
     * This used to initialize a v1 public key, but it was deprecated then removed.
     *
     * @throws InvalidVersionException
     */
    public static function v1(string $keyMaterial): static
    {
        throw new InvalidVersionException("Version 1 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * This used to initialize a v2 public key, but it was deprecated then removed.
     *
     * @throws InvalidVersionException
     */
    public static function v2(string $keyMaterial): static
    {
        throw new InvalidVersionException("Version 2 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * Initialize a v3 public key.
     *
     * @throws Exception
     */
    public static function v3(string $keyMaterial): V3AsymmetricPublicKey
    {
        return new V3AsymmetricPublicKey($keyMaterial);
    }

    /**
     * Initialize a v4 public key.
     *
     * @throws Exception
     */
    public static function v4(string $keyMaterial): V4AsymmetricPublicKey
    {
        return new V4AsymmetricPublicKey($keyMaterial);
    }

    /**
     * Initialize a public key.
     *
     * @throws Exception
     */
    public static function newVersionKey(
        string $keyMaterial,
        ?ProtocolInterface $protocol = null,
    ): self
    {
        $protocol = $protocol ?? new Version4();

        if (hash_equals($protocol::header(), Version3::HEADER)) {
            return new V3AsymmetricPublicKey($keyMaterial);
        }

        return new V4AsymmetricPublicKey($keyMaterial);
    }

    /**
     * Returns the base64url-encoded public key.
     *
     * @throws TypeError
     * @throws PasetoException
     */
    abstract public function encode(): string;

    /**
     * Return a PEM-encoded public key
     */
    abstract public function encodePem(): string;

    /**
     * Initialize a public key from a base64url-encoded string.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function fromEncodedString(
        string $encoded,
        ?ProtocolInterface $version = null,
    ): self
    {
        if (!$version) {
            $version = new Version4();
        }
        if (hash_equals($version::header(), Version3::HEADER)) {
            return V3AsymmetricPublicKey::fromEncodedString($encoded, $version);
        } else {
            return V4AsymmetricPublicKey::fromEncodedString($encoded, $version);
        }
    }


    /**
     * @throws Exception
     */
    public static function importPem(string $pem, ?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4();

        if ($protocol instanceof Version3) {
            return V3AsymmetricPublicKey::importPem($pem);
        }
        if ($protocol instanceof Version4) {
            return V4AsymmetricPublicKey::importPem($pem);
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @throws ParserException
     */
    abstract public function toHexString(): string;

    /**
     * Get the version of PASETO that this key is intended for.
     */
    public function getProtocol(): ProtocolInterface
    {
        return $this->protocol;
    }

    public function isForVersion(ProtocolInterface $protocol): bool
    {
        return $this->protocol instanceof $protocol;
    }

    /**
     * Get the raw key contents.
     */
    public function raw(): string
    {
        return $this->key;
    }

    /**
     * @return array<>
     */
    public function __debugInfo()
    {
        return [];
    }
}
