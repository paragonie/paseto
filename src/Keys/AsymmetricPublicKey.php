<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\{
    Base64,
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\Paseto\{
    Exception\ExceptionCode,
    Exception\InvalidVersionException,
    Exception\PasetoException,
    ReceivingKey,
    ProtocolInterface,
    Util
};
use FG\ASN1\Exception\ParserException;
use ParagonIE\EasyECC\ECDSA\PublicKey;
use ParagonIE\Paseto\Protocol\{
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
    protected string $key;
    protected ProtocolInterface $protocol;

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

        if (hash_equals($protocol::header(), Version4::HEADER)) {
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
        } elseif (hash_equals($protocol::header(), Version3::HEADER)) {
            $len = Binary::safeStrlen($keyMaterial);
            if ($len === 98) {
                $keyMaterial = Version3::getPublicKeyPem($keyMaterial);
            } elseif ($len === 49) {
                $keyMaterial = Version3::getPublicKeyPem(Hex::encode($keyMaterial));
            }
        }
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
     * @param string $keyMaterial
     * @return self
     *
     * @throws InvalidVersionException
     */
    public static function v1(string $keyMaterial): self
    {
        throw new InvalidVersionException("Version 1 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * This used to initialize a v2 public key, but it was deprecated then removed.
     *
     * @param string $keyMaterial
     * @return self
     *
     * @throws InvalidVersionException
     */
    public static function v2(string $keyMaterial): self
    {
        throw new InvalidVersionException("Version 2 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * Initialize a v3 public key.
     *
     * @param string $keyMaterial
     * @return self
     *
     * @throws Exception
     */
    public static function v3(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version3());
    }

    /**
     * Initialize a v4 public key.
     *
     * @param string $keyMaterial
     * @return self
     *
     * @throws Exception
     */
    public static function v4(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version4());
    }

    /**
     * Returns the base64url-encoded public key.
     *
     * @return string
     *
     * @throws TypeError
     * @throws PasetoException
     */
    public function encode(): string
    {
        if (hash_equals($this->protocol::header(), Version3::HEADER)) {
            if (Binary::safeStrlen($this->key) === 49) {
                Base64UrlSafe::encodeUnpadded($this->key);
            } elseif (Binary::safeStrlen($this->key) === 98) {
                Base64UrlSafe::encodeUnpadded(Hex::decode($this->key));
            }
            try {
                return Base64UrlSafe::encodeUnpadded(
                    Hex::decode(
                        Version3::getPublicKeyCompressed($this->key)
                    )
                );
            } catch (ParserException $ex) {
                throw new PasetoException("ASN.1 Parser Exception", 0, $ex);
            }
        }
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    /**
     * Return a PEM-encoded public key
     *
     * @return string
     */
    public function encodePem(): string
    {
        switch ($this->protocol::header()) {
            case 'v3':
                if (Binary::safeStrlen($this->key) > 49) {
                    return $this->key;
                }
                return Util::dos2unix(
                    PublicKey::fromString($this->key, 'P384')
                        ->exportPem()
                );
            case 'v4':
                $encoded = Base64::encode(
                    Hex::decode('302a300506032b6570032100') . $this->raw()
                );
                return "-----BEGIN PUBLIC KEY-----\n" .
                    Util::dos2unix(chunk_split($encoded, 64)).
                    "-----END PUBLIC KEY-----";
            default:
                throw new PasetoException("Unknown version");
        }

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
        if (!$version) {
            $version = new Version4();
        }
        if (hash_equals($version::header(), Version3::HEADER)) {
            $decodeString = Base64UrlSafe::decode($encoded);
            $length = Binary::safeStrlen($encoded);
            if ($length === 98) {
                $decoded = Version3::getPublicKeyPem($decodeString);
            } elseif ($length === 49) {
                $decoded = Version3::getPublicKeyPem(Hex::encode($decodeString));
            } else {
                $decoded = $decodeString;
            }
        } else {
            $decoded = Base64UrlSafe::decode($encoded);
        }
        return new self($decoded, $version);
    }

    /**
     * @return string
     * @throws ParserException
     */
    public function toHexString(): string
    {
        if (hash_equals($this->protocol::header(), Version3::HEADER)) {
            if (Binary::safeStrlen($this->key) === 98) {
                return $this->key;
            }
            if (Binary::safeStrlen($this->key) !== 49) {
                return Version3::getPublicKeyCompressed($this->key);
            }
        }
        return Hex::encode($this->key);
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
     * @param ProtocolInterface $protocol
     * @return bool
     */
    public function isForVersion(ProtocolInterface $protocol): bool
    {
        return $this->protocol instanceof $protocol;
    }

    /**
     * Get the raw key contents.
     *
     * @return string
     */
    public function raw(): string
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
