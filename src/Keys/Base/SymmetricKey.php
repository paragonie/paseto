<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Base;

use Exception;
use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paseto\{
    Exception\ExceptionCode,
    Exception\InvalidVersionException,
    Exception\PasetoException,
    Protocol\Version3,
    Protocol\Version4,
    ProtocolInterface,
    ReceivingKey,
    SendingKey,
    Util
};
use SodiumException;
use TypeError;
use function random_bytes;
use function sodium_crypto_generichash;

/**
 * Class SymmetricKey
 * @package ParagonIE\Paseto\Keys
 */
class SymmetricKey implements ReceivingKey, SendingKey
{
    const INFO_ENCRYPTION = 'paseto-encryption-key';
    const INFO_AUTHENTICATION = 'paseto-auth-key-for-aead';

    protected string $key = '';
    protected ProtocolInterface $protocol;

    /**
     * SymmetricKey constructor.
     *
     * @param string $keyMaterial
     * @param ProtocolInterface|null $protocol
     *
     * @throws PasetoException
     */
    public function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol = null
    ) {
        $this->protocol = $protocol ?? new Version4;

        switch ($this->protocol::class) {
            case Version3::class:
                if (Binary::safeStrlen($keyMaterial) !== Version3::SYMMETRIC_KEY_BYTES) {
                    throw new PasetoException("Invalid key length");
                }
                break;
            case Version4::class:
                if (Binary::safeStrlen($keyMaterial) !== Version4::SYMMETRIC_KEY_BYTES) {
                    throw new PasetoException("Invalid key length");
                }
                break;
            default:
                throw new InvalidVersionException("Unsupported version", ExceptionCode::BAD_VERSION);
        }

        $this->key = $keyMaterial;
    }

    /**
     * Wipe secrets before freeing memory
     */
    public function __destruct()
    {
        Util::wipe($this->key);
    }

    /**
     * @param ProtocolInterface|null $protocol
     * @return SymmetricKey
     *
     * @throws Exception
     */
    public static function generate(ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4;
        $length = $protocol::getSymmetricKeyByteLength();
        if ($length < 32) {
            throw new PasetoException("Invalid key length");
        }
        return new self(
            random_bytes($length),
            $protocol
        );
    }

    /**
     * This used to initialize a v1 symmetric key, but it was deprecated then removed.
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
     * This used to initialize a v2 symmetric key, but it was deprecated then removed.
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
     * Initialize a v3 symmetric key.
     *
     * @param string $keyMaterial
     *
     * @return self
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function v3(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version3());
    }

    /**
     * Initialize a v4 symmetric key.
     *
     * @param string $keyMaterial
     *
     * @return self
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function v4(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version4());
    }

    /**
     * Return a base64url-encoded representation of this symmetric key.
     *
     * @return string
     *
     * @throws TypeError
     */
    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    /**
     * Initialize a symmetric key from a base64url-encoded string.
     *
     * @param string $encoded
     * @param ProtocolInterface|null $version
     * @return self
     *
     * @throws TypeError
     * @throws PasetoException
     */
    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);
        return new self($decoded, $version);
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
     * Split this key into two 256-bit keys and a nonce, using HKDF-SHA384
     * (with the given salt)
     *
     * Used in version 3
     *
     * @param string $salt
     * @return array<int, string>
     *
     * @throws TypeError
     */
    public function splitV3(string $salt): array
    {
        $tmp = hash_hkdf(
            'sha384',
            $this->key,
            48,
            self::INFO_ENCRYPTION . $salt
        );
        $encKey = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 16);
        $authKey = hash_hkdf(
            'sha384',
            $this->key,
            48,
            self::INFO_AUTHENTICATION . $salt
        );
        return [$encKey, $authKey, $nonce];
    }


    /**
     * Split this key into two 256-bit keys and a nonce, using BLAKE2b-MAC
     * (with the given salt)
     *
     * Used in version 4
     *
     * @param string $salt
     * @return array<int, string>
     *
     * @throws SodiumException
     */
    public function splitV4(string $salt): array
    {
        $tmp = sodium_crypto_generichash(
            self::INFO_ENCRYPTION . $salt,
            $this->key,
            56
        );
        $encKey = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 24);
        $authKey = sodium_crypto_generichash(
            self::INFO_AUTHENTICATION . $salt,
            $this->key
        );
        return [$encKey, $authKey, $nonce];
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [];
    }
}
