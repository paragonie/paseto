<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
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

use Exception;
use SodiumException;
use TypeError;
use function random_bytes,
    sodium_crypto_generichash;

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
        $this->protocol = $protocol ?? new Version4;
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
        return new static(
            random_bytes($protocol::getSymmetricKeyByteLength()),
            $protocol
        );
    }

    /**
     * Initialize a v1 symmetric key.
     *
     * @param string $keyMaterial
     *
     * @return self
     *
     * @throws Exception
     * @throws TypeError
     *
     * @deprecated See Version3 instead.
     */
    public static function v1(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version1());
    }

    /**
     * Initialize a v2 symmetric key.
     *
     * @param string $keyMaterial
     *
     * @return self
     *
     * @throws Exception
     * @throws TypeError
     *
     * @deprecated See Version4 instead.
     */
    public static function v2(string $keyMaterial): self
    {
        return new self($keyMaterial, new Version2());
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
     * @throws PasetoException
     * @throws TypeError
     */
    public function splitV3(string $salt): array
    {
        $tmp = Util::HKDF(
            'sha384',
            $this->key,
            48,
            self::INFO_ENCRYPTION . $salt
        );
        $encKey = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 16);
        $authKey = Util::HKDF(
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
     * Split this key into two 256-bit keys, using HKDF-SHA384
     * (with the given salt)
     *
     * Used in versions 1 and 2
     *
     * @param string $salt
     * @return array<int, string>
     *
     * @throws PasetoException
     * @throws TypeError
     */
    public function split(string $salt): array
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
