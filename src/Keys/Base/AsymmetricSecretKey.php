<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Base;

use Exception;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\{
    Exception\ExceptionCode,
    Exception\InvalidVersionException,
    Exception\PasetoException,
    Exception\SecurityException,
    ProtocolInterface,
    SendingKey,
    Util
};
use ParagonIE\Paseto\Keys\{
    Version3\AsymmetricSecretKey as V3AsymmetricSecretKey,
    Version4\AsymmetricSecretKey as V4AsymmetricSecretKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use SodiumException;
use TypeError;
use function hash_equals;
use function sodium_crypto_sign_seed_keypair;

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\Paseto\Keys
 */
abstract class AsymmetricSecretKey implements SendingKey
{
    protected bool $hasAssertedValid = false;
    protected string $key;
    protected ProtocolInterface $protocol;

    /**
     * AsymmetricSecretKey constructor.
     *
     * @param string $keyData
     * @param ProtocolInterface $protocol
     *
     * @throws TypeError
     */
    protected function __construct(
        string $keyData,
        ProtocolInterface $protocol
    ) {
        $this->key = $keyData;
        $this->protocol = $protocol;
    }

    /**
     * @return bool
     */
    public function hasAssertedSecretKeyValid(): bool
    {
        return $this->hasAssertedValid;
    }

    /**
     * Optional check for libraries that load keys from semi-trustworthy sources.
     *
     * Misuse-resistance: Prevent mismatched public keys
     * See: https://github.com/MystenLabs/ed25519-unsafe-libs
     *
     * @throws SecurityException
     * @throws SodiumException
     */
    public function assertSecretKeyValid(): void
    {
        if (!($this->protocol instanceof Version4)) {
            return;
        }
        $sk = Binary::safeSubstr(
            sodium_crypto_sign_seed_keypair(
                Binary::safeSubstr($this->key, 0, 32)
            ),
            0,
            64
        );
        if (!hash_equals($this->key, $sk)) {
            throw new SecurityException(
                "Key mismatch: Public key doesn't belong to private key."
            );
        }
        $this->hasAssertedValid = true;
    }

    /**
     * Wipe secrets before freeing memory
     */
    public function __destruct()
    {
        Util::wipe($this->key);
    }

    /**
     * This used to initialize a v1 secret key, but it was deprecated then removed.
     *
     * @throws InvalidVersionException
     */
    public static function v1(string $keyMaterial): static
    {
        throw new InvalidVersionException("Version 1 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * This used to initialize a v2 secret key, but it was deprecated then removed.
     *
     * @throws InvalidVersionException
     */
    public static function v2(string $keyMaterial): static
    {throw new InvalidVersionException("Version 2 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * Initialize a v3 secret key.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function v3(string $keyMaterial): V3AsymmetricSecretKey
    {
        return new V3AsymmetricSecretKey($keyMaterial);
    }

    /**
     * Initialize a v4 secret key.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function v4(string $keyMaterial): V4AsymmetricSecretKey
    {
        return new V4AsymmetricSecretKey($keyMaterial);
    }

    /**
     * Generate a secret key.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function generate(?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4;
        if (hash_equals($protocol::header(), Version3::HEADER)) {
            return V3AsymmetricSecretKey::generate($protocol);
        }

        return V4AsymmetricSecretKey::generate($protocol);
    }

    /**
     * Initialize a public key.
     *
     * @throws Exception
     */
    public static function newVersionKey(string $keyMaterial, ?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4();

        if (hash_equals($protocol::header(), Version3::HEADER)) {
            return new V3AsymmetricSecretKey($keyMaterial);
        }

        return new V4AsymmetricSecretKey($keyMaterial);
    }

    /**
     * Return a base64url-encoded representation of this secret key.
     *
     * @throws TypeError
     */
    abstract public function encode(): string;

    /**
     * Return a PEM-encoded secret key
     *
     * @throws PasetoException
     */
    abstract public function encodePem(): string;

    /**
     * Initialize a secret key from a base64url-encoded string.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function fromEncodedString(string $encoded, ?ProtocolInterface $version = null): self
    {
        if ($version && hash_equals($version::header(), Version3::HEADER)) {
            return V3AsymmetricSecretKey::fromEncodedString($encoded);
        }

        return V4AsymmetricSecretKey::fromEncodedString($encoded);
    }

    /**
     * @throws InvalidVersionException
     */
    public static function importPem(string $pem, ?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4();

        if ($protocol instanceof Version3) {
            return V3AsymmetricSecretKey::importPem($pem);
        }
        if ($protocol instanceof Version4) {
            return V4AsymmetricSecretKey::importPem($pem);
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

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
     * Get the public key that corresponds to this secret key.
     *
     * @throws Exception
     * @throws TypeError
     */
    abstract public function getPublicKey(): AsymmetricPublicKey;

    /**
     * Get the raw key contents.
     */
    public function raw(): string
    {
        return Util::dos2unix($this->key);
    }

    /**
     * @return array<>
     */
    public function __debugInfo()
    {
        return [];
    }
}
