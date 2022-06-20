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
    Exception\SecurityException,
    SendingKey,
    ProtocolInterface,
    Util
};
use ParagonIE\EasyECC\ECDSA\{
    ConstantTimeMath,
    PublicKey,
    SecretKey
};
use Mdanter\Ecc\EccFactory;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use Exception;
use SodiumException;
use TypeError;
use function hash_equals,
    sodium_crypto_sign_keypair,
    sodium_crypto_sign_publickey_from_secretkey,
    sodium_crypto_sign_secretkey,
    sodium_crypto_sign_seed_keypair;

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\Paseto\Keys
 */
class AsymmetricSecretKey implements SendingKey
{
    protected string $key;
    protected ProtocolInterface $protocol;

    /**
     * AsymmetricSecretKey constructor.
     *
     * @param string $keyData
     * @param ProtocolInterface|null $protocol
     *
     * @throws Exception
     * @throws TypeError
     */
    public function __construct(
        string $keyData,
        ProtocolInterface $protocol = null
    ) {
        $protocol = $protocol ?? new Version4;

        if (hash_equals($protocol::header(), Version4::HEADER)) {
            $len = Binary::safeStrlen($keyData);
            if ($len === SODIUM_CRYPTO_SIGN_KEYPAIRBYTES) {
                $keyData = Binary::safeSubstr($keyData, 0, 64);
            } elseif ($len !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                if ($len !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
                    throw new PasetoException(
                        'Secret keys must be 32 or 64 bytes long; ' . $len . ' given.',
                        ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
                    );
                }
                $keypair = sodium_crypto_sign_seed_keypair($keyData);
                $keyData = Binary::safeSubstr($keypair, 0, 64);
            }
        }
        $this->key = $keyData;
        $this->protocol = $protocol;
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
     * This used to initialize a v2 secret key, but it was deprecated then removed.
     *
     * @param string $keyMaterial
     * @return self
     *
     * @throws InvalidVersionException
     */
    public static function v2(string $keyMaterial): self
    {throw new InvalidVersionException("Version 2 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * Initialize a v3 secret key.
     *
     * @param string $keyMaterial
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
     * Initialize a v4 secret key.
     *
     * @param string $keyMaterial
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
     * Generate a secret key.
     *
     * @param ProtocolInterface|null $protocol
     * @return self
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function generate(ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4;
        if (hash_equals($protocol::header(), Version3::HEADER)) {
            return new self(
                Util::dos2unix(SecretKey::generate(Version3::CURVE)->exportPem()),
                $protocol
            );
        }
        return new self(
            sodium_crypto_sign_secretkey(
                sodium_crypto_sign_keypair()
            ),
            $protocol
        );
    }

    /**
     * Return a base64url-encoded representation of this secret key.
     *
     * @return string
     *
     * @throws TypeError
     */
    public function encode(): string
    {
        // V3 secret keys -- coerce as just secret key bytes, no PEM
        if ($this->protocol instanceof Version3 && Binary::safeStrlen($this->key) > 48) {
            return Base64UrlSafe::encodeUnpadded(
                Hex::decode(
                    gmp_strval(
                        SecretKey::importPem($this->key)->getSecret(),
                        16
                    )
                )
            );
        }
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    /**
     * Return a PEM-encoded secret key
     *
     * @return string
     * @throws PasetoException
     */
    public function encodePem(): string
    {
        switch ($this->protocol::header()) {
            case 'v3':
                return Util::dos2unix((new SecretKey(
                    new ConstantTimeMath(),
                    EccFactory::getNistCurves()->generator384(),
                    gmp_init(Hex::encode($this->raw()), 16)
                ))->exportPem());
            case 'v4':
                $encoded = Base64::encode(
                    Hex::decode('302e020100300506032b657004220420') . $this->raw()
                );
                return "-----BEGIN EC PRIVATE KEY-----\n" .
                    Util::dos2unix(chunk_split($encoded, 64)).
                    "-----END EC PRIVATE KEY-----";
            default:
                throw new PasetoException("Unknown version");
        }
    }

    /**
     * Initialize a secret key from a base64url-encoded string.
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
     * Get the public key that corresponds to this secret key.
     *
     * @return AsymmetricPublicKey
     *
     * @throws Exception
     * @throws TypeError
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        switch ($this->protocol::header()) {
            case Version3::HEADER:
                /** @var PublicKey $pk */
                if (Binary::safeStrlen($this->key) === 48) {
                    $pk = PublicKey::promote(
                        (new SecretKey(
                            new ConstantTimeMath(),
                            EccFactory::getNistCurves()->generator384(),
                            gmp_init(Hex::encode($this->key), 16)
                        ))->getPublicKey()
                    );
                } else {
                    /** @var PublicKey $pk */
                    $pk = SecretKey::importPem($this->key)->getPublicKey();
                }
                return new AsymmetricPublicKey(
                    PublicKey::importPem($pk->exportPem())->toString(), // Compressed point
                    $this->protocol
                );
            default:
                return new AsymmetricPublicKey(
                    sodium_crypto_sign_publickey_from_secretkey($this->key),
                    $this->protocol
                );
        }
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
