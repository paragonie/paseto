<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paseto\{
    SendingKey,
    ProtocolInterface
};
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2
};

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\Paseto\Keys
 */
class AsymmetricSecretKey implements SendingKey
{
    /** @var string $key */
    protected $key;

    /** @var ProtocolInterface $protocol */
    protected $protocol;

    /**
     * AsymmetricSecretKey constructor.
     *
     * @param string $keyData
     * @param ProtocolInterface $protocol
     * @throws \Exception
     * @throws \TypeError
     */
    public function __construct(
        string $keyData,
        ProtocolInterface $protocol = null
    ) {
        $protocol = $protocol ?? new Version2;

        if (\hash_equals($protocol::header(), Version2::HEADER)) {
            $len = Binary::safeStrlen($keyData);
            if ($len === SODIUM_CRYPTO_SIGN_KEYPAIRBYTES) {
                $keyData = Binary::safeSubstr($keyData, 0, 64);
            } elseif ($len !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                if ($len !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
                    throw new \Exception(
                        'Secret keys must be 32 or 64 bytes long; ' . $len . ' given.'
                    );
                }
                $keypair = \sodium_crypto_sign_seed_keypair($keyData);
                $keyData = Binary::safeSubstr($keypair, 0, 64);
            }
        }
        $this->key = $keyData;
        $this->protocol = $protocol;
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
     * @param ProtocolInterface $protocol
     * @return self
     * @throws \Exception
     * @throws \TypeError
     */
    public static function generate(ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version2;

        if (\hash_equals($protocol::header(), Version1::HEADER)) {
            $rsa = Version1::getRsa();
            /** @var array<string, string> $keypair */
            $keypair = $rsa->createKey(2048);
            return new self($keypair['privatekey'], $protocol);
        }
        return new self(
            \sodium_crypto_sign_secretkey(
                \sodium_crypto_sign_keypair()
            ),
            $protocol
        );
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
     * @return AsymmetricPublicKey
     * @throws \Exception
     * @throws \TypeError
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        switch ($this->protocol::header()) {
            case Version1::HEADER:
                return new AsymmetricPublicKey(
                    Version1::RsaGetPublicKey($this->key),
                    $this->protocol
                );
            default:
                return new AsymmetricPublicKey(
                    \sodium_crypto_sign_publickey_from_secretkey($this->key),
                    $this->protocol
                );
        }
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
