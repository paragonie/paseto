<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2
};

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\Paseto\Keys
 */
class AsymmetricSecretKey implements KeyInterface
{
    /** @var string $key */
    protected $key;

    /** @var string $protocol */
    protected $protocol;

    /**
     * AsymmetricSecretKey constructor.
     *
     * @param string $keyData
     * @param string $protocol
     * @throws \Exception
     * @throws \TypeError
     */
    public function __construct(
        string $keyData,
        string $protocol = Version2::HEADER
    ) {
        if (\hash_equals($protocol, Version2::HEADER)) {
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
     * @param string $protocol
     * @return self
     * @throws \Exception
     * @throws \TypeError
     */
    public static function generate(string $protocol = Version2::HEADER): self
    {
        if (\hash_equals($protocol, Version1::HEADER)) {
            $rsa = Version1::getRsa();
            /** @var array<string, string> $keypair */
            $keypair = $rsa->createKey(2048);
            return new self($keypair['privatekey']);
        }
        return new self(
            \sodium_crypto_sign_secretkey(
                \sodium_crypto_sign_keypair()
            )
        );
    }

    /**
     * @return string
     */
    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    /**
     * @param string $encoded
     * @return self
     * @throws \Exception
     * @throws \TypeError
     */
    public static function fromEncodedString(string $encoded): self
    {
        $decoded = Base64UrlSafe::decode($encoded);
        return new self($decoded);
    }

    /**
     * @return string
     */
    public function getProtocol(): string
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
        switch ($this->protocol) {
            case Version1::HEADER:
                return new AsymmetricPublicKey(
                    Version1::RsaGetPublicKey($this->key),
                    Version1::HEADER
                );
            default:
                return new AsymmetricPublicKey(
                    \sodium_crypto_sign_publickey_from_secretkey($this->key)
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
