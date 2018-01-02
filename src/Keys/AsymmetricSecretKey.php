<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Keys;

use ParagonIE\PAST\Protocol\Version1;

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\PAST\Keys
 */
class AsymmetricSecretKey
{
    const VERSION1 = 'v1';
    const VERSION2 = 'v2';

    /** @var string $key */
    protected $key;

    /** @var string $version */
    protected $version;

    /**
     * AsymmetricSecretKey constructor.
     * @param string $keyData
     * @param string $protocol
     */
    public function __construct(string $keyData, string $protocol = self::VERSION2)
    {
        $this->key = $keyData;
        $this->version = $protocol;
    }

    /**
     * @param string $protocol
     * @return self
     */
    public static function generate(string $protocol = self::VERSION2): self
    {
        if ($protocol === self::VERSION1) {
            $rsa = Version1::getRsa(false);
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
     * @return AsymmetricPublicKey
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        switch ($this->version) {
            case self::VERSION1:
                return new AsymmetricPublicKey(
                    Version1::RsaGetPublicKey($this->key)
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
