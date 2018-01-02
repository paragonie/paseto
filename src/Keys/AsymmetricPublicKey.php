<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Keys;

use ParagonIE\ConstantTime\Binary;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\PAST\Keys
 */
class AsymmetricPublicKey
{
    /** @var string $key */
    protected $key = '';

    /**
     * AsymmetricPublicKey constructor.
     * @param string $keyMaterial
     * @param string $protocol
     * @throws \Exception
     */
    public function __construct(string $keyMaterial, string $protocol = AsymmetricSecretKey::VERSION2)
    {
        if ($protocol === AsymmetricSecretKey::VERSION2) {
            $len = Binary::safeStrlen($keyMaterial);
            if ($len !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new \Exception('Public keys must be 32 bytes long; ' . $len . ' given.');
            }
        }
        $this->key = $keyMaterial;
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
