<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Keys;

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
     */
    public function __construct(string $keyMaterial)
    {
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
