<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Keys;

/**
 * Class SymmetricAuthenticationKey
 * @package ParagonIE\PAST\Keys
 */
class SymmetricAuthenticationKey
{
    /** @var string $key */
    protected $key = '';

    /**
     * SymmetricAuthenticationKey constructor.
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
