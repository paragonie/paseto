<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Keys;
use ParagonIE\PAST\Util;

/**
 * Class SymmetricEncryptionKey
 * @package ParagonIE\PAST\Keys
 */
class SymmetricEncryptionKey
{
    const INFO_ENCRYPTION = 'past-encryption-key';
    const INFO_AUTHENTICATION = 'past-auth-key-for-aead';

    /** @var string $key */
    protected $key = '';

    /**
     * SymmetricEncryptionKey constructor.
     * @param string $keyMaterial
     */
    public function __construct(string $keyMaterial)
    {
        $this->key = $keyMaterial;
    }

    /**
     * @return string
     */
    public function raw(): string
    {
        return $this->key;
    }

    /**
     * @param string|null $salt
     * @return array<int, string>
     *
     * @throws \Error
     * @throws \TypeError
     */
    public function split(string $salt = null): array
    {
        $encKey = Util::HKDF('sha384', $this->key, 32, self::INFO_ENCRYPTION, $salt);
        $authKey = Util::HKDF('sha384', $this->key, 32, self::INFO_AUTHENTICATION, $salt);
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
