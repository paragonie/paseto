<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Traits;

use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\InvalidKeyException;
use ParagonIE\Paseto\Exception\NotFoundException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * @var array<string, KeyInterface> $keys
 */
trait MultiKeyTrait
{
    /** @var ProtocolInterface $version */
    protected $version = null;

    /**
     * The intended version for this protocol. Currently only meaningful
     * in asymmetric cryptography.
     *
     * @return ProtocolInterface
     */
    public function getProtocol(): ProtocolInterface
    {
        return $this->version;
    }

    /**
     * Throw an exception if the key is wrong.
     *
     * @param KeyInterface $key
     * @return void
     *
     * @throws InvalidKeyException
     * @throws PasetoException
     */
    protected function typeCheckKey(KeyInterface $key): void
    {
        $type = (string) static::KEY_TYPE;
        if (!interface_exists($type)) {
            throw new PasetoException(
                "The interface {$type} does not exist.",
                ExceptionCode::IMPOSSIBLE_CONDITION
            );
        }
        if (!$key instanceof $type) {
            throw new InvalidKeyException(
                "The provided key is the wrong type",
                ExceptionCode::PASETO_KEY_TYPE_ERROR
            );
        }
    }

    /**
     * Get the key for a given Key-ID
     *
     * @param string $keyId
     * @return KeyInterface
     *
     * @throws InvalidKeyException
     * @throws NotFoundException
     * @throws PasetoException
     */
    public function fetchKey(string $keyId = ''): KeyInterface
    {
        if (!array_key_exists($keyId, $this->keys)) {
            throw new NotFoundException(
                "The key you requested is not in this keyring.",
                ExceptionCode::KEY_NOT_IN_KEYRING
            );
        }
        $fetch = $this->keys[$keyId];
        $this->typeCheckKey($fetch);
        return $fetch;
    }

    /**
     * Returns the raw key as a string.
     *
     * @return string
     * @throws PasetoException
     */
    public function raw(): string
    {
        throw new PasetoException(
            "Do not invoke raw() on a MultiKey; fetch the specific key instead.",
            ExceptionCode::INVOKED_RAW_ON_MULTIKEY
        );
    }

    /**
     * @param ProtocolInterface $version
     * @return static
     */
    public function setVersion(ProtocolInterface $version): self
    {
        $this->version = $version;
        return $this;
    }

    /**
     * This hides the internal state from var_dump(), etc. if it returns
     * an empty array.
     *
     * @return array
     */
    public function __debugInfo()
    {
        return [];
    }
}
