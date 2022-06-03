<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Traits;

use ParagonIE\Paseto\{
    Exception\ExceptionCode,
    Exception\InvalidKeyException,
    Exception\NotFoundException,
    Exception\PasetoException,
    KeyInterface,
    ProtocolInterface,
    Purpose,
    ReceivingKey,
    SendingKey
};
use TypeError;
use function is_null;

/**
 * @var array<string, KeyInterface> $keys
 */
trait MultiKeyTrait
{
    /** @var ?Purpose $purpose */
    protected ?Purpose $purpose = null;

    /** @var ?ProtocolInterface $version */
    protected ?ProtocolInterface $version = null;

    /**
     * The intended version for this key.
     *
     * @return ProtocolInterface
     */
    public function getProtocol(): ProtocolInterface
    {
        if (is_null($this->version)) {
            throw new TypeError(
                "Version must not be NULL.",
                ExceptionCode::UNDEFINED_PROPERTY
            );
        }
        return $this->version;
    }

    /**
     * The intended purpose for this key.
     * @return ?Purpose
     */
    public function getPurpose(): ?Purpose
    {
        return $this->purpose;
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

        if (!is_null($this->version)) {
            if (!($key->getProtocol() instanceof $this->version)) {
                throw new InvalidKeyException(
                    "The provided key is for the wrong version",
                    ExceptionCode::WRONG_KEY_FOR_VERSION
                );
            }
        }

        if (!is_null($this->purpose)) {
            $valid = false;
            try {
                if ($key instanceof ReceivingKey) {
                    $valid = $this->purpose->isReceivingKeyValid($key);
                } elseif ($key instanceof SendingKey) {
                    $valid = $this->purpose->isSendingKeyValid($key);
                }
            } catch (TypeError $ex) {
                throw new InvalidKeyException(
                    "The provided key is not appropriate for the expected purpose.",
                    ExceptionCode::PURPOSE_WRONG_FOR_KEY,
                    $ex
                );
            }
            if (!$valid) {
                throw new InvalidKeyException(
                    "The provided key is not appropriate for the expected purpose.",
                    ExceptionCode::PURPOSE_WRONG_FOR_KEY
                );
            }
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
     * @param Purpose $purpose
     * @return static
     */
    public function setPurpose(Purpose $purpose): static
    {
        $this->purpose = $purpose;
        return $this;
    }

    /**
     * @param ProtocolInterface $version
     * @return static
     */
    public function setVersion(ProtocolInterface $version): static
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
