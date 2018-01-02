<?php
declare(strict_types=1);
namespace ParagonIE\PAST;

use ParagonIE\PAST\Exception\{
    InvalidKeyException,
    PastException
};
use ParagonIE\PAST\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricAuthenticationKey,
    SymmetricEncryptionKey
};
use ParagonIE\PAST\Protocol\Version2;
use ParagonIE\PAST\Traits\RegisteredClaims;

/**
 * Class Builder
 * @package ParagonIE\PAST
 */
class Builder
{
    use RegisteredClaims;

    /** @var array<string, string> */
    protected $claims = [];

    /** @var string $footer */
    protected $footer = '';

    /** @var KeyInterface $key */
    protected $key = null;

    /** @var string $purpose */
    protected $purpose = '';

    /** @var string $version */
    protected $version = '';

    /**
     * Builder constructor.
     *
     * @param string $version
     * @param string $purpose
     * @param KeyInterface|null $key
     */
    public function __construct(
        string $version = Version2::HEADER,
        string $purpose = '',
        KeyInterface $key = null
    ) {
        $this->version = $version;
        $this->purpose = $purpose;
        try {
            if (!\is_null($key)) {
                $this->setKey($key, true);
            }
        } catch (PastException $ex) {
        }
    }

    /**
     * Finalize the token as a string
     *
     * @return JsonToken
     * @throws PastException
     */
    public function getToken(): JsonToken
    {
        return (new JsonToken())
            ->setVersion($this->version)
            ->setPurpose($this->purpose)
            ->setKey($this->key)
            ->setClaims($this->claims)
            ->setFooter($this->footer);
    }

    /**
     * @param string $aud
     * @return self
     */
    public function setAudience(string $aud): self
    {
        $this->claims['aud'] = $aud;
        return $this;
    }

    /**
     * @param \DateTime|null $time
     * @return self
     */
    public function setExpiration(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $this->claims['exp'] = $time->format(\DateTime::ATOM);
        return $this;
    }

    /**
     * @param string $arbitraryData
     * @return self
     */
    public function setFooter(string $arbitraryData): self
    {
        $this->footer = $arbitraryData;
        return $this;
    }

    /**
     * @param \DateTime|null $time
     * @return self
     */
    public function setIssuedAt(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $this->claims['iat'] = $time->format(\DateTime::ATOM);
        return $this;
    }

    /**
     * @param string $iss
     * @return self
     */
    public function setIssuer(string $iss): self
    {
        $this->claims['iss'] = $iss;
        return $this;
    }

    /**
     * @param string $id
     * @return self
     */
    public function setJti(string $id): self
    {
        $this->claims['jti'] = $id;
        return $this;
    }

    /**
     * @param \DateTime|null $time
     * @return self
     */
    public function setNotBefore(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $this->claims['nbf'] = $time->format(\DateTime::ATOM);
        return $this;
    }

    /**
     * @param string $sub
     * @return self
     */
    public function setSubject(string $sub): self
    {
        $this->claims['sub'] = $sub;
        return $this;
    }

    /**
     * @param string $claim
     * @param string $value
     * @return self
     * @throws PastException
     */
    public function set(string $claim, $value): self
    {
        if (\in_array($claim, $this->registeredClaims, true)) {
            throw new PastException(
                'You cannot set a registered claim with set(). Use the appropriate interface.'
            );
        }
        $this->claims[$claim] = $value;
        return $this;
    }

    /**
     * @param KeyInterface $key
     * @param bool $checkPurpose
     * @return self
     * @throws PastException
     */
    public function setKey(KeyInterface $key, bool $checkPurpose = false): self
    {
        if ($checkPurpose) {
            switch ($this->purpose) {
                case 'auth':
                    if (!($key instanceof SymmetricAuthenticationKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' . SymmetricAuthenticationKey::class . ', got ' . \get_class($key)
                        );
                    }
                    break;
                case 'enc':
                    if (!($key instanceof SymmetricEncryptionKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' . SymmetricEncryptionKey::class . ', got ' . \get_class($key)
                        );
                    }
                    break;
                case 'seal':
                    if (!($key instanceof AsymmetricPublicKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' . AsymmetricPublicKey::class . ', got ' . \get_class($key)
                        );
                    }
                    if (!\hash_equals($this->version, $key->getProtocol())) {
                        throw new InvalidKeyException(
                            'Invalid key type. This key is for ' . $key->getProtocol() . ', not ' . $this->version
                        );
                    }
                    break;
                case 'sign':
                    if (!($key instanceof AsymmetricSecretKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' . AsymmetricSecretKey::class . ', got ' . \get_class($key)
                        );
                    }
                    if (!\hash_equals($this->version, $key->getProtocol())) {
                        throw new InvalidKeyException(
                            'Invalid key type. This key is for ' . $key->getProtocol() . ', not ' . $this->version
                        );
                    }
                    break;
                default:
                    throw new InvalidKeyException('Unknown purpose');
            }
        }
        $this->key = $key;
        return $this;
    }

    /**
     * @param string $purpose
     * @param bool $checkKeyType
     * @return self
     * @throws PastException
     */
    public function setPurpose(string $purpose, bool $checkKeyType = false): self
    {
        if ($checkKeyType) {
            $keyType = \get_class($this->key);
            switch ($keyType) {
                case SymmetricAuthenticationKey::class:
                    if (!\hash_equals('auth', $purpose)) {
                        throw new PastException(
                            'Invalid purpose. Expected auth, got ' . $purpose
                        );
                    }
                    break;
                case SymmetricEncryptionKey::class:
                    if (!\hash_equals('enc', $purpose)) {
                        throw new PastException(
                            'Invalid purpose. Expected enc, got ' . $purpose
                        );
                    }
                    break;
                case AsymmetricPublicKey::class:
                    if (!\hash_equals('seal', $purpose)) {
                        throw new PastException(
                            'Invalid purpose. Expected seal, got ' . $purpose
                        );
                    }
                    break;
                case AsymmetricSecretKey::class:
                    if (!\hash_equals('sign', $purpose)) {
                        throw new PastException(
                            'Invalid purpose. Expected sign, got ' . $purpose
                        );
                    }
                    break;
                default:
                    throw new PastException('Unknown purpose: ' . $purpose);
            }
        }

        $this->purpose = $purpose;
        return $this;
    }

    /**
     * @param string $version
     * @return self
     */
    public function setVersion(string $version): self
    {
        $this->version = $version;
        return $this;
    }
}
