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
use ParagonIE\PAST\Protocol\{
    Version1,
    Version2
};
use ParagonIE\PAST\Traits\RegisteredClaims;

/**
 * Class JsonToken
 * @package ParagonIE\PAST
 */
class JsonToken
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
    protected $version = Version2::HEADER;

    /**
     * @param string $claim
     * @return mixed
     * @throws PastException
     */
    public function get(string $claim)
    {
        if (\array_key_exists($claim, $this->claims)) {
            return $this->claims[$claim];
        }
        throw new PastException('Claim not found: ' . $claim);
    }

    /**
     * @return string
     * @throws PastException
     */
    public function getAudience(): string
    {
        return (string) $this->get('aud');
    }

    /**
     * @return \DateTime
     * @throws PastException
     */
    public function getExpiration(): \DateTime
    {
        return new \DateTime((string) $this->get('exp'));
    }

    /**
     * @return string
     */
    public function getFooter(): string
    {
        return $this->footer;
    }

    /**
     * @return array
     * @throws PastException
     */
    public function getFooterArray(): array
    {
        /** @var array $decoded */
        $decoded = \json_decode($this->footer, true);
        if (!\is_array($decoded)) {
            throw new PastException('Footer is not a valid JSON document');
        }
        return $decoded;
    }

    /**
     * @return \DateTime
     * @throws PastException
     */
    public function getIssuedAt(): \DateTime
    {
        return new \DateTime((string) $this->get('iat'));
    }
    /**
     * @return string
     * @throws PastException
     */
    public function getIssuer(): string
    {
        return (string) $this->get('iss');
    }


    /**
     * @return string
     * @throws PastException
     */
    public function getJti(): string
    {
        return (string) $this->get('jti');
    }

    /**
     * @return \DateTime
     * @throws PastException
     */
    public function getNotBefore(): \DateTime
    {
        return new \DateTime((string) $this->get('nbf'));
    }

    /**
     * @param string $claim
     * @param string $value
     * @return JsonToken
     */
    public function set(string $claim, $value): self
    {
        $this->claims[$claim] = $value;
        return $this;
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
     * @param array $claims
     * @return self
     */
    public function setClaims(array $claims): self
    {
        $this->claims = $claims;
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
     * @param string $footer
     * @return self
     */
    public function setFooter(string $footer = ''): self
    {
        $this->footer = $footer;
        return $this;
    }

    /**
     * @param array $footer
     * @return self
     * @throws PastException
     */
    public function setFooterArray(array $footer = []): self
    {
        $encoded = \json_encode($footer);
        if (!\is_string($encoded)) {
            throw new PastException('Could not encode array into JSON');
        }
        return $this->setFooter($encoded);
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
     * @param string $sub
     * @return self
     */
    public function setSubject(string $sub): self
    {
        $this->claims['sub'] = $sub;
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

    /**
     * @return string
     * @throws PastException
     * @psalm-suppress MixedInferredReturnType
     */
    public function toString(): string
    {
        // Mutual sanity checks
        $this->setKey($this->key, true);
        $this->setPurpose($this->purpose, true);

        $claims = \json_encode($this->claims);
        switch ($this->version) {
            case Version1::HEADER:
                $protocol = Version1::class;
                break;
            case Version2::HEADER:
                $protocol = Version2::class;
                break;
            default:
                throw new PastException('Unsupported version: ' . $this->version);
        }
        /** @var ProtocolInterface $protocol */
        switch ($this->purpose) {
            case 'auth':
                if ($this->key instanceof SymmetricAuthenticationKey) {
                    return $protocol::auth($claims, $this->key, $this->footer);
                }
                break;
            case 'enc':
                if ($this->key instanceof SymmetricEncryptionKey) {
                    return $protocol::encrypt($claims, $this->key, $this->footer);
                }
                break;
            case 'seal':
                if ($this->key instanceof AsymmetricPublicKey) {
                    try {
                        return $protocol::seal($claims, $this->key, $this->footer);
                    } catch (\Throwable $ex) {
                        throw new PastException('Sealing failed.', 0, $ex);
                    }
                }
                break;
            case 'sign':
                if ($this->key instanceof AsymmetricSecretKey) {
                    try {
                        return $protocol::sign($claims, $this->key, $this->footer);
                    } catch (\Throwable $ex) {
                        throw new PastException('Signing failed.', 0, $ex);
                    }
                }
                break;
        }
        throw new PastException('Unsupported key/purpose pairing.');
    }

    /**
     * @return string
     */
    public function __toString()
    {
        try {
            return $this->toString();
        } catch (\Throwable $ex) {
            return '';
        }
    }
}
