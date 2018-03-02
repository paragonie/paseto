<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Exception\{
    EncodingException,
    InvalidKeyException,
    InvalidPurposeException,
    InvalidVersionException,
    NotFoundException,
    PasetoException
};
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2
};
use ParagonIE\Paseto\Traits\RegisteredClaims;

/**
 * Class JsonToken
 * @package ParagonIE\Paseto
 */
class JsonToken
{
    use RegisteredClaims;

    /** @var string $cached */
    protected $cached = '';

    /** @var array<string, string> */
    protected $claims = [];

    /** @var string $explicitNonce -- Do not use this. It's for unit testing! */
    protected $explicitNonce = '';

    /** @var string $footer */
    protected $footer = '';

    /** @var KeyInterface|null $key */
    protected $key = null;

    /** @var string $purpose */
    protected $purpose = '';

    /** @var string $version */
    protected $version = Version2::HEADER;

    /**
     * @param SymmetricKey $key
     * @param string $version
     * @return self
     */
    public static function getLocal(
        SymmetricKey $key,
        string $version = Version2::HEADER
    ): self {
        $instance = new static();
        $instance->key = $key;
        $instance->version = $version;
        $instance->purpose = 'local';
        return $instance;
    }

    /**
     * @param AsymmetricSecretKey $key
     * @param string $version
     * @return self
     */
    public static function getPublic(
        AsymmetricSecretKey $key,
        string $version = Version2::HEADER
    ): self {
        $instance = new static();
        $instance->key = $key;
        $instance->version = $version;
        $instance->purpose = 'public';
        return $instance;
    }

    /**
     * Get any arbitrary claim.
     *
     * @param string $claim
     * @return mixed
     * @throws PasetoException
     */
    public function get(string $claim)
    {
        if (\array_key_exists($claim, $this->claims)) {
            return $this->claims[$claim];
        }
        throw new NotFoundException('Claim not found: ' . $claim);
    }

    /**
     * Get the 'exp' claim.
     *
     * @return string
     * @throws PasetoException
     */
    public function getAudience(): string
    {
        return (string) $this->get('aud');
    }

    /**
     * Get all of the claims stored in this Paseto.
     *
     * @return array
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * Get the 'exp' claim.
     *
     * @return \DateTime
     * @throws PasetoException
     */
    public function getExpiration(): \DateTime
    {
        return new \DateTime((string) $this->get('exp'));
    }

    /**
     * Get the footer as a string.
     *
     * @return string
     */
    public function getFooter(): string
    {
        return $this->footer;
    }

    /**
     * Get the footer as an array. Assumes JSON.
     *
     * @return array
     * @throws PasetoException
     */
    public function getFooterArray(): array
    {
        /** @var array $decoded */
        $decoded = \json_decode($this->footer, true);
        if (!\is_array($decoded)) {
            throw new EncodingException('Footer is not a valid JSON document');
        }
        return $decoded;
    }

    /**
     * Get the 'iat' claim.
     *
     * @return \DateTime
     * @throws PasetoException
     */
    public function getIssuedAt(): \DateTime
    {
        return new \DateTime((string) $this->get('iat'));
    }

    /**
     * Get the 'iss' claim.
     *
     * @return string
     * @throws PasetoException
     */
    public function getIssuer(): string
    {
        return (string) $this->get('iss');
    }

    /**
     * Get the 'jti' claim.
     *
     * @return string
     * @throws PasetoException
     */
    public function getJti(): string
    {
        return (string) $this->get('jti');
    }

    /**
     * Get the 'nbf' claim.
     *
     * @return \DateTime
     * @throws PasetoException
     */
    public function getNotBefore(): \DateTime
    {
        return new \DateTime((string) $this->get('nbf'));
    }

    /**
     * Get the 'sub' claim.
     *
     * @return string
     * @throws PasetoException
     */
    public function getSubject(): string
    {
        return (string) $this->get('sub');
    }

    /**
     * Set a claim to an arbitrary value.
     *
     * @param string $claim
     * @param string $value
     * @return self
     */
    public function set(string $claim, $value): self
    {
        $this->cached = '';
        $this->claims[$claim] = $value;
        return $this;
    }

    /**
     * Set the 'aud' claim.
     *
     * @param string $aud
     * @return self
     */
    public function setAudience(string $aud): self
    {
        $this->cached = '';
        $this->claims['aud'] = $aud;
        return $this;
    }

    /**
     * Set an array of claims in one go.
     *
     * @param array<string, string> $claims
     * @return self
     */
    public function setClaims(array $claims): self
    {
        $this->cached = '';
        $this->claims = $claims + $this->claims;
        return $this;
    }

    /**
     * Set the 'exp' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function setExpiration(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $this->cached = '';
        $this->claims['exp'] = $time->format(\DateTime::ATOM);
        return $this;
    }

    /**
     * Do not use this.
     *
     * @param string $nonce
     * @return self
     */
    public function setExplicitNonce(string $nonce = ''): self
    {
        $this->explicitNonce = $nonce;
        return $this;
    }

    /**
     * Set the footer.
     *
     * @param string $footer
     * @return self
     */
    public function setFooter(string $footer = ''): self
    {
        $this->cached = '';
        $this->footer = $footer;
        return $this;
    }

    /**
     * Set the footer, given an array of data. Converts to JSON.
     *
     * @param array $footer
     * @return self
     * @throws PasetoException
     */
    public function setFooterArray(array $footer = []): self
    {
        $encoded = \json_encode($footer);
        if (!\is_string($encoded)) {
            throw new EncodingException('Could not encode array into JSON');
        }
        return $this->setFooter($encoded);
    }

    /**
     * Set the 'iat' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function setIssuedAt(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $this->cached = '';
        $this->claims['iat'] = $time->format(\DateTime::ATOM);
        return $this;
    }

    /**
     * Set the 'iss' claim.
     *
     * @param string $iss
     * @return self
     */
    public function setIssuer(string $iss): self
    {
        $this->cached = '';
        $this->claims['iss'] = $iss;
        return $this;
    }

    /**
     * Set the 'jti' claim.
     *
     * @param string $id
     * @return self
     */
    public function setJti(string $id): self
    {
        $this->cached = '';
        $this->claims['jti'] = $id;
        return $this;
    }

    /**
     * Set the cryptographic key used to authenticate (and possibly encrypt)
     * the serialized token.
     *
     * @param KeyInterface $key
     * @param bool $checkPurpose
     * @return self
     * @throws PasetoException
     */
    public function setKey(KeyInterface $key, bool $checkPurpose = false): self
    {
        if ($checkPurpose) {
            switch ($this->purpose) {
                case 'local':
                    if (!($key instanceof SymmetricKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' .
                                SymmetricKey::class .
                                ', got ' .
                                \get_class($key)
                        );
                    }
                    break;
                case 'public':
                    if (!($key instanceof AsymmetricSecretKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' .
                                AsymmetricSecretKey::class .
                                ', got ' .
                                \get_class($key)
                        );
                    }
                    if (!\hash_equals($this->version, $key->getProtocol()::header())) {
                        throw new InvalidKeyException(
                            'Invalid key type. This key is for ' .
                                $key->getProtocol()::header() .
                                ', not ' .
                                $this->version
                        );
                    }
                    break;
                default:
                    throw new InvalidKeyException('Unknown purpose');
            }
        }

        $this->cached = '';
        $this->key = $key;
        return $this;
    }

    /**
     * Set the 'nbf' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function setNotBefore(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $this->cached = '';
        $this->claims['nbf'] = $time->format(\DateTime::ATOM);
        return $this;
    }

    /**
     * Set the purpose for this token. Allowed values:
     * 'local', 'public'.
     *
     * @param string $purpose
     * @param bool $checkKeyType
     * @return self
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     */
    public function setPurpose(string $purpose, bool $checkKeyType = false): self
    {
        if ($checkKeyType) {
            if (\is_null($this->key)) {
                throw new InvalidKeyException('Key cannot be null');
            }
            $keyType = \get_class($this->key);
            switch ($keyType) {
                case SymmetricKey::class:
                    if (!\hash_equals('local', $purpose)) {
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected local, got ' . $purpose
                        );
                    }
                    break;
                case AsymmetricSecretKey::class:
                    if (!\hash_equals('public', $purpose)) {
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected public, got ' . $purpose
                        );
                    }
                    break;
                default:
                    throw new InvalidPurposeException('Unknown purpose: ' . $purpose);
            }
        }

        $this->cached = '';
        $this->purpose = $purpose;
        return $this;
    }

    /**
     * Set the 'sub' claim.
     *
     * @param string $sub
     * @return self
     */
    public function setSubject(string $sub): self
    {
        $this->cached = '';
        $this->claims['sub'] = $sub;
        return $this;
    }

    /**
     * Set the version for the protocol.
     *
     * @param string $version
     * @return self
     */
    public function setVersion(string $version): self
    {
        $this->cached = '';
        $this->version = $version;
        return $this;
    }

    /**
     * Get the token as a string.
     *
     * @return string
     * @throws PasetoException
     * @psalm-suppress MixedInferredReturnType
     */
    public function toString(): string
    {
        if (!empty($this->cached)) {
            return $this->cached;
        }
        if (\is_null($this->key)) {
            throw new InvalidKeyException('Key cannot be null');
        }
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
                throw new InvalidVersionException(
                    'Unsupported version: ' . $this->version
                );
        }
        /** @var ProtocolInterface $protocol */
        switch ($this->purpose) {
            case 'local':
                if ($this->key instanceof SymmetricKey) {
                    $this->cached = (string) $protocol::encrypt(
                        $claims,
                        $this->key,
                        $this->footer,
                        $this->explicitNonce
                    );
                    return $this->cached;
                }
                break;
            case 'public':
                if ($this->key instanceof AsymmetricSecretKey) {
                    try {
                        $this->cached = (string) $protocol::sign(
                            $claims,
                            $this->key,
                            $this->footer
                        );
                        return $this->cached;
                    } catch (\Throwable $ex) {
                        throw new PasetoException('Signing failed.', 0, $ex);
                    }
                }
                break;
        }
        throw new PasetoException('Unsupported key/purpose pairing.');
    }

    /**
     * Return a new JsonToken instance with a changed claim.
     *
     * @param string $claim
     * @param string $value
     * @return self
     */
    public function with(string $claim, $value): self
    {
        $cloned = clone $this;
        $cloned->cached = '';
        $cloned->claims[$claim] = $value;
        return $cloned;
    }


    /**
     * Return a new JsonToken instance with a changed 'aud' claim.
     *
     * @param string $aud
     * @return self
     */
    public function withAudience(string $aud): self
    {
        return $this->with('aud', $aud);
    }

    /**
     * Return a new JsonToken instance with an array of changed claims.
     *
     * @param array<string, string> $claims
     * @return self
     */
    public function withClaims(array $claims): self
    {
        $cloned = clone $this;
        return $cloned->setClaims($claims);
    }

    /**
     * Return a new JsonToken instance with a changed 'exp' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withExpiration(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $cloned = clone $this;
        $cloned->cached = '';
        $cloned->claims['exp'] = $time->format(\DateTime::ATOM);
        return $cloned;
    }

    /**
     * Return a new JsonToken instance with a changed footer.
     *
     * @param string $footer
     * @return self
     */
    public function withFooter(string $footer = ''): self
    {
        $cloned = clone $this;
        $cloned->cached = '';
        $cloned->footer = $footer;
        return $this;
    }

    /**
     * Return a new JsonToken instance with a changed footer,
     * representing the JSON-encoded array provided.
     *
     * @param array $footer
     * @return self
     * @throws PasetoException
     */
    public function withFooterArray(array $footer = []): self
    {
        $encoded = \json_encode($footer);
        if (!\is_string($encoded)) {
            throw new EncodingException('Could not encode array into JSON');
        }
        return $this->withFooter($encoded);
    }

    /**
     * Return a new JsonToken instance with a changed 'iat' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withIssuedAt(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $cloned = clone $this;
        $cloned->cached = '';
        $cloned->claims['iat'] = $time->format(\DateTime::ATOM);
        return $cloned;
    }

    /**
     * Return a new JsonToken instance with a changed 'iss' claim.
     *
     * @param string $iss
     * @return self
     */
    public function withIssuer(string $iss): self
    {
        return $this->with('iss', $iss);
    }

    /**
     * Return a new JsonToken instance with a changed 'jti' claim.
     *
     * @param string $id
     * @return self
     */
    public function withJti(string $id): self
    {
        return $this->with('jti', $id);
    }

    /**
     * Return a new JsonToken instance, with the provided cryptographic key used
     * to authenticate (and possibly encrypt) the serialized token.
     *
     * @param KeyInterface $key
     * @param bool $checkPurpose
     * @return self
     * @throws PasetoException
     */
    public function withKey(KeyInterface $key, bool $checkPurpose = false): self
    {
        $cloned = clone $this;

        if ($checkPurpose) {
            switch ($cloned->purpose) {
                case 'local':
                    if (!($key instanceof SymmetricKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' .
                                SymmetricKey::class .
                                ', got ' .
                                \get_class($key)
                        );
                    }
                    break;
                case 'public':
                    if (!($key instanceof AsymmetricSecretKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' .
                                AsymmetricSecretKey::class .
                                ', got ' .
                                \get_class($key)
                        );
                    }
                    if (!\hash_equals($cloned->version, $key->getProtocol()::header())) {
                        throw new InvalidKeyException(
                            'Invalid key type. This key is for ' .
                                $key->getProtocol()::header() .
                                ', not ' .
                                $cloned->version
                        );
                    }
                    break;
                default:
                    throw new InvalidKeyException('Unknown purpose');
            }
        }

        $cloned->cached = '';
        $cloned->key = $key;
        return $cloned;
    }

    /**
     * Return a new JsonToken instance with a changed 'nbf' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withNotBefore(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        $cloned = clone $this;
        $cloned->cached = '';
        $cloned->claims['nbf'] = $time->format(\DateTime::ATOM);
        return $cloned;
    }

    /**
     * Return a new JsonToken instance with a new purpose.
     * Allowed values:
     * 'local', 'public'.
     *
     * @param string $purpose
     * @param bool $checkKeyType
     * @return self
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     */
    public function withPurpose(string $purpose, bool $checkKeyType = false): self
    {
        $cloned = clone $this;
        if ($checkKeyType) {
            if (\is_null($cloned->key)) {
                throw new InvalidKeyException('Key cannot be null');
            }
            $keyType = \get_class($cloned->key);
            switch ($keyType) {
                case SymmetricKey::class:
                    if (!\hash_equals('local', $purpose)) {
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected local, got ' . $purpose
                        );
                    }
                    break;
                case AsymmetricSecretKey::class:
                    if (!\hash_equals('public', $purpose)) {
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected public, got ' . $purpose
                        );
                    }
                    break;
                default:
                    throw new InvalidPurposeException('Unknown purpose: ' . $purpose);
            }
        }

        $cloned->cached = '';
        $cloned->purpose = $purpose;
        return $cloned;
    }

    /**
     * Return a new JsonToken instance with a changed 'sub' claim.
     *
     * @param string $sub
     * @return self
     */
    public function withSubject(string $sub): self
    {
        return $this->with('sub', $sub);
    }

    /**
     * Set the version for the protocol.
     *
     * @param string $version
     * @return self
     */
    public function withVersion(string $version): self
    {
        $cloned = clone $this;
        $cloned->cached = '';
        $cloned->version = $version;
        return $cloned;
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
