<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Exception\{
    EncodingException,
    InvalidKeyException,
    InvalidPurposeException,
    InvalidVersionException,
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
 * Class Builder
 * @package ParagonIE\Paseto
 */
class Builder
{
    use RegisteredClaims;

    /** @var string $cached */
    protected $cached = '';

    /** @var array<string, string> */
    protected $claims = [];

    /** @var string $explicitNonce -- Do not use this. It's for unit testing! */
    protected $explicitNonce = '';

    /** @var KeyInterface|null $key */
    protected $key = null;

    /** @var string $purpose */
    protected $purpose = '';

    /** @var ProtocolInterface $version */
    protected $version;

    /** @var JsonToken $token */
    protected $token;

    /**
     * Builder constructor.
     *
     * @param JsonToken|null $baseToken
     * @param ProtocolInterface|null $protocol
     * @param KeyInterface|null $key
     *
     * @throws PasetoException
     */
    public function __construct(
        JsonToken $baseToken = null,
        ProtocolInterface $protocol = null,
        KeyInterface $key = null
    ) {
        if (!$baseToken) {
            $baseToken = new JsonToken();
        }
        if (!$protocol) {
            $protocol = new Version2();
        }
        $this->token = $baseToken;
        $this->version = $protocol;
        if ($key) {
            $this->setKey($key);
        }
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
        return $this->token->get($claim);
    }

    /**
     * @return array
     * @throws PasetoException
     */
    public function getFooterArray(): array
    {
        return $this->token->getFooterArray();
    }

    /**
     * @param SymmetricKey $key
     * @param ProtocolInterface|null $version
     * @param JsonToken|null $baseToken
     *
     * @return Builder
     * @throws PasetoException
     */
    public static function getLocal(
        SymmetricKey $key,
        ProtocolInterface $version = null,
        JsonToken $baseToken = null
    ): self {
        if (!$version) {
            $version = new Version2();
        }
        $instance = new static($baseToken);
        $instance->key = $key;
        $instance->version = $version;
        $instance->purpose = 'local';
        return $instance;
    }

    /**
     * @param AsymmetricSecretKey $key
     * @param ProtocolInterface|null $version
     * @param JsonToken|null $baseToken
     *
     * @return Builder
     * @throws PasetoException
     */
    public static function getPublic(
        AsymmetricSecretKey $key,
        ProtocolInterface $version = null,
        JsonToken $baseToken = null
    ): self {
        if (!$version) {
            $version = new Version2();
        }
        $instance = new static($baseToken);
        $instance->key = $key;
        $instance->version = $version;
        $instance->purpose = 'public';
        return $instance;
    }

    /**
     * @return JsonToken
     */
    public function getJsonToken(): JsonToken
    {
        return $this->token;
    }

    /**
     * Set a claim to an arbitrary value.
     *
     * @param string $claim
     * @param string $value
     *
     * @return self
     */
    public function set(string $claim, $value): self
    {
        $this->token->set($claim, $value);
        return $this;
    }

    /**
     * Return a new JsonToken instance with a changed 'aud' claim.
     *
     * @param string $aud
     * @return self
     */
    public function setAudience(string $aud): self
    {
        return $this->set('aud', $aud);
    }

    /**
     * Return a new JsonToken instance set a changed 'exp' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function setExpiration(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        return $this->set('exp', $time->format(\DateTime::ATOM));
    }

    /**
     * Return a new JsonToken instance set a changed 'iat' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function setIssuedAt(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        return $this->set('iat', $time->format(\DateTime::ATOM));
    }

    /**
     * Return a new JsonToken instance set a changed 'iss' claim.
     *
     * @param string $iss
     * @return self
     */
    public function setIssuer(string $iss): self
    {
        return $this->set('iss', $iss);
    }

    /**
     * Return a new JsonToken instance set a changed 'jti' claim.
     *
     * @param string $id
     * @return self
     */
    public function setJti(string $id): self
    {
        return $this->set('jti', $id);
    }

    /**
     * Return a new JsonToken instance set a changed 'nbf' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function setNotBefore(\DateTime $time = null): self
    {
        if (!$time) {
            $time = new \DateTime('NOW');
        }
        return $this->set('nbf', $time->format(\DateTime::ATOM));
    }

    /**
     * Return a new JsonToken instance set a changed 'sub' claim.
     *
     * @param string $sub
     * @return self
     */
    public function setSubject(string $sub): self
    {
        return $this->set('sub', $sub);
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
     * Set an array of claims in one go.
     *
     * @param array<string, string> $claims
     * @return self
     */
    public function setClaims(array $claims): self
    {
        $this->cached = '';
        $this->token->setClaims($claims);
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
        $this->token->setFooter($footer);
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
                    if (!($key->getProtocol() instanceof $this->version)) {
                        throw new InvalidKeyException(
                            'Invalid key type. This key is for ' .
                            $key->getProtocol()::header() .
                            ', not ' .
                            $this->version::header()
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
     * @param ProtocolInterface|null $version
     *
     * @return self
     */
    public function setVersion(ProtocolInterface $version = null): self
    {
        if (!$version) {
            $version = new Version2();
        }
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

        $claims = \json_encode($this->token->getClaims());
        $protocol = $this->version;
        ProtocolCollection::throwIfUnsupported($protocol);
        switch ($this->purpose) {
            case 'local':
                if ($this->key instanceof SymmetricKey) {
                    $this->cached = (string) $protocol::encrypt(
                        $claims,
                        $this->key,
                        $this->token->getFooter(),
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
                            $this->token->getFooter()
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
        $cloned->token = $cloned->token->with($claim, $value);
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
        return (clone $this)->setAudience($aud);
    }

    /**
     * Return a new JsonToken instance with an array of changed claims.
     *
     * @param array<string, string> $claims
     * @return self
     */
    public function withClaims(array $claims): self
    {
        return (clone $this)->setClaims($claims);
    }

    /**
     * Return a new JsonToken instance with a changed 'exp' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withExpiration(\DateTime $time = null): self
    {
        return (clone $this)->setExpiration($time);
    }

    /**
     * Return a new JsonToken instance with a changed footer.
     *
     * @param string $footer
     * @return self
     */
    public function withFooter(string $footer = ''): self
    {
        return (clone $this)->setFooter($footer);
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
        return (clone $this)->setFooterArray($footer);
    }

    /**
     * Return a new JsonToken instance with a changed 'iat' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withIssuedAt(\DateTime $time = null): self
    {
        return (clone $this)->setIssuedAt($time);
    }

    /**
     * Return a new JsonToken instance with a changed 'iss' claim.
     *
     * @param string $iss
     * @return self
     */
    public function withIssuer(string $iss): self
    {
        return (clone $this)->setIssuer($iss);
    }

    /**
     * Return a new JsonToken instance with a changed 'jti' claim.
     *
     * @param string $id
     * @return self
     */
    public function withJti(string $id): self
    {
        return (clone $this)->setJti($id);
    }

    /**
     * Return a new JsonToken instance with a changed 'nbf' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withNotBefore(\DateTime $time = null): self
    {
        return (clone $this)->setNotBefore($time);
    }

    /**
     * Return a new JsonToken instance with a changed 'sub' claim.
     *
     * @param string $sub
     * @return self
     */
    public function withSubject(string $sub): self
    {
        return (clone $this)->setSubject($sub);
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
        return (clone $this)->setKey($key, $checkPurpose);
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
        return (clone $this)->setPurpose($purpose, $checkKeyType);
    }

    /**
     * Make a copy of the JsonToken object.
     *
     * @return void
     */
    public function __clone()
    {
        $this->token = clone $this->token;
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
