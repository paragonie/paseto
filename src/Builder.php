<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Exception\{
    EncodingException,
    InvalidKeyException,
    InvalidPurposeException,
    PasetoException
};
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\Version2;
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

    /** @var SendingKey|null $key */
    protected $key = null;

    /** @var Purpose|null $purpose */
    protected $purpose;

    /** @var ProtocolInterface $version */
    protected $version;

    /** @var JsonToken $token */
    protected $token;

    /**
     * Builder constructor.
     *
     * @param JsonToken|null $baseToken
     * @param ProtocolInterface|null $protocol
     * @param SendingKey|null $key
     *
     * @throws PasetoException
     */
    public function __construct(
        JsonToken $baseToken = null,
        ProtocolInterface $protocol = null,
        SendingKey $key = null
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
     * Get a Builder instance configured for local usage.
     * (i.e. shared-key authenticated encryption)
     *
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
        $instance->purpose = Purpose::local();
        return $instance;
    }

    /**
     * Get a Builder instance configured for remote usage.
     * (i.e. public-key digital signatures)
     *
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
        $instance->purpose = Purpose::public();
        return $instance;
    }

    /**
     * Get the JsonToken object (not the string)
     *
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
     * Set the 'aud' claim for the token we're building. (Mutable.)
     *
     * @param string $aud
     * @return self
     */
    public function setAudience(string $aud): self
    {
        return $this->set('aud', $aud);
    }

    /**
     * Set the 'exp' claim for the token we're building. (Mutable.)
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
     * Set the 'iat' claim for the token we're building. (Mutable.)
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
     * Set the 'iss' claim for the token we're building. (Mutable.)
     *
     * @param string $iss
     * @return self
     */
    public function setIssuer(string $iss): self
    {
        return $this->set('iss', $iss);
    }

    /**
     * Set the 'jti' claim for the token we're building. (Mutable.)
     *
     * @param string $id
     * @return self
     */
    public function setJti(string $id): self
    {
        return $this->set('jti', $id);
    }

    /**
     * Set the 'nbf' claim for the token we're building. (Mutable.)
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
     * Set the 'sub' claim for the token we're building. (Mutable.)
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
     * @param SendingKey $key
     * @param bool $checkPurpose
     * @return self
     * @throws PasetoException
     */
    public function setKey(SendingKey $key, bool $checkPurpose = false): self
    {
        if ($checkPurpose) {
            if (!isset($this->purpose)) {
                throw new InvalidKeyException('Unknown purpose');
            } elseif (!$this->purpose->isSendingKeyValid($key)) {
                throw new InvalidKeyException(
                    'Invalid key type. Expected ' .
                        $this->purpose->expectedSendingKeyType() .
                        ', got ' .
                        \get_class($key)
                );
            }
            switch ($this->purpose) {
                case Purpose::local():
                    break;
                case Purpose::public():
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
     * Purpose::local(), Purpose::public().
     *
     * @param Purpose $purpose
     * @param bool $checkKeyType
     * @return self
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     */
    public function setPurpose(Purpose $purpose, bool $checkKeyType = false): self
    {
        if ($checkKeyType) {
            if (\is_null($this->key)) {
                throw new InvalidKeyException('Key cannot be null');
            }
            $expectedPurpose = Purpose::fromSendingKey($this->key);
            if (!$purpose->equals($expectedPurpose)) {
                throw new InvalidPurposeException(
                    'Invalid purpose. Expected '.$expectedPurpose->rawString()
                    .', got ' . $purpose->rawString()
                );
            }
        }

        $this->cached = '';
        $this->purpose = $purpose;
        return $this;
    }

    /**
     * Pass an existing JsonToken object. Useful for updating an existing token.
     *
     * @param JsonToken $token
     *
     * @return Builder
     */
    public function setJsonToken(JsonToken $token): self
    {
        $this->token = $token;
        return $this;
    }

    /**
     * Specify the version of the protocol to be used.
     *
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
        if (\is_null($this->purpose)) {
            throw new InvalidPurposeException('Purpose cannot be null');
        }
        // Mutual sanity checks
        $this->setKey($this->key, true);
        $this->setPurpose($this->purpose, true);

        $claims = \json_encode($this->token->getClaims());
        $protocol = $this->version;
        ProtocolCollection::throwIfUnsupported($protocol);
        switch ($this->purpose) {
            case Purpose::local():
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
            case Purpose::public():
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
     * Return a new Builder instance with a changed claim.
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
     * Return a new Builder instance with a changed 'aud' claim.
     *
     * @param string $aud
     * @return self
     */
    public function withAudience(string $aud): self
    {
        return (clone $this)->setAudience($aud);
    }

    /**
     * Return a new Builder instance with an array of changed claims.
     *
     * @param array<string, string> $claims
     * @return self
     */
    public function withClaims(array $claims): self
    {
        return (clone $this)->setClaims($claims);
    }

    /**
     * Return a new Builder instance with a changed 'exp' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withExpiration(\DateTime $time = null): self
    {
        return (clone $this)->setExpiration($time);
    }

    /**
     * Return a new Builder instance with a changed footer.
     *
     * @param string $footer
     * @return self
     */
    public function withFooter(string $footer = ''): self
    {
        return (clone $this)->setFooter($footer);
    }

    /**
     * Return a new Builder instance with a changed footer,
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
     * Return a new Builder instance with a changed 'iat' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withIssuedAt(\DateTime $time = null): self
    {
        return (clone $this)->setIssuedAt($time);
    }

    /**
     * Return a new Builder instance with a changed 'iss' claim.
     *
     * @param string $iss
     * @return self
     */
    public function withIssuer(string $iss): self
    {
        return (clone $this)->setIssuer($iss);
    }

    /**
     * Return a new Builder instance with a changed 'jti' claim.
     *
     * @param string $id
     * @return self
     */
    public function withJti(string $id): self
    {
        return (clone $this)->setJti($id);
    }

    /**
     * Return a new Builder instance with a changed 'nbf' claim.
     *
     * @param \DateTime|null $time
     * @return self
     */
    public function withNotBefore(\DateTime $time = null): self
    {
        return (clone $this)->setNotBefore($time);
    }

    /**
     * Return a new Builder instance with a changed 'sub' claim.
     *
     * @param string $sub
     * @return self
     */
    public function withSubject(string $sub): self
    {
        return (clone $this)->setSubject($sub);
    }

    /**
     * Return a new Builder instance, with the provided cryptographic key used
     * to authenticate (and possibly encrypt) the serialized token.
     *
     * @param SendingKey $key
     * @param bool $checkPurpose
     * @return self
     * @throws PasetoException
     */
    public function withKey(SendingKey $key, bool $checkPurpose = false): self
    {
        return (clone $this)->setKey($key, $checkPurpose);
    }

    /**
     * Return a new Builder instance with a new purpose.
     * Allowed values:
     * Purpose::local(), Purpose::public().
     *
     * @param Purpose $purpose
     * @param bool $checkKeyType
     * @return self
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     */
    public function withPurpose(Purpose $purpose, bool $checkKeyType = false): self
    {
        return (clone $this)->setPurpose($purpose, $checkKeyType);
    }

    /**
     * Return a new Builder instance with the specified JsonToken object.
     *
     * @param JsonToken $token
     *
     * @return Builder
     */
    public function withJsonToken(JsonToken $token): self
    {
        return (clone $this)->setJsonToken($token);
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
