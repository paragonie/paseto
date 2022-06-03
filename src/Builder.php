<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use DateInterval;
use ParagonIE\Paseto\Exception\{
    EncodingException,
    ExceptionCode,
    InvalidKeyException,
    InvalidPurposeException,
    NotFoundException,
    PasetoException
};
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Parsing\NonExpiringSupport;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Traits\RegisteredClaims;
use Closure;
use DateTime;
use DateTimeInterface;
use Throwable;
use function is_null,
    is_string,
    json_decode,
    json_encode;

/**
 * Class Builder
 * @package ParagonIE\Paseto
 */
class Builder extends PasetoBase
{
    use NonExpiringSupport;
    use RegisteredClaims;

    protected string $cached = '';
    protected string $implicitAssertions = '';
    /** @var Closure|null $unitTestEncrypter -- Do not use this. It's for unit testing! */
    protected $unitTestEncrypter;
    protected ?SendingKey $key = null;
    protected ?Purpose $purpose = null;
    protected ProtocolInterface $version;
    protected JsonToken $token;

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
            $protocol = new Version4();
        }
        $this->token = $baseToken;
        $this->version = $protocol;
        if ($key) {
            $this->setKey($key);
        }
    }

    /**
     * Fetch a key (either from $this->key directly, or by its Key ID if we've
     * stored a KeyRing), then make sure it's an Asymmetric Secret Key.
     *
     * @return AsymmetricSecretKey
     *
     * @throws InvalidKeyException
     * @throws NotFoundException
     * @throws PasetoException
     */
    public function fetchSecretKey(): AsymmetricSecretKey
    {
        if ($this->key instanceof SendingKeyRing) {
            $footer = $this->token->getFooterArray();
            $index = (string) static::KEY_ID_FOOTER_CLAIM;
            $keyId = (string) ($footer[$index] ?? '');
            $key = $this->key->fetchKey($keyId);
        } else {
            $key = $this->key;
        }
        if (!($key instanceof AsymmetricSecretKey)) {
            throw new InvalidKeyException(
                "Only symmetric keys can be used for local tokens.",
                ExceptionCode::PURPOSE_WRONG_FOR_KEY
            );
        }
        return $key;
    }

    /**
     * Fetch a key (either from $this->key directly, or by its Key ID if we've
     * stored a KeyRing), then make sure it's a Symmetric Key.
     *
     * @return SymmetricKey
     *
     * @throws InvalidKeyException
     * @throws NotFoundException
     * @throws PasetoException
     */
    public function fetchSymmetricKey(): SymmetricKey
    {
        if ($this->key instanceof SendingKeyRing) {
            $footer = $this->token->getFooterArray();
            $index = (string) static::KEY_ID_FOOTER_CLAIM;
            $keyId = (string) ($footer[$index] ?? '');
            $key = $this->key->fetchKey($keyId);
        } else {
            $key = $this->key;
        }
        if (!($key instanceof SymmetricKey)) {
            throw new InvalidKeyException(
                "Only symmetric keys can be used for local tokens.",
                ExceptionCode::PURPOSE_WRONG_FOR_KEY
            );
        }
        return $key;
    }

    /**
     * Get any arbitrary claim.
     *
     * @param string $claim
     * @return mixed
     *
     * @throws PasetoException
     */
    public function get(string $claim): mixed
    {
        return $this->token->get($claim);
    }

    /**
     * Get the footer contents as an array.
     *
     * @return array
     *
     * @throws PasetoException
     */
    public function getFooterArray(): array
    {
        return $this->token->getFooterArray();
    }

    /**
     * Get the implicit assertions configured for this Builder.
     *
     * @return array
     */
    public function getImplicitAssertions(): array
    {
        if (empty($this->implicitAssertions)) {
            return [];
        }
        return (array) json_decode($this->implicitAssertions, true);
    }

    /**
     * Get a Builder instance configured for local usage.
     * (i.e. shared-key authenticated encryption)
     *
     * @param SymmetricKey $key
     * @param ProtocolInterface|null $version
     * @param JsonToken|null $baseToken
     * @return self
     *
     * @throws PasetoException
     */
    public static function getLocal(
        SymmetricKey $key,
        ProtocolInterface $version = null,
        JsonToken $baseToken = null
    ): self {
        if (!$version) {
            $version = $key->getProtocol();
        }
        $instance = new self($baseToken);
        $instance->key = $key;
        $instance->version = $version;
        $instance->purpose = Purpose::local();
        return $instance;
    }

    /**
     * Get a Builder instance configured for local usage.
     * (i.e. shared-key authenticated encryption)
     *
     * @param SendingKeyRing $key
     * @param ProtocolInterface|null $version
     * @param JsonToken|null $baseToken
     * @return self
     *
     * @throws PasetoException
     */
    public static function getLocalWithKeyRing(
        SendingKeyRing    $key,
        ProtocolInterface $version = null,
        JsonToken         $baseToken = null
    ): self {
        if (!$version) {
            $version = $key->getProtocol();
        }
        $instance = new self($baseToken);
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
     * @return self
     *
     * @throws PasetoException
     */
    public static function getPublic(
        AsymmetricSecretKey $key,
        ProtocolInterface $version = null,
        JsonToken $baseToken = null
    ): self {
        if (!$version) {
            $version = $key->getProtocol();
        }
        $instance = new self($baseToken);
        $instance->key = $key;
        $instance->version = $version;
        $instance->purpose = Purpose::public();
        return $instance;
    }

    /**
     * Get a Builder instance configured for remote usage.
     * (i.e. public-key digital signatures)
     *
     * @param SendingKeyRing $key
     * @param ProtocolInterface|null $version
     * @param JsonToken|null $baseToken
     * @return self
     *
     * @throws PasetoException
     */
    public static function getPublicWithKeyRing(
        SendingKeyRing    $key,
        ProtocolInterface $version = null,
        JsonToken         $baseToken = null
    ): self {
        if (!$version) {
            $version = $key->getProtocol();
        }
        $instance = new self($baseToken);
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
     * @param mixed $value
     *
     * @return self
     */
    public function set(string $claim, mixed $value): self
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
     * @param DateTimeInterface|null $time
     * @return self
     */
    public function setExpiration(DateTimeInterface $time = null): self
    {
        if (!$time) {
            $time = new DateTime('NOW');
        }
        return $this->set('exp', $time->format(DateTime::ATOM));
    }

    /**
     * Set the implicit assertions for the constructed PASETO token
     * (only affects v3/v4).
     *
     * @param array $assertions
     * @return self
     *
     * @throws PasetoException
     */
    public function setImplicitAssertions(array $assertions): self
    {
        if (empty($assertions)) {
            $implicit = '';
        } else {
            $implicit = json_encode($assertions);
        }
        if (!is_string($implicit)) {
            throw new EncodingException(
                'Could not serialize as string',
                ExceptionCode::IMPLICIT_ASSERTION_JSON_ERROR
            );
        }
        $this->implicitAssertions = $implicit;
        return $this;
    }

    /**
     * Set the 'iat' claim for the token we're building. (Mutable.)
     *
     * @param DateTimeInterface|null $time
     * @return self
     */
    public function setIssuedAt(DateTimeInterface $time = null): self
    {
        if (!$time) {
            $time = new DateTime('NOW');
        }
        return $this->set('iat', $time->format(DateTimeInterface::ATOM));
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
     * @param DateTimeInterface|null $time
     * @return self
     */
    public function setNotBefore(DateTimeInterface $time = null): self
    {
        if (!$time) {
            $time = new DateTime('NOW');
        }
        return $this->set('nbf', $time->format(DateTimeInterface::ATOM));
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
     * Set an array of claims in one go.
     *
     * @param array<string, mixed> $claims
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
     *
     * @throws PasetoException
     */
    public function setFooterArray(array $footer = []): self
    {
        $encoded = json_encode($footer);
        if (!is_string($encoded)) {
            throw new EncodingException(
                'Could not encode array into JSON',
                ExceptionCode::FOOTER_JSON_ERROR
            );
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
     *
     * @throws PasetoException
     */
    public function setKey(SendingKey $key, bool $checkPurpose = false): self
    {
        if ($key instanceof SendingKeyRing) {
            /** We'll need to do more checks at build time {@link toString()} */
            $this->key = $key;
            return $this;
        }
        if ($checkPurpose) {
            if (is_null($this->purpose)) {
                throw new InvalidKeyException(
                    'Unknown purpose',
                    ExceptionCode::PURPOSE_NOT_DEFINED
                );
            } elseif (!$this->purpose->isSendingKeyValid($key)) {
                throw new InvalidKeyException(
                    'Invalid key type. Expected ' .
                        $this->purpose->expectedSendingKeyType() .
                        ', got ' .
                        get_class($key),
                    ExceptionCode::PASETO_KEY_TYPE_ERROR
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
                    throw new InvalidKeyException(
                        'Unknown purpose',
                        ExceptionCode::PURPOSE_NOT_LOCAL_OR_PUBLIC
                    );
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
     *
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     */
    public function setPurpose(Purpose $purpose, bool $checkKeyType = false): self
    {
        if ($this->key instanceof SendingKeyRing) {
            /** We'll need to do more checks at build time {@link toString()} */
            $this->cached = '';
            $this->purpose = $purpose;
            return $this;
        }
        if ($checkKeyType) {
            if (is_null($this->key)) {
                throw new InvalidKeyException(
                    'Key cannot be null',
                    ExceptionCode::PASETO_KEY_IS_NULL
                );
            }
            $expectedPurpose = Purpose::fromSendingKey($this->key);
            if (!$purpose->equals($expectedPurpose)) {
                throw new InvalidPurposeException(
                    'Invalid purpose. Expected ' .
                        $expectedPurpose->rawString() .
                        ', got ' . $purpose->rawString(),
                    ExceptionCode::PURPOSE_WRONG_FOR_KEY
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
            $version = new Version4();
        }
        $this->version = $version;
        return $this;
    }

    /**
     * Get the token as a string.
     *
     * @return string
     *
     * @throws PasetoException
     */
    public function toString(): string
    {
        if (!empty($this->cached)) {
            return $this->cached;
        }
        if (is_null($this->key)) {
            throw new InvalidKeyException(
                'Key cannot be null',
                ExceptionCode::PASETO_KEY_IS_NULL
            );
        }
        if (is_null($this->purpose)) {
            throw new InvalidPurposeException(
                'Purpose cannot be null',
                ExceptionCode::PURPOSE_NOT_DEFINED
            );
        }
        // Mutual sanity checks
        $this->setKey($this->key, true);
        $this->setPurpose($this->purpose, true);

        $claimsArray = $this->token->getClaims();

        // PASETO tokens expire by default (unless otherwise specified).
        if (!$this->nonExpiring && !array_key_exists('exp', $claimsArray)) {
            $claimsArray['exp'] = (new DateTime('NOW'))
                ->add(new DateInterval('PT01H'))
                ->format(DateTime::ATOM);
        }
        $claims = json_encode($claimsArray, JSON_FORCE_OBJECT);
        $protocol = $this->version;
        ProtocolCollection::throwIfUnsupported($protocol);

        $implicit = '';
        if (!empty($this->implicitAssertions)) {
            if (!$protocol::supportsImplicitAssertions()) {
                throw new PasetoException(
                    'This version does not support implicit assertions',
                    ExceptionCode::IMPLICIT_ASSERTION_NOT_SUPPORTED
                );
            }
            $implicit = $this->implicitAssertions;
        }
        switch ($this->purpose) {
            case Purpose::local():
                $key = $this->fetchSymmetricKey();
                /**
                 * During unit tests, perform last-minute dependency
                 * injection to swap $protocol for a conjured up version.
                 * This new version can access a protected method on our
                 * actual $protocol, giving unit tests the ability to
                 * manually set a pre-decided nonce.
                 */
                if (isset($this->unitTestEncrypter)) {
                    /** @var ProtocolInterface */
                    $protocol = ($this->unitTestEncrypter)($protocol);
                }
                $this->cached = $protocol::encrypt(
                    $claims,
                    $key,
                    $this->token->getFooter(),
                    $implicit
                );
                return $this->cached;
            case Purpose::public():
                $key = $this->fetchSecretKey();
                try {
                    $this->cached = $protocol::sign(
                        $claims,
                        $key,
                        $this->token->getFooter(),
                        $implicit
                    );
                    return $this->cached;
                } catch (Throwable $ex) {
                    throw new PasetoException(
                        'Signing failed.',
                        ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR,
                        $ex
                    );
                }
        }
        throw new PasetoException(
            'Unsupported key/purpose pairing.',
            ExceptionCode::PURPOSE_WRONG_FOR_KEY
        );
    }

    /**
     * Return a new Builder instance with a changed claim.
     *
     * @param string $claim
     * @param mixed $value
     * @return self
     */
    public function with(string $claim, mixed $value): self
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
     * @param array<string, mixed> $claims
     * @return self
     */
    public function withClaims(array $claims): self
    {
        return (clone $this)->setClaims($claims);
    }

    /**
     * Return a new Builder instance with a changed 'exp' claim.
     *
     * @param DateTimeInterface|null $time
     * @return self
     */
    public function withExpiration(DateTimeInterface $time = null): self
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
     * Return a new Builder instance with changed implicit assertions
     * for the constructed PASETO token (only affects v3/v4).
     *
     * @param array $implicit
     * @return self
     *
     * @throws PasetoException
     */
    public function withImplicitAssertions(array $implicit): self
    {
        return (clone $this)->setImplicitAssertions($implicit);
    }

    /**
     * Return a new Builder instance with a changed 'iat' claim.
     *
     * @param DateTimeInterface|null $time
     * @return self
     */
    public function withIssuedAt(DateTimeInterface $time = null): self
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
     * @param DateTimeInterface|null $time
     * @return self
     */
    public function withNotBefore(DateTimeInterface $time = null): self
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
     *
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
     *
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
     * @return self
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
     * @throws PasetoException
     */
    public function __toString()
    {
        return $this->toString();
    }
}
