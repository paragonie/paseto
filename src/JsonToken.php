<?php
declare(strict_types=1);
namespace ParagonIE\PAST;

use ParagonIE\PAST\Exception\{
    EncodingException,
    InvalidKeyException,
    InvalidPurposeException,
    InvalidVersionException,
    NotFoundException,
    PastException
};
use ParagonIE\PAST\Keys\{
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
    const PURPOSE_AUTH = 'auth';
    const PURPOSE_ENC = 'enc';
    const PURPOSE_SIGN = 'sign';

    use RegisteredClaims;

    /** @var string $cached */
    protected $cached = '';

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

    private function __construct() {}

    public static function authenticated(SymmetricAuthenticationKey $key)
    {
        $instance = new static();
        $instance->key = $key;
        $instance->purpose = self::PURPOSE_AUTH;

        return $instance;
    }

    public static function encrypted(SymmetricEncryptionKey $key)
    {
        $instance = new static();
        $instance->key = $key;
        $instance->purpose = self::PURPOSE_ENC;

        return $instance;
    }

    public static function signed(AsymmetricSecretKey $key)
    {
        $instance = new static();
        $instance->key = $key;
        $instance->purpose = self::PURPOSE_SIGN;

        return $instance;
    }

    /**
     * Get any arbitrary claim.
     *
     * @param string $claim
     * @return mixed
     * @throws PastException
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
     * @throws PastException
     */
    public function getAudience(): string
    {
        return (string) $this->get('aud');
    }

    /**
     * Get all of the claims stored in this PAST.
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
     * @throws PastException
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
     * @throws PastException
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
     * @throws PastException
     */
    public function getIssuedAt(): \DateTime
    {
        return new \DateTime((string) $this->get('iat'));
    }

    /**
     * Get the 'iss' claim.
     *
     * @return string
     * @throws PastException
     */
    public function getIssuer(): string
    {
        return (string) $this->get('iss');
    }

    /**
     * Get the 'jti' claim.
     *
     * @return string
     * @throws PastException
     */
    public function getJti(): string
    {
        return (string) $this->get('jti');
    }

    /**
     * Get the 'nbf' claim.
     *
     * @return \DateTime
     * @throws PastException
     */
    public function getNotBefore(): \DateTime
    {
        return new \DateTime((string) $this->get('nbf'));
    }

    /**
     * Get the 'sub' claim.
     *
     * @return string
     * @throws PastException
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
     * @param array $claims
     * @return self
     */
    public function setClaims(array $claims): self
    {
        $this->cached = '';
        $this->claims = $claims;
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
     * @throws PastException
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
     * @throws PastException
     * @psalm-suppress MixedInferredReturnType
     */
    public function toString(): string
    {
        if (!empty($this->cached)) {
            return $this->cached;
        }
        $claims = \json_encode($this->claims);
        switch ($this->version) {
            case Version1::HEADER:
                $protocol = Version1::class;
                break;
            case Version2::HEADER:
                $protocol = Version2::class;
                break;
            default:
                throw new InvalidVersionException('Unsupported version: ' . $this->version);
        }
        $key = $this->key;
        /** @var ProtocolInterface $protocol */
        switch ($this->purpose) {
            case self::PURPOSE_AUTH:
                /** @var SymmetricAuthenticationKey $key */
                $this->cached = (string) $protocol::auth($claims, $key, $this->footer);
		        return $this->cached;
            case self::PURPOSE_ENC:
                /** @var SymmetricEncryptionKey $key */
                $this->cached = (string) $protocol::encrypt($claims, $key, $this->footer);
		        return $this->cached;
            case self::PURPOSE_SIGN:
                try {
                    /** @var AsymmetricSecretKey $key */
                    $this->cached = (string) $protocol::sign($claims, $key, $this->footer);
                    return $this->cached;
                } catch (\Throwable $ex) {
                    throw new PastException('Signing failed.', 0, $ex);
                }
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
