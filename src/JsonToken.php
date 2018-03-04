<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Exception\{
    EncodingException,
    NotFoundException,
    PasetoException
};
use ParagonIE\Paseto\Traits\RegisteredClaims;

/**
 * Class JsonToken
 * @package ParagonIE\Paseto
 */
class JsonToken
{
    use RegisteredClaims;

    /** @var array<string, string> */
    protected $claims = [];

    /** @var string $footer */
    protected $footer = '';

    /**
     * @param Builder $builder
     *
     * @return Builder
     */
    public function build(Builder $builder): Builder
    {
        return $builder->setJsonToken($this);
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
        /** @var array|bool $decoded */
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
        $this->claims['sub'] = $sub;
        return $this;
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
        return (clone $this)->set($claim, $value);
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
}
