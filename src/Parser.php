<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Paseto\Exception\{
    EncodingException,
    InvalidKeyException,
    InvalidPurposeException,
    InvalidVersionException,
    PasetoException,
    RuleViolation,
    SecurityException
};
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    SymmetricKey
};

use ParagonIE\Paseto\Traits\RegisteredClaims;

/**
 * Class Parser
 * @package ParagonIE\Paseto
 * @psalm-suppress PropertyNotSetInConstructor
 */
class Parser
{
    use RegisteredClaims;

    /** @var ProtocolCollection */
    protected $allowedVersions;

    /** @var ReceivingKey $key */
    protected $key;

    /** @var Purpose|null $purpose */
    protected $purpose;

    /** @var array<int, ValidationRuleInterface> */
    protected $rules = [];

    /**
     * Parser constructor.
     *
     * @param ProtocolCollection|null $allowedVersions
     * @param Purpose|null $purpose
     * @param ReceivingKey|null $key
     * @param array<int, ValidationRuleInterface> $parserRules
     * @throws PasetoException
     */
    public function __construct(
        ProtocolCollection $allowedVersions = null,
        Purpose $purpose = null,
        ReceivingKey $key = null,
        array $parserRules = []
    ) {
        $this->allowedVersions = $allowedVersions ?? ProtocolCollection::default();
        $this->purpose = $purpose;
        if (!\is_null($key)) {
            $this->setKey($key, true);
        }
        if (!empty($parserRules)) {
            foreach ($parserRules as $rule) {
                if ($rule instanceof ValidationRuleInterface) {
                    $this->addRule($rule);
                }
            }
        }
    }

    /**
     * Get a Parser instance intended for local usage.
     * (i.e. shard-key authenticated encryption)
     *
     * @param SymmetricKey $key
     * @param ProtocolCollection|null $allowedVersions
     *
     * @return Parser
     * @throws PasetoException
     */
    public static function getLocal(
        SymmetricKey $key,
        ProtocolCollection $allowedVersions = null
    ): self {
        /** @var Parser $instance */
        $instance = new static(
            $allowedVersions ?? ProtocolCollection::default(),
            Purpose::local(),
            $key
        );
        return $instance;
    }

    /**
     * Get a Parser instance intended for remote usage.
     * (i.e. public-key digital signatures).
     *
     * @param AsymmetricPublicKey $key
     * @param ProtocolCollection|null $allowedVersions
     *
     * @return Parser
     * @throws PasetoException
     */
    public static function getPublic(
        AsymmetricPublicKey $key,
        ProtocolCollection $allowedVersions = null
    ): self {
        /** @var Parser $instance */
        $instance = new static(
            $allowedVersions ?? ProtocolCollection::default(),
            Purpose::public(),
            $key
        );
        return $instance;
    }

    /**
     * Add a validation rule to be invoked by parse().
     *
     * @param ValidationRuleInterface $rule
     * @return self
     */
    public function addRule(ValidationRuleInterface $rule): self
    {
        $this->rules[] = $rule;
        return $this;
    }

    /**
     * Parse a string into a JsonToken object.
     *
     * @param string $tainted      Tainted user-provided string.
     * @param bool $skipValidation Don't validate according to the Rules.
     *                             (Does not disable cryptographic security.)
     * @return JsonToken
     * @throws PasetoException
     * @throws \TypeError
     */
    public function parse(string $tainted, bool $skipValidation = false): JsonToken
    {
        /** @var array<int, string> $pieces */
        $pieces = \explode('.', $tainted);
        if (\count($pieces) < 3) {
            throw new SecurityException('Truncated or invalid token');
        }

        // First, check against the user's specified list of allowed versions.
        $header = $pieces[0];
        /** @var ProtocolInterface $protocol */
        $protocol = ProtocolCollection::protocolFromHeader($header);
        if (!$this->allowedVersions->has($protocol)) {
            throw new InvalidVersionException('Disallowed or unsupported version');
        }

        /** @var Purpose $purpose */
        $footer = '';
        $purpose = new Purpose($pieces[1]);

        // $this->purpose is not mandatory, but if it's set, verify against it.
        if (isset($this->purpose)) {
            if (!$this->purpose->equals($purpose)) {
                throw new InvalidPurposeException('Disallowed or unsupported purpose');
            }
        }

        if (!$purpose->isReceivingKeyValid($this->key)) {
            throw new InvalidKeyException('Invalid key type');
        }

        // Let's verify/decode according to the appropriate method:
        switch ($purpose) {
            case Purpose::local():
                $footer = (\count($pieces) > 3)
                    ? Base64UrlSafe::decode($pieces[3])
                    : '';
                /** @var SymmetricKey $key */
                $key = $this->key;
                try {
                    /** @var string $decoded */
                    $decoded = $protocol::decrypt($tainted, $key, $footer);
                } catch (\Throwable $ex) {
                    throw new PasetoException('An error occurred', 0, $ex);
                }
                break;
            case Purpose::public():
                $footer = (\count($pieces) > 4)
                    ? Base64UrlSafe::decode($pieces[4])
                    : '';
                /** @var AsymmetricPublicKey $key */
                $key = $this->key;
                try {
                    /** @var string $decoded */
                    $decoded = $protocol::verify($tainted, $key, $footer);
                } catch (\Throwable $ex) {
                    throw new PasetoException('An error occurred', 0, $ex);
                }
                break;
        }

        // Did we get data?
        if (!isset($decoded)) {
            throw new PasetoException('Unsupported purpose or version.');
        }
        /** @var array<string, string>|bool $claims */
        $claims = \json_decode((string) $decoded, true);
        if (!\is_array($claims)) {
            throw new EncodingException('Not a JSON token.');
        }

        // Let's build the token object.
        $token = (new JsonToken())
            ->setFooter($footer)
            ->setClaims($claims);
        if (!$skipValidation && !empty($this->rules)) {
            // Validate all of the rules that were specified:
            $this->validate($token, true);
        }
        return $token;
    }

    /**
     * Which protocol versions to permit.
     *
     * @param ProtocolCollection $whitelist
     * @return self
     */
    public function setAllowedVersions(ProtocolCollection $whitelist): self
    {
        $this->allowedVersions = $whitelist;
        return $this;
    }

    /**
     * Specify the key for the token we are going to parse.
     *
     * @param ReceivingKey $key
     * @param bool $checkPurpose
     * @return self
     * @throws PasetoException
     */
    public function setKey(ReceivingKey $key, bool $checkPurpose = false): self
    {
        if ($checkPurpose) {
            if (!isset($this->purpose)) {
                throw new InvalidKeyException('Unknown purpose');
            } elseif (!$this->purpose->isReceivingKeyValid($key)) {
                throw new InvalidKeyException(
                    'Invalid key type. Expected ' .
                        $this->purpose->expectedReceivingKeyType() .
                        ', got ' .
                        \get_class($key)
                );
            }
        }
        $this->key = $key;
        return $this;
    }

    /**
     * Specify the allowed 'purpose' for the token we are going to parse.
     *
     * @param Purpose $purpose
     * @param bool $checkKeyType
     * @return self
     * @throws PasetoException
     */
    public function setPurpose(Purpose $purpose, bool $checkKeyType = false): self
    {
        if ($checkKeyType) {
            /** @var Purpose */
            $expectedPurpose = Purpose::fromReceivingKey($this->key);
            if (!$purpose->equals($expectedPurpose)) {
                throw new InvalidPurposeException(
                    'Invalid purpose. Expected '.$expectedPurpose->rawString()
                    .', got ' . $purpose->rawString()
                );
            }
        }

        $this->purpose = $purpose;
        return $this;
    }

    /**
     * Does this token pass all of the rules defined?
     *
     * @param JsonToken $token
     * @param bool $throwOnFailure
     * @return bool
     * @throws RuleViolation
     */
    public function validate(JsonToken $token, bool $throwOnFailure = false): bool
    {
        if (empty($this->rules)) {
            return true;
        }
        /** @var ValidationRuleInterface $rule */
        foreach ($this->rules as $rule) {
            if (!$rule->isValid($token)) {
                if ($throwOnFailure) {
                    throw new RuleViolation($rule->getFailureMessage());
                }
                return false;
            }
        }
        return true;
    }
}
