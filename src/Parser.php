<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Exception\{
    EncodingException,
    ExceptionCode,
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
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Parsing\PasetoMessage;
use ParagonIE\Paseto\Traits\RegisteredClaims;
use function get_class,
    is_array,
    is_null,
    is_string,
    json_encode,
    json_decode;
use TypeError;
use Throwable;

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

    /** @var string $implicitAssertions */
    protected $implicitAssertions = '';

    /** @var ReceivingKey $key */
    protected $key;

    /** @var ?int $maxClaimCount */
    protected $maxClaimCount = null;

    /** @var ?int $maxClaimDepth */
    protected $maxClaimDepth = null;

    /** @var ?int $maxJsonLength */
    protected $maxJsonLength = null;

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
     *
     * @throws PasetoException
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function __construct(
        ProtocolCollection $allowedVersions = null,
        Purpose $purpose = null,
        ReceivingKey $key = null,
        array $parserRules = []
    ) {
        $this->allowedVersions = $allowedVersions ?? ProtocolCollection::default();
        $this->purpose = $purpose;
        if (!is_null($key)) {
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
     * Get the configured implicit assertions.
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
     * Extract a footer from the PASETO message, as a string.
     *
     * @param string $tainted
     * @return string
     *
     * @throws InvalidPurposeException
     * @throws PasetoException
     * @throws SecurityException
     * @throws TypeError
     */
    public static function extractFooter(string $tainted): string
    {
        return PasetoMessage::fromString($tainted)->footer();
    }

    /**
     * Get a Parser instance intended for local usage.
     * (i.e. shard-key authenticated encryption)
     *
     * @param SymmetricKey $key
     * @param ProtocolCollection|null $allowedVersions
     * @return self
     *
     * @throws PasetoException
     */
    public static function getLocal(
        SymmetricKey $key,
        ProtocolCollection $allowedVersions = null
    ): self {
        return new static(
            $allowedVersions ?? ProtocolCollection::default(),
            Purpose::local(),
            $key
        );
    }

    /**
     * Get a Parser instance intended for remote usage.
     * (i.e. public-key digital signatures).
     *
     * @param AsymmetricPublicKey $key
     * @param ProtocolCollection|null $allowedVersions
     * @return self
     *
     * @throws PasetoException
     */
    public static function getPublic(
        AsymmetricPublicKey $key,
        ProtocolCollection $allowedVersions = null
    ): self {
        return new static(
            $allowedVersions ?? ProtocolCollection::default(),
            Purpose::public(),
            $key
        );
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
     *
     * @throws PasetoException
     * @throws TypeError
     */
    public function parse(string $tainted, bool $skipValidation = false): JsonToken
    {
        $parsed = PasetoMessage::fromString($tainted);

        // First, check against the user's specified list of allowed versions.
        $protocol = $parsed->header()->protocol();
        if (!$this->allowedVersions->has($protocol)) {
            throw new InvalidVersionException(
                'Disallowed or unsupported version',
                ExceptionCode::BAD_VERSION
            );
        }

        /** @var Purpose $purpose */
        $footer = $parsed->footer();
        $purpose = $parsed->header()->purpose();

        // $this->purpose is not mandatory, but if it's set, verify against it.
        if (isset($this->purpose)) {
            if (!$this->purpose->equals($purpose)) {
                throw new InvalidPurposeException(
                    'Disallowed or unsupported purpose',
                    ExceptionCode::PURPOSE_WRONG_FOR_PARSER
                );
            }
        }

        if (!$purpose->isReceivingKeyValid($this->key)) {
            throw new InvalidKeyException(
                'Invalid key type',
                ExceptionCode::PASETO_KEY_TYPE_ERROR
            );
        }

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

        /** @var string|null $decoded */
        // Let's verify/decode according to the appropriate method:
        switch ($purpose) {
            case Purpose::local():
                /** @var SymmetricKey $key */
                $key = $this->key;
                try {
                    $decoded = $protocol::decrypt($tainted, $key, $footer, $implicit);
                } catch (Throwable $ex) {
                    throw new PasetoException(
                        'An error occurred',
                        ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR,
                        $ex
                    );
                }
                break;
            case Purpose::public():
                /** @var AsymmetricPublicKey $key */
                $key = $this->key;
                try {
                    $decoded = $protocol::verify($tainted, $key, $footer, $implicit);
                } catch (Throwable $ex) {
                    throw new PasetoException(
                        'An error occurred',
                        ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR,
                        $ex
                    );
                }
                break;
        }

        // Did we get data?
        if (!isset($decoded)) {
            throw new PasetoException(
                'Unsupported purpose or version.',
                ExceptionCode::PURPOSE_NOT_LOCAL_OR_PUBLIC
            );
        }

        // Throw if the claims were invalid:
        $this->throwIfClaimsJsonInvalid($decoded);

        /** @var array<string, string>|bool $claims */
        $claims = json_decode($decoded, true, ($this->maxClaimDepth ?? 512));
        if (!is_array($claims)) {
            throw new EncodingException(
                'Not a JSON token.',
                ExceptionCode::PAYLOAD_JSON_ERROR
            );
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
     * @param ProtocolCollection $allowlist
     * @return self
     */
    public function setAllowedVersions(ProtocolCollection $allowlist): self
    {
        $this->allowedVersions = $allowlist;
        return $this;
    }

    /**
     * Set the implicit assertions for the constructed PASETO token
     * (only affects v3/v4).
     *
     * @param array $assertions
     * @return self
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
            throw new PasetoException(
                'Could not serialize as string',
                ExceptionCode::IMPLICIT_ASSERTION_JSON_ERROR
            );
        }
        $this->implicitAssertions = $implicit;
        return $this;
    }

    /**
     * Limit the length of the decoded JSON payload containing the claims.
     *
     * @param int|null $length
     * @return self
     */
    public function setMaxJsonLength(?int $length = null): self
    {
        $this->maxJsonLength = $length;
        return $this;
    }

    /**
     * Limit the maximum number of claims in the decoded JSON payload.
     *
     * @param int|null $maximum
     * @return self
     */
    public function setMaxClaimCount(?int $maximum = null): self
    {
        $this->maxClaimCount = $maximum;
        return $this;
    }

    /**
     * Limit the maximum depth of the decoded JSON payload containign the claims.
     *
     * @param int|null $maximum
     * @return self
     */
    public function setMaxClaimDepth(?int $maximum = null): self
    {
        $this->maxClaimDepth = $maximum;
        return $this;
    }

    /**
     * Specify the key for the token we are going to parse.
     *
     * @param ReceivingKey $key
     * @param bool $checkPurpose
     * @return self
     *
     * @throws PasetoException
     */
    public function setKey(ReceivingKey $key, bool $checkPurpose = false): self
    {
        if ($checkPurpose) {
            if (is_null($this->purpose)) {
                throw new InvalidKeyException(
                    'Unknown purpose',
                    ExceptionCode::PURPOSE_NOT_DEFINED
                );
            } elseif (!$this->purpose->isReceivingKeyValid($key)) {
                throw new InvalidKeyException(
                    'Invalid key type. Expected ' .
                        $this->purpose->expectedReceivingKeyType() .
                        ', got ' .
                        get_class($key),
                    ExceptionCode::PASETO_KEY_TYPE_ERROR
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
     *
     * @throws PasetoException
     */
    public function setPurpose(Purpose $purpose, bool $checkKeyType = false): self
    {
        if ($checkKeyType) {
            $expectedPurpose = Purpose::fromReceivingKey($this->key);
            if (!$purpose->equals($expectedPurpose)) {
                throw new InvalidPurposeException(
                    'Invalid purpose. Expected ' .
                        $expectedPurpose->rawString() .
                        ', got ' . $purpose->rawString(),
                    ExceptionCode::PURPOSE_WRONG_FOR_KEY
                );
            }
        }

        $this->purpose = $purpose;
        return $this;
    }

    /**
     * This will throw an EncodingException if the claims JSON string
     * violates one of the configured controls.
     *
     * a. String too long
     * b. Too much recursive depth
     * c. Too many object keys
     *
     * @throws EncodingException
     */
    public function throwIfClaimsJsonInvalid(string $jsonString): void
    {
        if (!is_null($this->maxJsonLength)) {
            $length = Binary::safeStrlen($jsonString);
            if ($length > $this->maxJsonLength) {
                throw new EncodingException(
                    "Claims length is too long ({$length} > {$this->maxJsonLength}",
                    ExceptionCode::CLAIM_JSON_TOO_LONG
                );
            }
        }
        if (!is_null($this->maxClaimCount)) {
            $count = Util::countJsonKeys($jsonString);
            if ($count > $this->maxClaimCount) {
                throw new EncodingException(
                    "Too many claims in this token ({$count} > {$this->maxClaimCount}",
                    ExceptionCode::CLAIM_JSON_TOO_MANY_KEYs
                );
            }
        }
        if (!is_null($this->maxClaimDepth)) {
            $depth = Util::calculateJsonDepth($jsonString);
            if ($depth > $this->maxClaimDepth) {
                throw new EncodingException(
                    "Too many layers of claims ({$depth} > {$this->maxClaimDepth}",
                    ExceptionCode::CLAIM_JSON_TOO_DEEP
                );
            }
        }
    }

    /**
     * Does this token pass all of the rules defined?
     *
     * @param JsonToken $token
     * @param bool $throwOnFailure
     * @return bool
     *
     * @throws RuleViolation
     */
    public function validate(JsonToken $token, bool $throwOnFailure = false): bool
    {
        if (empty($this->rules)) {
            // No rules defined, so we default to "true".
            return true;
        }
        foreach ($this->rules as $rule) {
            if (!$rule->isValid($token)) {
                if ($throwOnFailure) {
                    throw new RuleViolation(
                        $rule->getFailureMessage(),
                        ExceptionCode::PARSER_RULE_FAILED
                    );
                }
                return false;
            }
        }
        return true;
    }
}
