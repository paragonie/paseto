<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use Exception;
use ParagonIE\Paseto\Exception\{
    EncodingException,
    ExceptionCode,
    InvalidKeyException,
    InvalidPurposeException,
    InvalidVersionException,
    NotFoundException,
    PasetoException,
    RuleViolation,
    SecurityException
};
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    SymmetricKey
};
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Parsing\{
    NonExpiringSupport,
    PasetoMessage
};
use ParagonIE\Paseto\Rules\NotExpired;
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
 */
class Parser extends PasetoBase
{
    use NonExpiringSupport;
    use RegisteredClaims;

    /** @var ProtocolCollection */
    protected ProtocolCollection $allowedVersions;

    /** @var string $implicitAssertions */
    protected string $implicitAssertions = '';

    /** @var ?ReceivingKey $key */
    protected ?ReceivingKey $key = null;

    /** @var ?int $maxClaimCount */
    protected ?int $maxClaimCount = null;

    /** @var ?int $maxClaimDepth */
    protected ?int $maxClaimDepth = null;

    /** @var ?int $maxJsonLength */
    protected ?int $maxJsonLength = null;

    /** @var Purpose|null $purpose */
    protected ?Purpose $purpose;

    /** @var array<int, ValidationRuleInterface> */
    protected array $rules = [];

    /**
     * Parser constructor.
     *
     * @param ProtocolCollection|null $allowedVersions
     * @param Purpose|null $purpose
     * @param ReceivingKey|null $key
     * @param array<int, ValidationRuleInterface> $parserRules
     *
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
     * @throws EncodingException
     */
    public function getImplicitAssertions(): array
    {
        if (empty($this->implicitAssertions)) {
            return [];
        }
        $decoded = json_decode($this->implicitAssertions, true);
        if (!is_array($decoded)) {
            throw new EncodingException(
                'Implicit Assertion string is not a valid JSON object',
                ExceptionCode::FOOTER_JSON_ERROR
            );
        }
        return $decoded;
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
        return new self(
            $allowedVersions ?? ProtocolCollection::default(),
            Purpose::local(),
            $key
        );
    }

    /**
     * Get a Parser instance intended for local usage.
     * (i.e. shard-key authenticated encryption)
     *
     * @param ReceivingKeyRing $key
     * @param ProtocolCollection|null $allowedVersions
     * @return self
     *
     * @throws PasetoException
     */
    public static function getLocalWithKeyRing(
        ReceivingKeyRing   $key,
        ProtocolCollection $allowedVersions = null
    ): self {
        return new self(
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
        return new self(
            $allowedVersions ?? ProtocolCollection::default(),
            Purpose::public(),
            $key
        );
    }

    /**
     * Get a Parser instance intended for remote usage.
     * (i.e. public-key digital signatures).
     *
     * @param ReceivingKeyRing $key
     * @param ProtocolCollection|null $allowedVersions
     * @return self
     *
     * @throws PasetoException
     */
    public static function getPublicWithKeyRing(
        ReceivingKeyRing   $key,
        ProtocolCollection $allowedVersions = null
    ): self {
        return new self(
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
     * If our footer contains a JSON payload, first perform the necessary safety checks
     * (string length, number of keys, recursive depth) before attempting json_decode().
     *
     * If we end up with a valid payload, and a Key ID (`kid`) is defined, return that.
     *
     * Empty / non-JSON payloads result in an empty string.
     * Malformed or unsafe JSON payloads result in an Exception being thrown.
     * Missing `kid` results in an empty string.
     * A non-string `kid` results in an empty string.
     * Otherwise, return the `kid` to the caller.
     *
     * @ref https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#storing-json-in-the-footer
     *
     * @param string $data
     * @return string
     *
     * @throws EncodingException
     * @throws SecurityException
     */
    public function extractKeyIdFromFooterJson(string $data): string
    {
        $length = Binary::safeStrlen($data);
        if ($length < 6) {
            // Too short to be JSON
            return '';
        }
        if ($data[0] !== '{' || $data[$length - 1] !== '}') {
            // Not JSON
            return '';
        }

        // Perform safety checks before invoking json_decode()
        if (!is_null($this->maxJsonLength) && $length > $this->maxJsonLength) {
            throw new SecurityException(
                "Footer JSON is too long",
                ExceptionCode::FOOTER_JSON_ERROR
            );
        }
        if (!is_null($this->maxClaimDepth)) {
            if (Util::calculateJsonDepth($data) > $this->maxClaimDepth) {
                throw new SecurityException(
                    "Footer JSON is has too much recursion",
                    ExceptionCode::FOOTER_JSON_ERROR
                );
            }
        }
        if (!is_null($this->maxClaimCount)) {
            if (Util::countJsonKeys($data) > $this->maxClaimCount) {
                throw new SecurityException(
                    "Footer JSON is has too many keys",
                    ExceptionCode::FOOTER_JSON_ERROR
                );
            }
        }

        $decoded = json_decode($data, true, $this->maxClaimDepth ?? 512);
        if (!is_array($decoded)) {
            return '';
        }

        // No key id -> ''
        $index = (string) static::KEY_ID_FOOTER_CLAIM;
        if (!isset($decoded[$index])) {
            return '';
        }
        // Non-string in key id -> ''
        if (!is_string($decoded[$index])) {
            return '';
        }
        return $decoded[$index];
    }

    /**
     * Fetch a key (either from $this->key directly, or by its Key ID if we've
     * stored a KeyRing), then make sure it's an Asymmetric Public Key.
     *
     * @param string $keyId
     *
     * @return AsymmetricPublicKey
     * @throws InvalidKeyException
     * @throws NotFoundException
     * @throws PasetoException
     */
    public function fetchPublicKey(string $keyId = ''): AsymmetricPublicKey
    {
        if ($this->key instanceof ReceivingKeyRing) {
            $key = $this->key->fetchKey($keyId);
        } else {
            $key = $this->key;
        }
        if (!($key instanceof AsymmetricPublicKey)) {
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
     * @param string $keyId
     *
     * @return SymmetricKey
     * @throws InvalidKeyException
     * @throws NotFoundException
     * @throws PasetoException
     */
    public function fetchSymmetricKey(string $keyId = ''): SymmetricKey
    {
        if ($this->key instanceof ReceivingKeyRing) {
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

        if (!($this->key instanceof ReceivingKeyRing) && !is_null($this->key)) {
            if (!$purpose->isReceivingKeyValid($this->key)) {
                throw new InvalidKeyException(
                    'Invalid key type',
                    ExceptionCode::PASETO_KEY_TYPE_ERROR
                );
            }
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
        $keyId = $this->extractKeyIdFromFooterJson($footer);

        /** @var string|null $decoded */
        // Let's verify/decode according to the appropriate method:
        switch ($purpose) {
            case Purpose::local():
                // A symmetric key is, by type-safety, suitable for local tokens
                $key = $this->fetchSymmetricKey($keyId);

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
                // An asymmetric public key is, by type-safety, suitable for public tokens
                $key = $this->fetchPublicKey($keyId);
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

        /** @var array<string, mixed>|bool $claims */
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

        if (!$skipValidation) {
            // Validate all the rules that were specified:
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
        if ($key instanceof ReceivingKeyRing) {
            $this->key = $key;
            return $this;
        }
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
        if ($checkKeyType && !is_null($this->key)) {
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
        $rules = $this->rules;
        if (!$this->nonExpiring) {
            // By default, we disallow expired tokens
            $rules[] = new NotExpired();
        }
        if (empty($rules)) {
            // No rules defined, so we default to "true".
            return true;
        }

        foreach ($rules as $rule) {
            try {
                if (!$rule->isValid($token)) {
                    if ($throwOnFailure) {
                        throw new RuleViolation(
                            $rule->getFailureMessage(),
                            ExceptionCode::PARSER_RULE_FAILED
                        );
                    }
                    return false;
                }
            } catch (Exception $ex) {
                if ($throwOnFailure) {
                    throw new RuleViolation(
                        $ex->getMessage(),
                        ExceptionCode::PARSER_RULE_FAILED
                    );
                }
                return false;
            }
        }
        return true;
    }
}
