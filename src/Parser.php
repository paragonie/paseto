<?php
declare(strict_types=1);
namespace ParagonIE\PAST;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\PAST\Exception\{
    EncodingException,
    InvalidKeyException,
    InvalidPurposeException,
    InvalidVersionException,
    PastException,
    RuleViolation,
    SecurityException
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
 * Class Parser
 * @package ParagonIE\PAST
 * @psalm-suppress PropertyNotSetInConstructor
 */
class Parser
{
    use RegisteredClaims;

    const DEFAULT_VERSION_ALLOW = [
        Version1::HEADER,
        Version2::HEADER
    ];

    /** @var array<int, string> */
    protected $allowedVersions;

    /** @var KeyInterface $key */
    protected $key;

    /** @var string $purpose */
    protected $purpose;

    /** @var array<int, ValidationRuleInterface> */
    protected $rules = [];

    /**
     * Parser constructor.
     *
     * @param array<int, string> $allowedVersions
     * @param string $purpose
     * @param KeyInterface|null $key
     * @param array<int, ValidationRuleInterface> $parserRules
     * @throws PastException
     */
    public function __construct(
        array $allowedVersions = self::DEFAULT_VERSION_ALLOW,
        string $purpose = '',
        KeyInterface $key = null,
        array $parserRules = []
    ) {
        $this->allowedVersions = $allowedVersions;
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
     * @throws PastException
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
        if (!\in_array($header, $this->allowedVersions, true)) {
            throw new InvalidVersionException('Disallowed or unsupported version');
        }

        // Our parser's built-in whitelist of headers is defined here.
        switch ($header) {
            case Version1::HEADER:
                $protocol = Version1::class;
                break;
            case Version2::HEADER:
                $protocol = Version2::class;
                break;
            default:
                throw new InvalidVersionException('Disallowed or unsupported version');
        }
        /** @var ProtocolInterface $protocol */
        /** @var string $purpose */
        $footer = '';
        $purpose = $pieces[1];

        // $this->purpose is not mandatory, but if it's set, verify against it.
        if (!empty($this->purpose)) {
            if (!\hash_equals($this->purpose, $purpose)) {
                throw new InvalidPurposeException('Disallowed or unsupported purpose');
            }
        }

        // Let's verify/decode according to the appropriate method:
        switch ($purpose) {
            case 'auth':
                if (!($this->key instanceof SymmetricAuthenticationKey)) {
                    throw new InvalidKeyException('Invalid key type');
                }
                $footer = (\count($pieces) > 3)
                    ? Base64UrlSafe::decode($pieces[3])
                    : '';
                try {
                    /** @var string $decoded */
                    $decoded = $protocol::authVerify($tainted, $this->key, $footer);
                } catch (\Throwable $ex) {
                    throw new PastException('An error occurred', 0, $ex);
                }
                break;
            case 'enc':
                if (!($this->key instanceof SymmetricEncryptionKey)) {
                    throw new InvalidKeyException('Invalid key type');
                }
                $footer = (\count($pieces) > 3)
                    ? Base64UrlSafe::decode($pieces[3])
                    : '';
                try {
                    /** @var string $decoded */
                    $decoded = $protocol::decrypt($tainted, $this->key, $footer);
                } catch (\Throwable $ex) {
                    throw new PastException('An error occurred', 0, $ex);
                }
                break;
            case 'seal':
                if (!($this->key instanceof AsymmetricSecretKey)) {
                    throw new InvalidKeyException('Invalid key type');
                }
                $footer = (\count($pieces) > 4)
                    ? Base64UrlSafe::decode($pieces[4])
                    : '';
                try {
                    /** @var string $decoded */
                    $decoded = $protocol::unseal($tainted, $this->key, $footer);
                } catch (\Throwable $ex) {
                    throw new PastException('An error occurred', 0, $ex);
                }
                break;
            case 'sign':
                if (!($this->key instanceof AsymmetricPublicKey)) {
                    throw new InvalidKeyException('Invalid key type');
                }
                $footer = (\count($pieces) > 4)
                    ? Base64UrlSafe::decode($pieces[4])
                    : '';
                try {
                    /** @var string $decoded */
                    $decoded = $protocol::signVerify($tainted, $this->key, $footer);
                } catch (\Throwable $ex) {
                    throw new PastException('An error occurred', 0, $ex);
                }
                break;
        }

        // Did we get data?
        if (!isset($decoded)) {
            throw new PastException('Unsupported purpose or version.');
        }
        /** @var array $claims */
        $claims = \json_decode((string) $decoded, true);
        if (!\is_array($claims)) {
            throw new EncodingException('Not a JSON token.');
        }

        // Let's build the token object.
        $token = (new JsonToken())
            ->setVersion($header)
            ->setPurpose($purpose)
            ->setKey($this->key)
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
     * @param array<int, string> $whitelist
     * @return self
     */
    public function setAllowedVarsions(array $whitelist): self
    {
        $this->allowedVersions = $whitelist;
        return $this;
    }

    /**
     * Specify the key for the token we are going to parse.
     *
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
                    if (!($key instanceof AsymmetricSecretKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' . AsymmetricSecretKey::class . ', got ' . \get_class($key)
                        );
                    }
                    break;
                case 'sign':
                    if (!($key instanceof AsymmetricPublicKey)) {
                        throw new InvalidKeyException(
                            'Invalid key type. Expected ' . AsymmetricPublicKey::class . ', got ' . \get_class($key)
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
     * Specify the allowed 'purpose' for the token we are going to parse.
     *
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
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected auth, got ' . $purpose
                        );
                    }
                    break;
                case SymmetricEncryptionKey::class:
                    if (!\hash_equals('enc', $purpose)) {
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected enc, got ' . $purpose
                        );
                    }
                    break;
                case AsymmetricSecretKey::class:
                    if (!\hash_equals('seal', $purpose)) {
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected seal, got ' . $purpose
                        );
                    }
                    break;
                case AsymmetricPublicKey::class:
                    if (!\hash_equals('sign', $purpose)) {
                        throw new InvalidPurposeException(
                            'Invalid purpose. Expected sign, got ' . $purpose
                        );
                    }
                    break;
                default:
                    throw new InvalidPurposeException('Unknown purpose: ' . $purpose);
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
