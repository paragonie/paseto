<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\EncodingException;
use ParagonIE\Paseto\JsonToken;
use ParagonIE\Paseto\Util;
use ParagonIE\Paseto\ValidationRuleInterface;

/**
 * Class FooterJSON
 * @package ParagonIE\Paseto\Rules
 */
class FooterJSON implements ValidationRuleInterface
{
    /** @var int $maxDepth */
    protected $maxDepth;

    /** @var int $maxKeys */
    protected $maxKeys;

    /** @var int $maxLength */
    protected $maxLength;

    /** @var string $rejectReason */
    protected $rejectReason = '';

    /**
     * FooterJSON constructor.
     *
     * @param int $maxDepth
     * @param int $maxLength
     * @param int $maxKeys
     */
    public function __construct(
        int $maxDepth = 2,
        int $maxLength = 8192,
        int $maxKeys = 512
    ) {
        $this->maxDepth = $maxDepth;
        $this->maxKeys = $maxKeys;
        $this->maxLength = $maxLength;
    }

    /**
     * Get the message of the last failure. Optional.
     *
     * @return string
     */
    public function getFailureMessage(): string
    {
        if ($this->rejectReason) {
            return 'The JSON-encoded footer is invalid: ' . $this->rejectReason;
        }
        return 'The JSON-encoded footer is invalid';
    }

    /**
     * Validate this token according to this rule.
     *
     * @param JsonToken $token
     * @return bool
     *
     * @throws EncodingException
     */
    public function isValid(JsonToken $token): bool
    {
        $json = $token->getFooter();
        if (empty($json)) {
            $this->rejectReason = "Footer is empty, when JSON was expected.";
            return false;
        }
        $length = Binary::safeStrlen($json);
        if ($length > $this->maxLength) {
            $this->rejectReason = "Footer is too long ({$length}, when the maximum allowed is {$this->maxLength})";
            return false;
        }

        $count = Util::countJsonKeys($json);
        if ($count > $this->maxKeys) {
            $this->rejectReason = "Footer has too many keys ({$count}, when the maximum allowed is {$this->maxKeys})";
            return false;
        }

        $depth = Util::calculateJsonDepth($json);
        if ($depth > $this->maxDepth) {
            $this->rejectReason = "Maximum stack depth exceeded";
            return false;
        }

        /** @var array|bool|null $decoded */
        $decoded = json_decode($json, true, $this->maxDepth);
        if (!$decoded) {
            $this->rejectReason = json_last_error_msg();
        }
        return is_array($decoded);
    }

    /**
     * @param int $maxDepth
     * @return self
     */
    public function setMaxDepth(int $maxDepth): self
    {
        $this->maxDepth = $maxDepth;
        return $this;
    }

    /**
     * @param int $maxKeys
     * @return self
     */
    public function setMaxKeys(int $maxKeys): self
    {
        $this->maxKeys = $maxKeys;
        return $this;
    }

    /**
     * @param int $maxLength
     * @return self
     */
    public function setMaxLength(int $maxLength): self
    {
        $this->maxLength = $maxLength;
        return $this;
    }

    /**
     * @param int $maxDepth
     * @return self
     */
    public function withMaxDepth(int $maxDepth): self
    {
        return (clone $this)->setMaxDepth($maxDepth);
    }

    /**
     * @param int $maxKeys
     * @return self
     */
    public function withMaxKeys(int $maxKeys): self
    {
        return (clone $this)->setMaxKeys($maxKeys);
    }

    /**
     * @param int $maxLength
     * @return self
     */
    public function withMaxLength(int $maxLength): self
    {
        return (clone $this)->setMaxLength($maxLength);
    }
}