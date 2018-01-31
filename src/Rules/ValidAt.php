<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};

/**
 * Class ValidAt
 * @package ParagonIE\Paseto\Rules
 */
class ValidAt implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var \DateTime $now */
    protected $now;

    /**
     * ValidAt constructor.
     * @param \DateTime|null $now
     */
    public function __construct(\DateTime $now = null)
    {
        if (!$now) {
            $now = new \DateTime();
        }
        $this->now = $now;
    }

    /**
     * @return string
     */
    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $issuedAt = $token->getIssuedAt();
            if ($issuedAt > $this->now) {
                $this->failure = 'This token was issued in the future.';
                return false;
            }
            $notBefore = $token->getNotBefore();
            if ($notBefore > $this->now) {
                $this->failure = 'This token cannot be used yet.';
                return false;
            }
            $expires = $token->getExpiration();
            if ($expires < $this->now) {
                $this->failure = 'This token has expired.';
                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
