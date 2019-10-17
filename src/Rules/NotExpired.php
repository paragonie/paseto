<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};
use ParagonIE\Paseto\Exception\PasetoException;

/**
 * Class NotExpired
 * @package ParagonIE\Paseto\Rules
 */
class NotExpired implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var \DateTimeInterface $now */
    protected $now;

    /**
     * NotExpired constructor.
     * @param \DateTimeInterface|null $now Allows "now" to be overwritten for unit testing
     */
    public function __construct(\DateTimeInterface $now = null)
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
