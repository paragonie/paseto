<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};

/**
 * Class NotExpired
 * @package ParagonIE\Paseto\Rules
 */
class NotExpired implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var \DateTime $now */
    protected $now;

    /**
     * NotExpired constructor.
     * @param \DateTime|null $now Allows "now" to be overwritten for unit testing
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
