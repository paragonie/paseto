<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Rules;

use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\JsonToken;
use ParagonIE\PAST\ValidationRuleInterface;

/**
 * Class NotExpired
 * @package ParagonIE\PAST\Rules
 */
class NotExpired implements ValidationRuleInterface
{
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
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $expires = $token->getExpiration();
            return $expires > $this->now;
        } catch (PastException $ex) {
            return false;
        }
    }
}
