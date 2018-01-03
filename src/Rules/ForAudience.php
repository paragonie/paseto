<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Rules;

use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\{
    JsonToken,
    ValidationRuleInterface
};

/**
 * Class ForAudience
 * @package ParagonIE\PAST\Rules
 */
class ForAudience implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var string $issuer */
    protected $audience;

    /**
     * ForAudience constructor.
     * @param string $audience
     */
    public function __construct(string $audience)
    {
        $this->audience = $audience;
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
            $audience = $token->getAudience();
            if (!\hash_equals($this->audience, $audience)) {
                $this->failure = 'This token is not intended for ' .
                    $this->audience . ' (expected); instead, it is intended for ' .
                    $audience . ' instead.';
                return false;
            }
        } catch (PastException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
