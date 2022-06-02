<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};
use ParagonIE\Paseto\Exception\PasetoException;
use function hash_equals;

/**
 * Class ForAudience
 * @package ParagonIE\Paseto\Rules
 */
class ForAudience implements ValidationRuleInterface
{
    protected string $failure = 'OK';
    protected string $audience;

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
     * Does the 'aud' claim match what we expect from the Parser?
     *
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $audience = $token->getAudience();
            if (!hash_equals($this->audience, $audience)) {
                $this->failure = 'This token is not intended for ' .
                    $this->audience . ' (expected); instead, it is intended for ' .
                    $audience . ' instead.';
                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
