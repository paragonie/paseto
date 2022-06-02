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
 * Class IdentifiedBy
 * @package ParagonIE\Paseto\Rules
 */
class IdentifiedBy implements ValidationRuleInterface
{
    protected string $failure = 'OK';
    protected string $identifier;

    /**
     * IdentifiedBy constructor.
     * @param string $identifier
     */
    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }

    /**
     * @return string
     */
    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * Does the 'jti' claim match what we expect from the Parser?
     *
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $identifier = $token->getJti();
            if (!hash_equals($this->identifier, $identifier)) {
                $this->failure = 'This token was expected to be identified by ' .
                    $this->identifier . ', but it was identified by ' .
                    $identifier .' instead.';
                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
