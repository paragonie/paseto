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
 * Class Subject
 * @package ParagonIE\Paseto\Rules
 */
class Subject implements ValidationRuleInterface
{
    protected string $failure = 'OK';
    protected string $subject;

    /**
     * Subject constructor.
     * @param string $subject
     */
    public function __construct(string $subject)
    {
        $this->subject = $subject;
    }

    /**
     * @return string
     */
    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * Does the 'sub' claim match what we expect from the Parser?
     *
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $subject = $token->getSubject();
            if (!hash_equals($this->subject, $subject)) {
                $this->failure = 'This token was not related to ' .
                    $this->subject . ' (expected); its subject is ' .
                    $subject . ' instead.';
                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
