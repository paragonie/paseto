<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Rules;

use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\{
    JsonToken,
    ValidationRuleInterface
};

/**
 * Class Subject
 * @package ParagonIE\PAST\Rules
 */
class Subject implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var string $subject */
    protected $subject;

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
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $subject = $token->getSubject();
            if (!\hash_equals($this->subject, $subject)) {
                $this->failure = 'This token was not related to ' .
                    $this->subject . ' (expected); its subject is ' .
                    $subject . ' instead.';
                return false;
            }
        } catch (PastException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
