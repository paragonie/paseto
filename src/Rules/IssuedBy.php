<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Rules;

use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\{
    JsonToken,
    ValidationRuleInterface
};

/**
 * Class IssuedBy
 * @package ParagonIE\PAST\Rules
 */
class IssuedBy implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var string $issuer */
    protected $issuer;

    /**
     * IssuedBy constructor.
     * @param string $issuer
     */
    public function __construct(string $issuer)
    {
        $this->issuer = $issuer;
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
            $issuedBy = $token->getIssuer();
            if (!\hash_equals($this->issuer, $issuedBy)) {
                $this->failure = 'This token was not issued by ' .
                    $this->issuer . ' (expected); it was issued by ' .
                    $issuedBy . ' instead.';
                return false;
            }
        } catch (PastException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}