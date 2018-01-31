<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};

/**
 * Class IssuedBy
 * @package ParagonIE\Paseto\Rules
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
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}