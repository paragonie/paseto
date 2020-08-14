<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};
use ParagonIE\Paseto\Exception\PasetoException;

/**
 * Class IdentifiedBy
 * @package ParagonIE\Paseto\Rules
 */
class IdentifiedBy implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var string $issuer */
    protected $issuer;

    /**
     * IdentifiedBy constructor.
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
            $issuer = $token->getIssuer();
            if (!\hash_equals($this->issuer, $issuer)) {
                $this->failure = 'This token was expected to be identified by ' .
                    $this->issuer . ', but it was identified by ' .
                    $issuer .' instead.';
                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
