<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};

/**
 * Class IdentifiedBy
 * @package ParagonIE\Paseto\Rules
 */
class IdentifiedBy implements ValidationRuleInterface
{
    /** @var string $failure */
    protected $failure = 'OK';

    /** @var string $issuer */
    protected $id;

    /**
     * IdentifiedBy constructor.
     * @param string $id
     */
    public function __construct(string $id)
    {
        $this->id = $id;
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
            $jti = $token->getJti();
            if (!\hash_equals($this->id, $jti)) {
                $this->failure = 'This token was expected to be identified by ' .
                    $this->id . ', but it was identified by ' .
                    $jti .' instead.';
                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
