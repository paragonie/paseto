<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\{
    JsonToken,
    ValidationRuleInterface
};
use Override;
use ParagonIE\Paseto\Exception\PasetoException;
use Exception;
use DateTime;
use DateTimeInterface;

/**
 * Class ValidAt
 * @package ParagonIE\Paseto\Rules
 * @api
 */
class ValidAt implements ValidationRuleInterface
{
    protected string $failure = 'OK';
    protected DateTimeInterface $now;

    /**
     * ValidAt constructor.
     * 
     * @param DateTimeInterface|null $now
     */
    public function __construct(?DateTimeInterface $now = null)
    {
        if (!$now) {
            $now = new DateTime();
        }
        $this->now = $now;
    }

    /**
     * @return string
     */
    #[Override]
    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * @param JsonToken $token
     * @return bool
     *
     * @throws Exception
     */
    #[Override]
    public function isValid(JsonToken $token): bool
    {
        try {
            $issuedAt = $token->getIssuedAt();
            if ($issuedAt > $this->now) {
                $this->failure = 'This token was issued in the future.';
                return false;
            }
            $notBefore = $token->getNotBefore();
            if ($notBefore > $this->now) {
                $this->failure = 'This token cannot be used yet.';
                return false;
            }
            $expires = $token->getExpiration();
            if ($expires < $this->now) {
                $this->failure = 'This token has expired.';
                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();
            return false;
        }
        return true;
    }
}
