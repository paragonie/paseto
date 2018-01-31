<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

/**
 * Interface ValidationRuleInterface
 * @package ParagonIE\Paseto
 */
interface ValidationRuleInterface
{
    /**
     * Get the message of the last failure. Optional.
     *
     * @return string
     */
    public function getFailureMessage(): string;

    /**
     * Validate this token according to this rule.
     *
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool;
}
