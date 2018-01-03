<?php
declare(strict_types=1);
namespace ParagonIE\PAST;

/**
 * Interface ValidationRuleInterface
 * @package ParagonIE\PAST
 */
interface ValidationRuleInterface
{
    /**
     * @return string
     */
    public function getFailureMessage(): string;

    /**
     * @param JsonToken $token
     * @return bool
     */
    public function isValid(JsonToken $token): bool;
}
