<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Exception;

/**
 * Class ExceptionCode
 * @package ParagonIE\Paseto\Exception
 */
abstract class ExceptionCode
{
    const BAD_VERSION                      = 0x3142EE01;
    const CLAIM_JSON_TOO_LONG              = 0x3142EE02;
    const CLAIM_JSON_TOO_MANY_KEYs         = 0x3142EE03;
    const CLAIM_JSON_TOO_DEEP              = 0x3142EE04;
    const FOOTER_JSON_ERROR                = 0x3142EE05;
    const FOOTER_MISMATCH_EXPECTED         = 0x3142EE06;
    const HKDF_BAD_LENGTH                  = 0x3142EE07;
    const IMPLICIT_ASSERTION_JSON_ERROR    = 0x3142EE08;
    const IMPLICIT_ASSERTION_NOT_SUPPORTED = 0x3142EE09;
    const INVALID_BASE64URL                = 0x3142EE0A;
    const INVALID_HEADER                   = 0x3142EE0B;
    const INVALID_JSON                     = 0x3142EE0C;
    const INVALID_MAC                      = 0x3142EE0D;
    const INVALID_NUMBER_OF_PIECES         = 0x3142EE0E;
    const INVALID_SIGNATURE                = 0x3142EE0F;
    const PASETO_KEY_TYPE_ERROR            = 0x3142EE10;
    const PASETO_KEY_IS_NULL               = 0x3142EE11;
    const PARSER_RULE_FAILED               = 0x3142EE12;
    const PAYLOAD_JSON_ERROR               = 0x3142EE13;
    const PURPOSE_NOT_DEFINED              = 0x3142EE14;
    const PURPOSE_NOT_LOCAL_OR_PUBLIC      = 0x3142EE15;
    const PURPOSE_WRONG_FOR_KEY            = 0x3142EE16;
    const PURPOSE_WRONG_FOR_PARSER         = 0x3142EE17;
    const SPECIFIED_CLAIM_NOT_FOUND        = 0x3142EE18;
    const UNSPECIFIED_CRYPTOGRAPHIC_ERROR  = 0x3142EE19;
    const WRONG_KEY_FOR_VERSION            = 0x3142EE1A;
    const IMPOSSIBLE_CONDITION             = 0x3142EE1B;
    const INVOKED_RAW_ON_MULTIKEY          = 0x3142EE1C;
    const KEY_NOT_IN_KEYRING               = 0x3142EE1D;
    const UNDEFINED_PROPERTY               = 0x3142EE1E;
    const INVALID_MESSAGE_LENGTH           = 0x3142EE1F;
    const OBSOLETE_PROTOCOL                = 0x3142EE20;

    /**
     * @param int $code
     * @return string
     */
    public static function explainErrorCode(int $code): string
    {
        return match ($code) {
            self::BAD_VERSION =>
                "PASETO is very pedantic about versions. " .
                "If you're getting this message, you were insufficiently pedantic in how you called this feature.",
            self::CLAIM_JSON_TOO_LONG =>
                "The length of the JSON-encoded claim sis longer than the Parser is configured to accept.",
            self::CLAIM_JSON_TOO_MANY_KEYs =>
                "The number of object keys in the JSON-encoded claims exceeds the configured limit. " .
                "This may be a Hash-DoS attempt, but it's most likely a misconfiguration.",
            self::CLAIM_JSON_TOO_DEEP =>
                "This JSON-encoded claims has too much recursive depth.",
            self::FOOTER_JSON_ERROR =>
                "A JSON error occurred when JSON-serializing or deserializing the footer.",
            self::FOOTER_MISMATCH_EXPECTED =>
                "We were expecting a different footer than the payload contained.",
            self::HKDF_BAD_LENGTH =>
                "At some point, HKDF was called incorrectly. " .
                "This shouldn't ever happen in practice. Make sure your copy of this library imported correctly.",
            self::IMPLICIT_ASSERTION_JSON_ERROR =>
                "A JSON error occurred when JSON-serializing or deserializing the Implicit Assertions.",
            self::IMPLICIT_ASSERTION_NOT_SUPPORTED =>
                "Implicit Assertions are only a part of Version 3 and Version 4. " .
                "This feature is explicitly not permitted in older versions to ensure backwards compatibility.",
            self::INVALID_BASE64URL =>
                "An error occurred when attempting to decode what we expected to be a base64url-encoded string. " .
                "This usually implies invalid data was passed to this method. " .
                "Check that you're passing data correctly.",
            self::INVALID_HEADER =>
                "The header did not match what was expected. " .
                "Make sure you're passing the right token to the right methods.",
            self::INVALID_JSON =>
                "When attempting to calculate the recursive depth of the JSON payload, we arrived at " .
                "an invalid state. This usually happens when there aren't an equal number of open brackets " .
                "and close brackets, or they're not in the proper sequence." .
                "This *may* be an attempt to attack the JSON parser library (i.e. stack overflow), " .
                "but we detected and prevented this invalid data from reaching the JSON parser.",
            self::INVALID_MAC =>
                "The message authentication code provided with this message did not match the one we calculated.",
            self::IMPOSSIBLE_CONDITION =>
                "A condition we thought impossible has occurred.",
            self::INVOKED_RAW_ON_MULTIKEY =>
                "The raw() method was invoked on a SendingKeyMap or ReceivingKeyMap object, " .
                "instead of the actual key. This is an error. Invoke fetch() to get the underling key " .
                "and pass that instead.",
            self::KEY_NOT_IN_KEYRING =>
                "The key you requested is not in this keyring.",
            self::UNDEFINED_PROPERTY =>
                "An expected property was not defined at runtime.",
            self::INVALID_MESSAGE_LENGTH =>
                "The received PASETO was too short to be valid.",
            self::OBSOLETE_PROTOCOL =>
                "The PASETO protocol version you specified was deprecated and then removed from this library.",
            default => 'Unknown error code',
        };
    }
}
