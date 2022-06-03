<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Exception\{
    ExceptionCode,
    PasetoException
};
use PHPUnit\Framework\TestCase;

class ExceptionHelpfulTest extends TestCase
{
    /**
     * @param int $code
     * @throws PasetoException
     */
    private function generateException(int $code): void
    {
        throw new PasetoException('Test', $code);
    }

    public function codeProvider(): array
    {
        return [
            [ExceptionCode::BAD_VERSION],
            [ExceptionCode::CLAIM_JSON_TOO_LONG],
            [ExceptionCode::CLAIM_JSON_TOO_MANY_KEYs],
            [ExceptionCode::CLAIM_JSON_TOO_DEEP],
            [ExceptionCode::FOOTER_JSON_ERROR],
            [ExceptionCode::FOOTER_MISMATCH_EXPECTED],
            [ExceptionCode::HKDF_BAD_LENGTH],
            [ExceptionCode::IMPLICIT_ASSERTION_JSON_ERROR],
            [ExceptionCode::IMPLICIT_ASSERTION_NOT_SUPPORTED],
            [ExceptionCode::INVALID_BASE64URL],
            [ExceptionCode::INVALID_HEADER],
            [ExceptionCode::INVALID_JSON],
            [ExceptionCode::INVALID_MAC],
            [ExceptionCode::INVALID_NUMBER_OF_PIECES],
            [ExceptionCode::INVALID_SIGNATURE],
            [ExceptionCode::PASETO_KEY_TYPE_ERROR],
            [ExceptionCode::PASETO_KEY_IS_NULL],
            [ExceptionCode::PARSER_RULE_FAILED],
            [ExceptionCode::PAYLOAD_JSON_ERROR],
            [ExceptionCode::PURPOSE_NOT_DEFINED],
            [ExceptionCode::PURPOSE_NOT_LOCAL_OR_PUBLIC],
            [ExceptionCode::PURPOSE_WRONG_FOR_KEY],
            [ExceptionCode::PURPOSE_WRONG_FOR_PARSER],
            [ExceptionCode::SPECIFIED_CLAIM_NOT_FOUND],
            [ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR],
            [ExceptionCode::WRONG_KEY_FOR_VERSION],
            [ExceptionCode::IMPOSSIBLE_CONDITION],
            [ExceptionCode::INVOKED_RAW_ON_MULTIKEY],
            [ExceptionCode::KEY_NOT_IN_KEYRING],
            [ExceptionCode::UNDEFINED_PROPERTY],
            [ExceptionCode::INVALID_MESSAGE_LENGTH]
        ];
    }

    /**
     * @dataProvider codeProvider
     */
    public function testException(int $code): void
    {
        try {
            $this->generateException($code);
        } catch (PasetoException $ex) {
            $expect = ExceptionCode::explainErrorCode($code);
            $message = $ex->getHelpfulMessage();
            $this->assertSame($expect, $message);
        }
    }
}
