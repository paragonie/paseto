<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\Keys\{
    AsymmetricSecretKey,
    SymmetricAuthenticationKey
};
use ParagonIE\PAST\Parser;
use PHPUnit\Framework\TestCase;

/**
 * Class ParserTest
 * @package ParagonIE\PAST\Tests
 */
class ParserTest extends TestCase
{
    /**
     * @covers Parser::parse()
     * @throws PastException
     */
    public function testAuthToken()
    {
        $key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');

        $serialized = 'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9pBzDGiV6cmCX8Wxuj09xmNYiVOcD9yuE0TntviAEWvs=';
        $token = (new Parser())
            ->setPurpose('auth')
            ->setKey($key)
            ->parse($serialized);
        $this->assertSame(
            '2039-01-01T00:00:00+00:00',
            $token->getExpiration()->format(\DateTime::ATOM),
            'Mismatched expiration date/time'
        );
        $this->assertSame(
            'this is a signed message',
            $token->get('data'),
            'Custom claim not found'
        );
        $this->assertSame($serialized, (string) $token);

        // Switch to asymmetric-key crypto:
        $token->setPurpose('sign')
            ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9J_YYSKaRss60fvAT5jR0KzGXRrgAT9hSPbJ8O5w1F_EgTTU4Zbjms_ngcM_gEtUlvDIFs1QFv3GWkU4Ya6z9CQ==',
            (string) $token,
            'Switching to signing caused a different signature'
        );
    }
}
