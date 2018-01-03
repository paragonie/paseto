<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\Keys\{
    AsymmetricSecretKey,
    SymmetricAuthenticationKey
};
use ParagonIE\PAST\Parser;
use ParagonIE\PAST\Rules\NotExpired;
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

        $serialized = 'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9RlncOC5ppeg9qraMSSfXlDC-XzpBWDrZEt_F8rpXpbo=';
        $parser = (new Parser())
            ->setPurpose('auth')
            ->setKey($key);
        $token = $parser->parse($serialized);
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

        $this->assertTrue($parser->validate($token));
        $parser->addRule(new NotExpired(new \DateTime('2007-01-01T00:00:00')));
        $this->assertTrue($parser->validate($token));

        $cloned = clone $parser;
        $cloned->addRule(new NotExpired(new \DateTime('2050-01-01T23:59:59')));
        $this->assertFalse($cloned->validate($token));

        try {
            $cloned->parse($serialized);
            $this->fail('Validation logic is being ignored.');
        } catch (PastException $ex) {
        }
        $parser->parse($serialized);

        // Switch to asymmetric-key crypto:
        $token->setPurpose('sign')
            ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9UErJWp-gsQiZcJpN_dEfUo3D7OQWBuG6wEjywHpyx1xZd-8KjzDtayi22lfW7gRuKAPf_pxdQE04_X4OulWHCQ==',
            (string) $token,
            'Switching to signing caused a different signature'
        );
    }
}
