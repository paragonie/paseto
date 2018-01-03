<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\PAST\JsonToken;
use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\Keys\{
    AsymmetricSecretKey,
    SymmetricAuthenticationKey
};
use PHPUnit\Framework\TestCase;

/**
 * Class JsonTokenTest
 * @package ParagonIE\PAST\Tests
 */
class JsonTokenTest extends TestCase
{
    /**
     * @covers Builder::getToken()
     * @throws PastException
     */
    public function testAuthDeterminism()
    {
        $key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $builder = (new JsonToken())
            ->setPurpose('auth')
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'));

        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ93f3nsnVwKRNLECMSi0_vhOUzXLj62UvCfPBGx4Nva9M=',
            (string) $builder,
            'Auth, no footer'
        );
        $footer = (string) \json_encode(['key-id' => 'gandalf0']);
        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9V5lr8_gYa6yH3ZAKMcqnv_Deuow7TPCMtGBPLC6ZVbU=.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Auth, footer'
        );
        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ93f3nsnVwKRNLECMSi0_vhOUzXLj62UvCfPBGx4Nva9M=',
            (string) $builder->setFooter(''),
            'Auth, removed footer'
        );

        // Now let's switch gears to asymmetric crypto:
        $builder->setPurpose('sign')
                ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HUL-xbk0NkbdgAkFVt75Cm2N01fb30V79xSMrCnkAha2iS3cqc-cJnTEyRiD5hazSXqwU3gV4QsZw2AEgFy2Dw==',
            (string) $builder,
            'Sign, no footer'
        );
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9VJyhiHv4L-EalZB4FVqBPmfx5MlgZg305gJT1dUULR8ll_tFYIX8OmFt_ZZmn1bYrkJ9Mla24cz4_trbwAyGDA==.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Sign, footer'
        );
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HUL-xbk0NkbdgAkFVt75Cm2N01fb30V79xSMrCnkAha2iS3cqc-cJnTEyRiD5hazSXqwU3gV4QsZw2AEgFy2Dw==',
            (string) $builder->setFooter(''),
            'Sign, removed footer'
        );
    }

    /**
     * @throws PastException
     */
    public function testAuthTokenCustomFooter()
    {
        $key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $footerArray = ['key-id' => 'gandalf0'];
        $builder = (new JsonToken())
            ->setPurpose('auth')
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'))
            ->setFooterArray($footerArray);
        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9V5lr8_gYa6yH3ZAKMcqnv_Deuow7TPCMtGBPLC6ZVbU=.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder,
            'Auth, footer'
        );
        $this->assertEquals(
            $footerArray,
            $builder->getFooterArray()
        );
    }
}
