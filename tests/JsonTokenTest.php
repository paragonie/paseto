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
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9tDsPOV3V0FyU3p2whkyGrjnvl9ViUooDjfBkRg7AUn8=',
            (string) $builder,
            'Auth, no footer'
        );
        $footer = (string) \json_encode(['key-id' => 'gandalf0']);
        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9eRS5hqdrfbWwGba6CieXQ7Z5_YUPg2lD66W9DsHlkzs=.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Auth, footer'
        );
        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9tDsPOV3V0FyU3p2whkyGrjnvl9ViUooDjfBkRg7AUn8=',
            (string) $builder->setFooter(''),
            'Auth, removed footer'
        );

        // Now let's switch gears to asymmetric crypto:
        $builder->setPurpose('sign')
                ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9GS-ZKUvi69Ye9R4PL5S5I1Sii1K6t9GDrWGnOalp_yuh35rcssWYhUSaSzmJ6XknXmIlCDje-y6TXxu6LOefDQ==',
            (string) $builder,
            'Sign, no footer'
        );
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9s-ypX1ibvpvi4y50xVOWH_0dZXkCzNP-jUzJbyr0ahiPz0wiOxwm2w2FvCv_Y5byVzmTJvpLUa8OmJGHe-JcAQ==.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Sign, footer'
        );
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9GS-ZKUvi69Ye9R4PL5S5I1Sii1K6t9GDrWGnOalp_yuh35rcssWYhUSaSzmJ6XknXmIlCDje-y6TXxu6LOefDQ==',
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
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9eRS5hqdrfbWwGba6CieXQ7Z5_YUPg2lD66W9DsHlkzs=.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder,
            'Auth, footer'
        );
        $this->assertEquals(
            $footerArray,
            $builder->getFooterArray()
        );
    }
}
