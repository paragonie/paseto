<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\PAST\Builder;
use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\Keys\{
    AsymmetricSecretKey,
    SymmetricAuthenticationKey
};
use PHPUnit\Framework\TestCase;

/**
 * Class BuilderTest
 * @package ParagonIE\PAST\Tests
 */
class BuilderTest extends TestCase
{
    /**
     * @covers Builder::getToken()
     * @throws PastException
     */
    public function testAuthDeterminism()
    {
        $key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $builder = (new Builder())
            ->setPurpose('auth')
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'));

        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9pBzDGiV6cmCX8Wxuj09xmNYiVOcD9yuE0TntviAEWvs=',
            (string) $builder->getToken(),
            'Auth, no footer'
        );
        $footer = (string) \json_encode(['key-id' => 'gandalf0']);
        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9X7CSuUFMklmXhHsu4bXvx_wiH_OyxpMijfNCjHiklXk=.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer)->getToken(),
            'Auth, footer'
        );
        $this->assertSame(
            'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9pBzDGiV6cmCX8Wxuj09xmNYiVOcD9yuE0TntviAEWvs=',
            (string) $builder->setFooter('')->getToken(),
            'Auth, removed footer'
        );

        // Now let's switch gears to asymmetric crypto:
        $builder->setPurpose('sign')
                ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9J_YYSKaRss60fvAT5jR0KzGXRrgAT9hSPbJ8O5w1F_EgTTU4Zbjms_ngcM_gEtUlvDIFs1QFv3GWkU4Ya6z9CQ==',
            (string) $builder->getToken(),
            'Sign, no footer'
        );
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ97mfQNGcQvr0ygbUO4XwAgTtb0NDlSLQpbG0hQRIr1JAo3XwUIq1HgSy84iA1h5fds-ZqwFkn1baN0WapHLwIAQ==.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer)->getToken(),
            'Sign, footer'
        );
        $this->assertSame(
            'v2.sign.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9J_YYSKaRss60fvAT5jR0KzGXRrgAT9hSPbJ8O5w1F_EgTTU4Zbjms_ngcM_gEtUlvDIFs1QFv3GWkU4Ya6z9CQ==',
            (string) $builder->setFooter('')->getToken(),
            'Sign, removed footer'
        );
    }
}
