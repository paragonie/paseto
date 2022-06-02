<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\{
    Builder,
    Exception\PasetoException,
    JsonToken,
    Purpose
};
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use PHPUnit\Framework\TestCase;

/**
 * Class JsonTokenTest
 * @package ParagonIE\Paseto\Tests
 */
class JsonTokenTest extends TestCase
{
    /**
     * @covers Builder::getToken()
     * @throws PasetoException
     * @throws \Exception
     * @throws \ParagonIE\Paseto\Exception\InvalidKeyException
     * @throws \ParagonIE\Paseto\Exception\InvalidPurposeException
     * @throws \TypeError
     */
    public function testAuthDeterminism()
    {
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');
        $builder = (new Builder())
            ->setPurpose(Purpose::local())
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'));

        NonceFixer::buildSetExplicitNonce()->bindTo($builder, $builder)($nonce);

        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGb6hs4MANpkKEzSOVPaHQVrE_TyDA7Pe37zn1qQykJeCi6_WZVov-PkRU5F6ANACIZKUXgzN9gucaifEsf4TFPuDoiz_k0PwaUM222jY1TPwYUHvx50GN4veVKo-aFbctcZjqg6MA',
            (string) $builder,
            'Auth, no footer'
        );
        $footer = (string) \json_encode(['key-id' => 'gandalf0']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGb6hs4MANpkKEzSOVPaHQVrE_TyDA7Pe37zn1qQykJeCi6_WZVov-PkRU5F6ANACIZKUXgzN9gucaifEsf4TFPuDoiz_k0AMr750FXTBgsZercGCHkWLxy62xRbZTIHlIGaxDekO4.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Auth, footer'
        );
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGb6hs4MANpkKEzSOVPaHQVrE_TyDA7Pe37zn1qQykJeCi6_WZVov-PkRU5F6ANACIZKUXgzN9gucaifEsf4TFPuDoiz_k0PwaUM222jY1TPwYUHvx50GN4veVKo-aFbctcZjqg6MA',
            (string) $builder->setFooter(''),
            'Auth, removed footer'
        );

        // Now let's switch gears to asymmetric crypto:
        $builder->setPurpose(Purpose::public())
                ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9_LCndxFrGmFDZbUAgixuWRPZv7J67DA6AT69KfJU2APR8J-APE1RxlKrdFyumd2h_GjcU4tdNgHlgZpuKf3BCQ',
            (string) $builder,
            'Sign, no footer'
        );
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9GZ1yMhB9oF0coCoSXk6K2lPkbFwPbXuLAXw3j0_ZXOdTWUM8Y1sjOUFjJHOQo6PLMAqfldyiC7G1XJEEbuvrAg.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Sign, footer'
        );
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9_LCndxFrGmFDZbUAgixuWRPZv7J67DA6AT69KfJU2APR8J-APE1RxlKrdFyumd2h_GjcU4tdNgHlgZpuKf3BCQ',
            (string) $builder->setFooter(''),
            'Sign, removed footer'
        );
    }

    /**
     * @covers JsonToken::with()
     * @throws PasetoException
     */
    public function testWith()
    {
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');
        $footerArray = ['key-id' => 'gandalf0'];

        $builder = (new Builder())
            ->setPurpose(Purpose::local())
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'))
            ->setFooterArray($footerArray);

        NonceFixer::buildSetExplicitNonce()->bindTo($builder, $builder)($nonce);

        $first = (string) $builder;
        $alt = $builder->with('data', 'this is a different message');
        $second = (string) $alt;
        $third = (string) $builder;

        $this->assertSame($first, $third);
        $this->assertNotSame($first, $second);
        $this->assertNotSame($second, $third);

        $mutated = $builder->withAudience('example.com');
        $mutateTwo = $mutated->withAudience('example.org');

        $this->assertNotSame(
            $mutated->getJsonToken()->getAudience(),
            $mutateTwo->getJsonToken()->getAudience()
        );
    }

    /**
     * @throws PasetoException
     */
    public function testSetClaims()
    {
        $token = new JsonToken();

        $token->setExpiration(new \DateTime());
        $token->setClaims([
            'test' => 'foo'
        ]);

        $this->assertInstanceOf(
            \DateTime::class,
            $token->getExpiration()
        );
        $this->assertSame('foo', $token->get('test'));
    }

    /**
     * @throws PasetoException
     */
    public function testAuthTokenCustomFooter()
    {
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');
        $footerArray = ['key-id' => 'gandalf0'];
        $builder = (new Builder())
            ->setPurpose(Purpose::local())
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'))
            ->setFooterArray($footerArray);

        NonceFixer::buildSetExplicitNonce()->bindTo($builder, $builder)($nonce);

        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGb6hs4MANpkKEzSOVPaHQVrE_TyDA7Pe37zn1qQykJeCi6_WZVov-PkRU5F6ANACIZKUXgzN9gucaifEsf4TFPuDoiz_k0AMr750FXTBgsZercGCHkWLxy62xRbZTIHlIGaxDekO4.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder,
            'Auth, footer'
        );
        $this->assertSame(
            $footerArray,
            $builder->getFooterArray()
        );
    }
}
