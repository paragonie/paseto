<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\PAST\JsonToken;
use ParagonIE\PAST\Exception\PastException;
use ParagonIE\PAST\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
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
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');
        $builder = (new JsonToken())
            ->setPurpose('local')
            ->setExplicitNonce($nonce)
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'));

        $this->assertSame(
            'v2.local.3fNxan9FHjedQRSONRnT7Ce_KhhpB0NrlHwAGsCb54x0FhrjBfeNN4uPHFiO5H0iPCZSjwfEkkfiGeYpE6KAfr1Zm3G-VTe4lcXtgDyKATYULT-zLPfshRqisk4n7EbGufWuqilYvYXMCiYbaA',
            (string) $builder,
            'Auth, no footer'
        );
        $footer = (string) \json_encode(['key-id' => 'gandalf0']);
        $this->assertSame(
            'v2.local.3fNxan9FHjedQRSONRnT7Ce_KhhpB0NrlHwAGsCb54x0FhrjBfeNN4uPHFiO5H0iPCZSjwfEkkfiGeYpE6KAfr1Zm3G-VTe4lcXtgDyKATYULT-zLPfshRqisk4nZ9JDgBVa-L9vW26CMc57aw.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Auth, footer'
        );
        $this->assertSame(
            'v2.local.3fNxan9FHjedQRSONRnT7Ce_KhhpB0NrlHwAGsCb54x0FhrjBfeNN4uPHFiO5H0iPCZSjwfEkkfiGeYpE6KAfr1Zm3G-VTe4lcXtgDyKATYULT-zLPfshRqisk4n7EbGufWuqilYvYXMCiYbaA',
            (string) $builder->setFooter(''),
            'Auth, removed footer'
        );

        // Now let's switch gears to asymmetric crypto:
        $builder->setPurpose('public')
                ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9BAOu3lUQMVHnBcPSkuORw51yiGGQ3QFUMoJO9U0gRAdAOPQEZFsd0YM_GZuBcmrXEOD1Re-Ila8vfPrfM5S6Ag',
            (string) $builder,
            'Sign, no footer'
        );
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9Hzr4d37ny_OVLHxKACtO3tgVACqE2VHMR0InSWhaVC8-aw-Po1oVtPUeMoLUzPTr3qRQiuzl44WTGR8nfGiQBw.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder->setFooter($footer),
            'Sign, footer'
        );
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9BAOu3lUQMVHnBcPSkuORw51yiGGQ3QFUMoJO9U0gRAdAOPQEZFsd0YM_GZuBcmrXEOD1Re-Ila8vfPrfM5S6Ag',
            (string) $builder->setFooter(''),
            'Sign, removed footer'
        );
    }

    /**
     * @covers JsonToken::with()
     * @throws PastException
     */
    public function testWith()
    {
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');
        $footerArray = ['key-id' => 'gandalf0'];

        $token = (new JsonToken())
            ->setPurpose('local')
            ->setExplicitNonce($nonce)
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'))
            ->setFooterArray($footerArray);

        $first = (string) $token;
        $alt = $token->with('data', 'this is a different message');
        $second = (string) $alt;
        $third = (string) $token;

        $this->assertSame($first, $third);
        $this->assertNotSame($first, $second);
        $this->assertNotSame($second, $third);

        $mutated = $token->withAudience('example.com');
        $mutateTwo = $mutated->withAudience('example.org');

        $this->assertNotSame(
            $mutated->getAudience(),
            $mutateTwo->getAudience()
        );
    }

    /**
     * @throws PastException
     */
    public function testAuthTokenCustomFooter()
    {
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');
        $footerArray = ['key-id' => 'gandalf0'];
        $builder = (new JsonToken())
            ->setPurpose('local')
            ->setExplicitNonce($nonce)
            ->setKey($key)
            ->set('data', 'this is a signed message')
            ->setExpiration(new \DateTime('2039-01-01T00:00:00+00:00'))
            ->setFooterArray($footerArray);
        $this->assertSame(
            'v2.local.3fNxan9FHjedQRSONRnT7Ce_KhhpB0NrlHwAGsCb54x0FhrjBfeNN4uPHFiO5H0iPCZSjwfEkkfiGeYpE6KAfr1Zm3G-VTe4lcXtgDyKATYULT-zLPfshRqisk4nZ9JDgBVa-L9vW26CMc57aw.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            (string) $builder,
            'Auth, footer'
        );
        $this->assertSame(
            $footerArray,
            $builder->getFooterArray()
        );
    }
}
