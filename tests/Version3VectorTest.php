<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use Mdanter\Ecc\EccFactory;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\ECDSA\PublicKey;
use ParagonIE\EasyECC\ECDSA\SecretKey;
use ParagonIE\Paseto\Keys\Version3\{
    AsymmetricPublicKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\Version3;
use PHPUnit\Framework\TestCase;

/**
 * Class Version3VectorTest
 * @package ParagonIE\Paseto\Tests
 */
class Version3VectorTest extends TestCase
{
    /**
     * @throws \ParagonIE\Paseto\Exception\PasetoException
     * @throws \ParagonIE\Paseto\Exception\SecurityException
     */
    public function testOfficialVectors()
    {
        $symmetricKey = new SymmetricKey(
            Hex::decode(
                '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
            )
        );
        $nonce = str_repeat("\0", 32);
        $nonce2 = Hex::decode('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2');

        $version3Encrypt = NonceFixer::buildUnitTestEncrypt(new Version3)->bindTo(null, new Version3);

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABLt5-kR6TZW6LYCBsWla5Tmn_7cLt0zT1OyRnIPjuAYLA0ZdlHrd_BiMIUzVbI7ma_lO6UNJWYiR2v0joy6WvesFN0kAhnZgpPRQVFEJTK2GSwDbWErD1NbI4MbWgC3djoYw4g0kXuZXY5qbkGWugNzOoTKAI',
            $version3Encrypt($message, $symmetricKey, '', '', $nonce),
            'Test Vector 3-E-1'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABLt5-kR6TZW6LYCBsWla5Tmn_7a7dz2z1UyRnIPjuAYLA0ZdlHrd_BiMIUzVbI7ma_lO6UNJWYiR2v0joy6WvesFN0kAh_A0APZdJXUREr7ZyeXfxgyMiT_F08jZiPxbj2opNIw5u9rJO8Y9eOruTakJng3bc',
            $version3Encrypt($message, $symmetricKey, '', '', $nonce),
            'Test Vector 3-E-2'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0doDkavZyIu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNkvPoevaXFtzOv_tMxxYt_i7afc2avjyDp69TX3lchI-Ed6l7aLMgJvoSzxQZaJuM-E',
            $version3Encrypt($message, $symmetricKey, '', '', $nonce2),
            'Test Vector 3-E-3'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0duzUdq5ySu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNksGsq5I4rtEgvE-WgP9V2p5j-Am6AzMTnYk--x0jGcBFkJWtSRbvh62QEWu1gYxw8E',
            $version3Encrypt($message, $symmetricKey, '', '', $nonce2),
            'Test Vector 3-E-4'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $footer = \json_encode(['kid' => 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0doDkavZyIu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNkuTL6D0bKlatkgbNuYdzL_Ngw8XG9-CfzVF18KL7WFTBaAXuBHJxAaz2ChQZEIOrwM.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
            $version3Encrypt($message, $symmetricKey, $footer, '', $nonce2),
            'Test Vector 3-E-5'
        );
        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $footer = \json_encode(['kid' => 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0duzUdq5ySu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNkvNhmzXOmA4g5FcC1fmqpw5-BrmNDSscZLd-VZEsfofAzzYBltIapOPuOAGDI0sJ8I.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
            $version3Encrypt($message, $symmetricKey, $footer, '', $nonce2),
            'Test Vector 3-E-6'
        );

        $implicit = \json_encode(['test-vector' => '3-E-7']);
        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0doDkavZyIu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNktkR5lvQgZEoo5SUPbSk-dEpEa9GVDgm05bdwI-TLWIIpFKal0igpgJwWNlpkKwo2M.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
            $version3Encrypt($message, $symmetricKey, $footer, $implicit, $nonce2),
            'Test Vector 3-E-7'
        );

        $implicit = \json_encode(['test-vector' => '3-E-8']);
        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0duzUdq5ySu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNksGPtABBONQk8vDq4rCGeXENQ0Tx26j0ymtaZbFGK7upNRyqfEwKKsAt73vAEEZCm8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
            $version3Encrypt($message, $symmetricKey, $footer, $implicit, $nonce2),
            'Test Vector 3-E-8'
        );

        // Nothing Up My Sleeves test vector secret key
        $sk = new SecretKey(
            EccFactory::getAdapter(),
            EasyECC::getGenerator('P384'),
            gmp_init(
                hash('sha384', 'Paragon Initiative Enterprises - PASETO v3.public'),
                16
            )
        );
        $pk = PublicKey::promote($sk->getPublicKey());
        $testPublicKey = '02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb';
        $this->assertSame($testPublicKey, $pk->toString());

        $publicKey = new AsymmetricPublicKey($testPublicKey);

        $message = \json_encode(['data' => 'this is a signed message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $footer = '';
        $this->assertSame(
            $message,
            Version3::verify(
                'v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph',
                $publicKey,
                $footer
            ),
            'Version 3-S-1'
        );

        $footer = '{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}';
        $this->assertSame(
            $message,
            Version3::verify(
                'v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9',
                $publicKey,
                $footer
            ),
            'Version 3-S-2'
        );

        $implicit = \json_encode(['test-vector' => '3-S-3']);
        $this->assertSame(
            $message,
            Version3::verify(
                'v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9',
                $publicKey,
                $footer,
                $implicit
            ),
            'Version 3-S-3'
        );
    }


    /**
     * @throws \TypeError
     * @throws \ParagonIE\Paseto\Exception\SecurityException
     */
    public function testEncrypt()
    {
        $nullKey = new SymmetricKey(\str_repeat("\0", 32));
        $fullKey = new SymmetricKey(\str_repeat("\xff", 32));
        $symmetricKey = new SymmetricKey(
            Hex::decode(
                '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
            )
        );
        $nonce = str_repeat("\0", 32);
        //$nonce2 = hash('sha256', 'Paragon Initiative Enterprises, LLC', true);
        $nonce2 = Hex::decode('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2');

        $version3Encrypt = NonceFixer::buildUnitTestEncrypt(new Version3)->bindTo(null, new Version3);

        // Empty message, empty footer, empty nonce
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnWpZYRRL4N8bww7FJo3bp-irlGWIGX_sj_hk4Zh0a14Pc7u0HZt4stpY1RSIgFDU',
            $version3Encrypt('', $nullKey, '', '', $nonce),
            'Test Vector 3E-1-1'
        );
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABO08Z0hcswGJuuher4sHGlku0CYwIJPipujbTbsOxRUEp5nvmPmL77Hp-MvSZfB04',
            $version3Encrypt('', $fullKey, '', '', $nonce),
            'Test Vector 3E-1-2'
        );
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADGq0FhXG8_06C8PRMYSHTZFPY1PWfDTgW8k9vLrp0ktvKdL3xn64gDE0xssniF0t8',
            $version3Encrypt('', $symmetricKey, '', '', $nonce),
            'Test Vector 3E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADPYJHpDWDsZ7ycOWlUHTpKehONRxcxHlUJ6VMN4LuGcjdSDRcYEdN9hIsw2w1KLNI.Q3VvbiBBbHBpbnVz',
            $version3Encrypt('', $nullKey, 'Cuon Alpinus', '', $nonce),
            'Test Vector 3E-2-1'
        );
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACXju5ZspuuR8g9fcdHyzZHAMHYiM7PeKonRUkVnaInctDb-Mb1sjj9_FZKffuckfs.Q3VvbiBBbHBpbnVz',
            $version3Encrypt('', $fullKey, 'Cuon Alpinus', '', $nonce),
            'Test Vector 3E-2-2'
        );
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACLynXpeVUCYkyt6j4cNpVI4V8pDzSsqSxErrctLc803Fyys58HARGKFWax6DVtFMw.Q3VvbiBBbHBpbnVz',
            $version3Encrypt('', $symmetricKey, 'Cuon Alpinus', '', $nonce),
            'Test Vector 3E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACw3y9IXsH8i3bQb6cY3G_SdugbhzfODFWQNp8KBpjQ-9578yAMJmp4hPDFf6n9gQxA5fqv511LmahVhAi6MS7Ks6YJcfc66DpIltKxiG3LJizk',
            $version3Encrypt('Love is stronger than hate or fear', $nullKey, '', '', $nonce),
            'Test Vector 3E-3-1'
        );
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACFk75aa12GzK18ZDCCRfcmliEwDhnJ6Ic9v9Z5bv-AL8Ehvt4wWaaf8izz-2XmHKXLnmdDBM9AQcss_58o29aibFBA-AxJ_qo9fZlLQ4eSU95u',
            $version3Encrypt('Love is stronger than hate or fear', $fullKey, '', '', $nonce),
            'Test Vector 3E-3-2'
        );
        $this->assertSame(
            'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB8-o2gE6yIQfPYEh0L0qJSmmqzYrA31zlOjFTCP2iHYrRk0Sx-QnIgfQwzzhWRrRKlw24mzUGKcYE3rSJBZmsKwuUpf7NhEZprB8_OhA1lSXzH',
            $version3Encrypt('Love is stronger than hate or fear', $symmetricKey, '', '', $nonce),
            'Test Vector 3E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_IHgJWW_vj__ghDpoo7u5pj9xh8TwpQUFjJSLTjZEbuW11GNClJZEc4WrH_NJvlXzkiuaar_9uMTtYGZLBkuP7cXvm_rF8gOFBCIgKqsvmlh37z.Q3VvbiBBbHBpbnVz',
            $version3Encrypt('Love is stronger than hate or fear', $nullKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 3E-4-1'
        );
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_I_P7_GAMGs4ZeISGJNCHrYXxkqxmqp5DWlrIGsW6EAjVcptbTOAffzr3N35cpo0Gy5Con7gUwV-Xr2gaXRhlpxrqfGOW-zvmuxCyZqm13ilLjh.Q3VvbiBBbHBpbnVz',
            $version3Encrypt('Love is stronger than hate or fear', $fullKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 3E-4-2'
        );
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_KtzPozdijUoqtx8ek5XzFTdFhVsjJZp5iI_s3UNg_t9n8UCDvg_jdQwCBcVpUD7rxQ0EAhBhRxxBpp2PDsjfLo_98HL2xLbItyBYK6JSAcufIj.Q3VvbiBBbHBpbnVz',
            $version3Encrypt('Love is stronger than hate or fear', $symmetricKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 3E-4-3'
        );

        $message = \json_encode(['data' => 'this is a sealed message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $footer = \json_encode(['kid' => 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0doDkYo5yYu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNkscHuaJ1d7Wdtz3xsnTaEouVAy5uAdRgiAPxNMTd1vHvaf8UFuVbA6wMD_0dJ8M-9k.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
            $version3Encrypt($message, $symmetricKey, $footer, '', $nonce2),
            'Test Vector 3E-5-1'
        );
        $implicit = \json_encode(['test-vector' => '3E-6-1']);
        $this->assertSame(
            'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_Kageg3IiCFuPpx6-8kGD1SdE0doDkYo5yYu4DeN1zq9HtEhw4IU0o_kdeWV-J_U7rJinQ5eCsyDoeGDlyRBoJ5cz3hNktZfN6xmSe13LGlsoK6hR4z1_gUoo3Q1pnz5rCaV0jvZUtSrFAxX9xjD1HkNcqx7lY.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
            $version3Encrypt($message, $symmetricKey, $footer, $implicit, $nonce2),
            'Test Vector 3E-6-1'
        );
    }
}
