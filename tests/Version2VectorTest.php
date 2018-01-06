<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\PAST\Keys\AsymmetricPublicKey;
use ParagonIE\PAST\Keys\AsymmetricSecretKey;
use ParagonIE\PAST\Keys\SymmetricKey;
use ParagonIE\PAST\Protocol\Version2;
use PHPUnit\Framework\TestCase;
use function Sodium\crypto_generichash;

/**
 * Class Version2VectorTest
 *
 * Contains test vectors for building compatible implementations in other languages.
 *
 * @package ParagonIE\PAST\Tests
 */
class Version2VectorTest extends TestCase
{
    /** @var SymmetricKey */
    protected $fullKey;
    /** @var SymmetricKey */

    protected $nullKey;

    /** @var AsymmetricSecretKey */
    protected $privateKey;

    /** @var AsymmetricSecretKey */
    protected $publicKey;

    /** @var SymmetricKey */
    protected $symmetricKey;

    /**
     * This just sets up two asymmetric keys, generated once
     * upon a time, to facilitate the standard test vectors.
     *
     * DO NOT USE THESE KEYS EVER FOR ANY PURPOSE OTHER THAN
     * VERIFYING THE PROVIDED TEST VECTORS FOR VERSION 2.
     */
    public function setUp()
    {
        $this->symmetricKey = new SymmetricKey(
            Hex::decode(
                '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
            )
        );
        $this->nullKey = new SymmetricKey(\str_repeat("\0", 32));
        $this->fullKey = new SymmetricKey(\str_repeat("\xff", 32));

        $this->privateKey = new AsymmetricSecretKey(
            Hex::decode(
                'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774' .
                '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'
            ),
            Version2::HEADER
        );

        $this->publicKey = new AsymmetricPublicKey(
            Hex::decode(
                '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'
            ),
            Version2::HEADER
        );
    }

    /**
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testEncrypt()
    {
        $nonce = str_repeat("\0", 24);
        // $nonce2 = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce2 = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');

        // Empty message, empty footer, empty nonce
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8nUfSPYW3qhCbMdndcgghw',
            Version2::encrypt('', $this->nullKey, '', $nonce),
            'Test Vector 2E-1-1'
        );
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATcNxU2Kfscz9HMSeRxSGng',
            Version2::encrypt('', $this->fullKey, '', $nonce),
            'Test Vector 2E-1-2'
        );
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAV1u2CMi5yQsIfxOu82zz2Q',
            Version2::encrypt('', $this->symmetricKey, '', $nonce),
            'Test Vector 2E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAb2Uo17v-1PTwI1hxEpdjlQ.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('', $this->nullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 2E-2-1'
        );
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEcVxT7kXPsURYvjorFG-8g.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('', $this->fullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 2E-2-2'
        );
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEWzCGD8yh5GlCNN5OF_V8Q.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('', $this->symmetricKey, 'Cuon Alpinus', $nonce),
            'Test Vector 2E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANPHg7MVJ_l-qlYGq21N6Os9syV8vqfDMrri3zBsa_hrv8DMgZQ022_ztdIh6CnoZ7jY',
            Version2::encrypt('Love is stronger than hate or fear', $this->nullKey, '', $nonce),
            'Test Vector 2E-3-1'
        );
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwd-DjyBeoOKahcthIBMhlrirZYzQHBPnVUG2EjqlVNIovDOi2pTU_yFfyxYCJZ834Dc',
            Version2::encrypt('Love is stronger than hate or fear', $this->fullKey, '', $nonce),
            'Test Vector 2E-3-2'
        );
        $this->assertSame(
            'v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhSMBt_gIsjBPup1V1H3G_wjwnaLZgXxM4MVFLgvOCutFcvjymg7Ir2CcF0c8vB3dII8',
            Version2::encrypt('Love is stronger than hate or fear', $this->symmetricKey, '', $nonce),
            'Test Vector 2E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v2.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbRA5L610X9nVzdTMNRIrkpMjQ2UUP5Xi7vqOKWcQz9Bv3uRo_lBDUShbrkog5mtkf0Vs.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('Love is stronger than hate or fear', $this->nullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 2E-4-1'
        );
        $this->assertSame(
            'v2.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGb-pLK-oBK_b14xcdkl8bEkDgIwXB8AGr8lSbutuLuuczU2DdK_cjYGbXw5ja0jNRQzgo.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('Love is stronger than hate or fear', $this->fullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 2E-4-2'
        );
        $this->assertSame(
            'v2.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbjgPFTyS8RFUJ7bnJm1BbcwJ-zJ5PjjvwtGd9Ro-VFwcy2j1-zzEtfeMzLZ7RxQO84v0.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('Love is stronger than hate or fear', $this->symmetricKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 2E-4-3'
        );
    }

    /**
     * @covers Version2::sign()
     */
    public function testSignVectors()
    {
        // Empty string, 32-character NUL byte key.
        $this->assertSame(
            'v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA',
            Version2::sign('', $this->privateKey),
            'Test Vector S-1'
        );

        // Empty string, 32-character NUL byte key, non-empty footer.
        $this->assertSame(
            'v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz',
            Version2::sign('', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector S-2'
        );

        // Non-empty string, 32-character 0xFF byte key.
        $this->assertSame(
            'v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM',
            Version2::sign('Frank Denis rocks', $this->privateKey),
            'Test Vector S-3'
        );

        // Non-empty string, 32-character 0xFF byte key. (One character difference)
        $this->assertSame(
            'v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML',
            Version2::sign('Frank Denis rockz', $this->privateKey),
            'Test Vector S-4'
        );

        // Non-empty string, 32-character 0xFF byte key, non-empty footer.
        $this->assertSame(
            'v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz',
            Version2::sign('Frank Denis rocks', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector S-5'
        );
    }
}
