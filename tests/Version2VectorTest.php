<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version2;
use PHPUnit\Framework\TestCase;

/**
 * Class Version2VectorTest
 *
 * Contains test vectors for building compatible implementations in other languages.
 *
 * @package ParagonIE\Paseto\Tests
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
            new Version2
        );

        $this->publicKey = new AsymmetricPublicKey(
            Hex::decode(
                '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'
            ),
            new Version2
        );
    }

    /**
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testEncrypt()
    {
        $nonce = str_repeat("\0", 24);
        // $nonce2 = sodium_crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce2 = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');

        // Empty message, empty footer, empty nonce
        $this->assertSame(
            'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ',
            Version2::encrypt('', $this->nullKey, '', $nonce),
            'Test Vector 2E-1-1'
        );
        $this->assertSame(
            'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg',
            Version2::encrypt('', $this->fullKey, '', $nonce),
            'Test Vector 2E-1-2'
        );
        $this->assertSame(
            'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA',
            Version2::encrypt('', $this->symmetricKey, '', $nonce),
            'Test Vector 2E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('', $this->nullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 2E-2-1'
        );
        $this->assertSame(
            'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('', $this->fullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 2E-2-2'
        );
        $this->assertSame(
            'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('', $this->symmetricKey, 'Cuon Alpinus', $nonce),
            'Test Vector 2E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0',
            Version2::encrypt('Love is stronger than hate or fear', $this->nullKey, '', $nonce),
            'Test Vector 2E-3-1'
        );
        $this->assertSame(
            'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw',
            Version2::encrypt('Love is stronger than hate or fear', $this->fullKey, '', $nonce),
            'Test Vector 2E-3-2'
        );
        $this->assertSame(
            'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U',
            Version2::encrypt('Love is stronger than hate or fear', $this->symmetricKey, '', $nonce),
            'Test Vector 2E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('Love is stronger than hate or fear', $this->nullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 2E-4-1'
        );
        $this->assertSame(
            'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('Love is stronger than hate or fear', $this->fullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 2E-4-2'
        );
        $this->assertSame(
            'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz',
            Version2::encrypt('Love is stronger than hate or fear', $this->symmetricKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 2E-4-3'
        );

        $message = \json_encode(['data' => 'this is a signed message', 'expires' => '2019-01-01T00:00:00+00:00']);
        $footer = 'Paragon Initiative Enterprises';
        $this->assertSame(
            'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
            Version2::encrypt($message, $this->symmetricKey, $footer, $nonce2),
            'Test Vector 2E-5'
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

        $message = \json_encode(['data' => 'this is a signed message', 'expires' => '2019-01-01T00:00:00+00:00']);
        $footer = 'Paragon Initiative Enterprises';
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI',
            Version2::sign($message, $this->privateKey),
            'Test Vector S-6'
        );
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
            Version2::sign($message, $this->privateKey, $footer),
            'Test Vector S-6'
        );
    }
}
