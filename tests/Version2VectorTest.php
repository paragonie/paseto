<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\PAST\Keys\AsymmetricPublicKey;
use ParagonIE\PAST\Keys\AsymmetricSecretKey;
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\PAST\Protocol\Version2;
use PHPUnit\Framework\TestCase;

/**
 * Class Version2VectorTest
 *
 * Contains test vectors for building compatible implementations in other languages.
 *
 * @package ParagonIE\PAST\Tests
 */
class Version2VectorTest extends TestCase
{
    /** @var AsymmetricSecretKey */
    protected $privateKey;

    /** @var AsymmetricSecretKey */
    protected $publicKey;

    /**
     * This just sets up two asymmetric keys, generated once
     * upon a time, to facilitate the standard test vectors.
     *
     * DO NOT USE THESE KEYS EVER FOR ANY PURPOSE OTHER THAN
     * VERIFYING THE PROVIDED TEST VECTORS FOR VERSION 2.
     */
    public function setUp()
    {
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
     * @covers Version2::auth()
     */
    public function testAuthVectors()
    {
        $nullAuthKey = new SymmetricAuthenticationKey(\str_repeat("\0", 32));
        $fullAuthKey = new SymmetricAuthenticationKey(\str_repeat("\xff", 32));

        // Empty string, 32-character NUL byte key.
        $this->assertSame(
            'v2.auth.xnXx4GERjFlWU-nLJO-UJlQ7XKU74mOvBV-u5UymqKg=',
            Version2::auth('', $nullAuthKey),
            'Test Vector A-1'
        );

        // Empty string, 32-character NUL byte key, non-empty footer.
        $this->assertSame(
            'v2.auth.s9S77tR3hP7KgflCquKbYPPQlsOJrquQgGrU4za-jog=.Q3VvbiBBbHBpbnVz',
            Version2::auth('', $nullAuthKey, 'Cuon Alpinus'),
            'Test Vector A-2'
        );

        // Non-empty string, 32-character 0xFF byte key.
        $this->assertSame(
            'v2.auth.RnJhbmsgRGVuaXMgcm9ja3OlPWwML5vX9jz8eWMxZY0J6pvcheSEXJl4cWaGzyGQ6w==',
            Version2::auth('Frank Denis rocks', $fullAuthKey),
            'Test Vector A-3'
        );

        // Non-empty string, 32-character 0xFF byte key. (One character difference)
        $this->assertSame(
            'v2.auth.RnJhbmsgRGVuaXMgcm9ja3qtXffI1R5G4KJuLWjKmF6L84REbNNOtcsqr-3z7zfxyw==',
            Version2::auth('Frank Denis rockz', $fullAuthKey),
            'Test Vector A-4'
        );

        // Non-empty string, 32-character 0xFF byte key, non-empty footer.
        $this->assertSame(
            'v2.auth.RnJhbmsgRGVuaXMgcm9ja3N0ncPqYRX7SWTwgwS_MK65vnFPVHq_ciVqpO8MvlZiaA==.Q3VvbiBBbHBpbnVz',
            Version2::auth('Frank Denis rocks', $fullAuthKey, 'Cuon Alpinus'),
            'Test Vector A-5'
        );
    }

    /**
     * @covers Version2::sign()
     */
    public function testSignVectors()
    {
        // Empty string, 32-character NUL byte key.
        $this->assertSame(
            'v2.sign.uSe9owhGweXNMjH2NrUQNuUqLa8WB7i49txhXYESYOyuPyvUwczk12uSIgH1ju9esybqXIY13tRUv3KIMXGdCg==',
            Version2::sign('', $this->privateKey),
            'Test Vector S-1'
        );

        // Empty string, 32-character NUL byte key, non-empty footer.
        $this->assertSame(
            'v2.sign.rvZMDKWEur7JGgrJ4p6d5S4ymHunVg80ymzl8Gi9eCM3ZDlqBht-1koKxdyW834xm4JdXcqu9v6gUetNyBGmDA==.Q3VvbiBBbHBpbnVz',
            Version2::sign('', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector S-2'
        );

        // Non-empty string, 32-character 0xFF byte key.
        $this->assertSame(
            'v2.sign.RnJhbmsgRGVuaXMgcm9ja3OCetrstPDcM-eMqEbbPiRplvLiLMB-RzJfgFeNrm_aQVX3AIrdGdREPL4RwlQ-HckuiAbcad22Pc_sMUTe5dwF',
            Version2::sign('Frank Denis rocks', $this->privateKey),
            'Test Vector S-3'
        );

        // Non-empty string, 32-character 0xFF byte key. (One character difference)
        $this->assertSame(
            'v2.sign.RnJhbmsgRGVuaXMgcm9ja3olt14-8N5T7RKW6XeXvKzEUaeS2GMoevR8mH8xblc076eESVZx0sHGSJUsAJ9TAIEYa0DKxToOj6B_lCKPclsP',
            Version2::sign('Frank Denis rockz', $this->privateKey),
            'Test Vector S-4'
        );

        // Non-empty string, 32-character 0xFF byte key, non-empty footer.
        $this->assertSame(
            'v2.sign.RnJhbmsgRGVuaXMgcm9ja3OyFOsrobYVbyj3IWticlQ8ueEB0tGQA820l6pUzhzy6s0By0WABq4jcdwiNX_xFUx3DMqKHrMEUXSbH9Lgp0EK.Q3VvbiBBbHBpbnVz',
            Version2::sign('Frank Denis rocks', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector S-5'
        );
    }
}
