<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\PAST\Protocol\Version1;
use PHPUnit\Framework\TestCase;

/**
 * Class Version1VectorTest
 *
 * Contains test vectors for building compatible implementations in other languages.
 *
 * @package ParagonIE\PAST\Tests
 */
class Version1VectorTest extends TestCase
{
    /**
     * @covers Version1::auth()
     */
    public function testAuthVectors()
    {
        $nullAuthKey = new SymmetricAuthenticationKey(\str_repeat("\0", 32));
        $fullAuthKey = new SymmetricAuthenticationKey(\str_repeat("\xff", 32));

        // Empty string, 32-character NUL byte key.
        $this->assertSame(
            'v1.auth.6n6C7vHPzV5xHULfMOjiLg7F46iPeymVwawZN5kF3B-OyhzPsjqAOLYhtCc52-Wt',
            Version1::auth('', $nullAuthKey),
            'Test Vector A-1'
        );

        // Empty string, 32-character NUL byte key, non-empty footer.
        $this->assertSame(
            'v1.auth.JEEQ-GXQAK2qNYilKVXynuLhlXUw8xdeHNhsBH8OMA6mS_sYMzavZ_kUrdMgmNKr.Q3VvbiBBbHBpbnVz',
            Version1::auth('', $nullAuthKey, 'Cuon Alpinus'),
            'Test Vector A-2'
        );

        // Non-empty string, 32-character 0xFF byte key.
        $this->assertSame(
            'v1.auth.RnJhbmsgRGVuaXMgcm9ja3OvktwlGNM0U3P2mAbLVKRcHWC33xXQwVN-IlE8M3idKitswqz33kA5q2ThfOT4uqU',
            Version1::auth('Frank Denis rocks', $fullAuthKey),
            'Test Vector A-3'
        );

        // Non-empty string, 32-character 0xFF byte key. (One character difference)
        $this->assertSame(
            'v1.auth.RnJhbmsgRGVuaXMgcm9ja3qoKuUpOSkEDafLOA9FDz8zYCX18f6ILDXjbgOwxsfD_HxRo6Jnz5xFN236X_1IdrQ',
            Version1::auth('Frank Denis rockz', $fullAuthKey),
            'Test Vector A-4'
        );

        // Non-empty string, 32-character 0xFF byte key, non-empty footer.
        $this->assertSame(
            'v1.auth.RnJhbmsgRGVuaXMgcm9ja3N_vl77CqDA-VdqmjEs6ugayZRK7Fl20OviMWGefxRDbeMtNsuhosEfDU0CeJPodSM.Q3VvbiBBbHBpbnVz',
            Version1::auth('Frank Denis rocks', $fullAuthKey, 'Cuon Alpinus'),
            'Test Vector A-5'
        );
    }
}
