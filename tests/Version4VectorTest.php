<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;
use PHPUnit\Framework\TestCase;

/**
 * Class Version4VectorTest
 *
 * Contains test vectors for building compatible implementations in other languages.
 *
 * @package ParagonIE\Paseto\Tests
 */
class Version4VectorTest extends TestCase
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

    private $beforeCalled = false;

    /**
     * This just sets up two asymmetric keys, generated once
     * upon a time, to facilitate the standard test vectors.
     *
     * DO NOT USE THESE KEYS EVER FOR ANY PURPOSE OTHER THAN
     * VERIFYING THE PROVIDED TEST VECTORS FOR VERSION 2.
     *
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     * @before
     */
    public function before()
    {
        if ($this->beforeCalled) {
            return;
        }
        $this->beforeCalled = true;
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
            new Version4
        );

        $this->publicKey = new AsymmetricPublicKey(
            Hex::decode(
                '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'
            ),
            new Version4
        );
    }

    /**
     * @throws PasetoException
     */
    public function testOfficialVectors()
    {
        $nonce = str_repeat("\0", 24);
        // $nonce2 = sodium_crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce2 = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');

        $version4Encrypt = NonceFixer::buildUnitTestEncrypt(new Version4)->bindTo(null, new Version4);

        $footer = '';

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACbDT5rQo5rjKqw1OBPe4PlZGsFkZNGtE65uYNNa1yOy4cgCbG2VMPAcgFV9pIJ_zhzsVOpnQ8kcTeR52K6ADBbQ_2uzB4VxjCO5fA5jJPq0j8AT0QDxD1K39HpXRK0t_H0kEFX8',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce),
            'Test Vector 4-E-1'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACbDT5rQo5rjKqw1OBPe4PlZGsEIVM31E8ZuYNNa1yOy4cgCbG2VMPAcgFV9pIJ_zhzsVOpnQ8kcTeR52K6ADBbQ_2uzBjVReST9h8K8N26lW0Qef7KEiFwLSpLWX2lGdILYYhJ8',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce),
            'Test Vector 4-E-2'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyziBNj1lBM5SbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgb488ZNd_TuBR2W9yB8bhY9bwitXvm4tP6Wo-_5CKnuNc',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-3'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyzjtBiE9BKZSbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgbrVP9nVUkkqqn4eDTyHkWzwlLoYqjx379Skif_t1EteU',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-4'
        );

        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyziBNj1lBM5SbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgblnLvSBF-SG1TUd5e5td_IO7428haPSaduYMSQxAnekE.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-5'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyzjtBiE9BKZSbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgb0dh6JW1LdjXnk6GRCBzoMH63Yy_RO76BDp0dlZuHk3Q.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-6'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $implicit = \json_encode(['test-vector' => '4-E-7']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyziBNj1lBM5SbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgbYCFr4d96DTmSSwMktcMcMIUUzU62oaPKsbHkBKN27sY.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, $implicit, $nonce2),
            'Test Vector 4-E-7'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $implicit = \json_encode(['test-vector' => '4-E-8']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyzjtBiE9BKZSbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgbztJgsYb0BbisnXxIIpWUpBctN28mpOXVAkNR1yw_AyM.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, $implicit, $nonce2),
            'Test Vector 4-E-8'
        );


        $footer = '';
        $message = \json_encode(['data' => 'this is a signed message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA',
            Version4::sign($message, $this->privateKey, $footer),
            'Test Vector 4-S-1'
        );

        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            Version4::sign($message, $this->privateKey, $footer),
            'Test Vector 4-S-2'
        );

    }


    /**
     * @throws \TypeError
     */
    public function testEncrypt()
    {
        $nonce = str_repeat("\0", 24);
        // $nonce2 = sodium_crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce2 = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');

        $version4Encrypt = NonceFixer::buildUnitTestEncrypt(new Version4)->bindTo(null, new Version4);

        // Empty message, empty footer, empty nonce
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwmvKdnEB4XprW_sL883KSQubmn1-yXYGtQ9SGAUPJVQ',
            $version4Encrypt('', $this->nullKey, '', '', $nonce),
            'Test Vector 4E-1-1'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD0ZGbutCbPr_vLRlAAe8IHgvRh8HOJQGmO4S20WqasU',
            $version4Encrypt('', $this->fullKey, '', '', $nonce),
            'Test Vector 4E-1-2'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiRoI7hm5tgAKcfVZd6DnK0dfENOBGGMqGhFWNi4h75I',
            $version4Encrypt('', $this->symmetricKey,  '', '', $nonce),
            'Test Vector 4E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAD0sNxD1ed-ydXy5zzJYXM2xgCn2EngDJFT8MUSkIY.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('', $this->nullKey, 'Cuon Alpinus', '', $nonce),
            'Test Vector 4E-2-1'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAActXxAn7iB1h-b9q6YX-qP6qIX3I2YcHX5ts2fzR9OHA.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('', $this->fullKey, 'Cuon Alpinus',  '', $nonce),
            'Test Vector 4E-2-2'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT1WJhYpH3JIL2rj1snlaVOlUwHt3ghnqeZzCvU3CrCg.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('', $this->symmetricKey, 'Cuon Alpinus',  '', $nonce),
            'Test Vector 4E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtzKGeN3xftTtixTCIcKilh_cwBeEMGlBB9kpk4NYpbkT1PRSBHEtkpriWLfCbOzfj5vOQS4kv5IZmzuRy7tIrFwZ',
            $version4Encrypt('Love is stronger than hate or fear', $this->nullKey, '',  '', $nonce),
            'Test Vector 4E-3-1'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA58Fxa9f_ubKKJMPyiVAfoojPl0yLI9iEA7vX_OZ8JjSU-thaSqpka5W-2hgdWjGrJ07dZFigyNooSgnrDGQayifb',
            $version4Encrypt('Love is stronger than hate or fear', $this->fullKey, '',  '', $nonce),
            'Test Vector 4E-3-2'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPv3B4uAgt6KbqxdIGbC0P1ZT-EsSd3FA697VPtfmz-68Iih5r0tDbzYjTNn6jThfViB-mOeqJpfRGE_7nNr66FuB',
            $version4Encrypt('Love is stronger than hate or fear', $this->symmetricKey, '',  '', $nonce),
            'Test Vector 4E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGb6ZCxFG5bnP3XRtisMJ_Ed4yTebjqY2L8MIeZK56FHipgtBdbBUCNgKOX4yQDsAWpMOErKcsiYj11mF1W1NT552wT.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('Love is stronger than hate or fear', $this->nullKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 4E-4-1'
        );
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGblBKkNnvENjCr6-6jZsv9gVLP4IxAfgBFVCiWNGFgCdJ1Kp9t4CVx9JgrTcdhXXE9pSN86AiYv7DswtVz3TyAHjo3.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('Love is stronger than hate or fear', $this->fullKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 4E-4-2'
        );
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbWpzFZ6qO87tIoNl1nGcjDhSnhjJGzENFM9HWZTOKCiHjcSrojNEIq7TsjCDTue_0RgdplG6dR2H9Z9SJYTFbFbo_.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('Love is stronger than hate or fear', $this->symmetricKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 4E-4-3'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $footer = 'Paragon Initiative Enterprises';
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyziBNj1lBM5SbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgbsw8tjucGmaV4R9AadPpfwmhzXUFSsoz2qGhqMhjEqQo.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4E-5'
        );

        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $this->assertSame(
            'v4.local.RXQsl21oT_hOvcDeWYCal82i9kyE_aGbbdHXY_6GoqEZoMNzgSAvDxSyziBNj1lBM5SbbzLZDSPnIa5XKKud4I31Tf1WolQApQZdZPPCN9vOeV7mgeI42JR0kQgblnLvSBF-SG1TUd5e5td_IO7428haPSaduYMSQxAnekE.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4E-6'
        );
    }

    /**
     * @covers Version4::sign()
     *
     * @throws \TypeError
     * @throws PasetoException
     */
    public function testSignVectors()
    {
        // Empty string, 32-character NUL byte key.
        $this->assertSame(
            'v4.public.bdBfv2AnJ9PBhCa0qKew-fWIcpZ61c3NobCVvNVrWi1ZY7oRJPzeqH3VU4pYjrwbqdPDxOS97oTdRlFX3DKgAw',
            Version4::sign('', $this->privateKey),
            'Test Vector 4-S-1'
        );

        // Empty string, 32-character NUL byte key, non-empty footer.
        $this->assertSame(
            'v4.public.QgY3HuGJRnCr-I96pkEc2L2YyiZnxX0W3i671hOH7sqt2yqT9SMtLFgUHaLcbKkFjotj5xDNKrg7m9es1ASiAg.Q3VvbiBBbHBpbnVz',
            Version4::sign('', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector 4-S-2'
        );

        // Non-empty string, 32-character 0xFF byte key.
        $this->assertSame(
            'v4.public.RnJhbmsgRGVuaXMgcm9ja3NXNhunYdg69TViFngtEEppfPURPA-8pCtPvH0zDY0qZjT2Rky67e8WwAMRoPlSS_PzCTDH6PEJ7T7iNdDxcJ4C',
            Version4::sign('Frank Denis rocks', $this->privateKey),
            'Test Vector 4-S-3'
        );

        // Non-empty string, 32-character 0xFF byte key. (One character difference)
        $this->assertSame(
            'v4.public.RnJhbmsgRGVuaXMgcm9ja3ou56y37F0xRmq7FUa2OhA8ojprnyzIGBzffvogTQFmGp9dk54HsXvmrA6HZjOiXddyPvC6AbgPBXMqLqHrJPIK',
            Version4::sign('Frank Denis rockz', $this->privateKey),
            'Test Vector 4-S-4'
        );

        // Non-empty string, 32-character 0xFF byte key, non-empty footer.
        $this->assertSame(
            'v4.public.RnJhbmsgRGVuaXMgcm9ja3P_cuaiaBWtQ-3v3JWRASbl_6D99iuILRX4qTHc9RnwDtzfhn6aa1OwCVM3_GnCY3LCcOBR3ht312kD0bfMBRUH.Q3VvbiBBbHBpbnVz',
            Version4::sign('Frank Denis rocks', $this->privateKey, 'Cuon Alpinus'),
            'Test Vector 4-S-5'
        );

        $message = \json_encode(['data' => 'this is a signed message', 'exp' => '2019-01-01T00:00:00+00:00']);
        $footer = 'Paragon Initiative Enterprises';
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9q7Vl3wbLgV28wsCyjqTmF9dsdQ2tPQHuhJ03di1D9rmK-TdtxZe4Ygf6AuAC6S5-GK-BkX0YTj72nn3B3PBRAg',
            Version4::sign($message, $this->privateKey),
            'Test Vector 4-S-6'
        );
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ91Iet_TczjlphDg-vLJSV4nOX0uTtMzPrfzHw6LEe0-fjSG4xqC35RpZaPlgtes3dbEdayMk-PRk7yRpHhZU6Ag.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
            Version4::sign($message, $this->privateKey, $footer),
            'Test Vector 4-S-7'
        );

        $message = \json_encode(['data' => 'this is a signed message', 'exp' => '2019-01-01T00:00:00+00:00']);
        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9NF34so33DWiY6yEs3O6fMjxcy4_VbplJ0DDTXqEulRTBdUeRJqqNgbY4vZ1Z_oYV-cuQ_S_WUSZ1RGgXrcdZAA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            Version4::sign($message, $this->privateKey, $footer),
            'Test Vector 4-S-8'
        );

        $implicit = \json_encode(['test-vector' => '4-S-9']);
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9mVWjSTAhdeHvM7YPvT7w1rKvFRNStzYtxanb0YmDOYk7GuBIp1c6hZlYJHimJW1s7A8OAJpWKD0xZr0IfAFSAw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            Version4::sign($message, $this->privateKey, $footer, $implicit),
            'Test Vector 4-S-9'
        );
    }
}
