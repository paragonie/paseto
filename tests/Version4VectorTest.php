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
        $nonce = str_repeat("\0", 32);
        // $nonce2 = sodium_crypto_generichash('Paragon Initiative Enterprises, LLC', '', 32);
        $nonce2 = Hex::decode('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8');

        $version4Encrypt = NonceFixer::buildUnitTestEncrypt(new Version4)->bindTo(null, new Version4);

        $footer = '';

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce),
            'Test Vector 4-E-1'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce),
            'Test Vector 4-E-2'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-3'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-4'
        );

        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-5'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4-E-6'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $implicit = \json_encode(['test-vector' => '4-E-7']);
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            $version4Encrypt($message, $this->symmetricKey, $footer, $implicit, $nonce2),
            'Test Vector 4-E-7'
        );

        $message = \json_encode(['data' => 'this is a hidden message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $implicit = \json_encode(['test-vector' => '4-E-8']);
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
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

        $implicit = json_encode(['test-vector' => '4-S-3']);
        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $this->assertSame(
            'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
            Version4::sign($message, $this->privateKey, $footer, $implicit),
            'Test Vector 4-S-3'
        );

    }


    /**
     * @throws \TypeError
     */
    public function testEncrypt()
    {
        $nonce = str_repeat("\0", 32);
        // $nonce2 = sodium_crypto_generichash('Paragon Initiative Enterprises, LLC', '', 32);
        $nonce2 = Hex::decode('df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8');

        $version4Encrypt = NonceFixer::buildUnitTestEncrypt(new Version4)->bindTo(null, new Version4);

        // Empty message, empty footer, empty nonce
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADkSQPdGD_mRYqjZBajSRjn961Uz9av-lrGGDKkxNQqpA',
            $version4Encrypt('', $this->nullKey, '', '', $nonce),
            'Test Vector 4E-1-1'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACpBupoEVz-frC4IBr-KBt4b8PSBnV2vfTo0lB3AZU-rQ',
            $version4Encrypt('', $this->fullKey, '', '', $nonce),
            'Test Vector 4E-1-2'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACJ9-FQi28Bj60m8wi4FU0K5kNSrzOWAn0jlvUK52fM_A',
            $version4Encrypt('', $this->symmetricKey,  '', '', $nonce),
            'Test Vector 4E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQdTeurN12FlbotJr8JaNCzv5hbZnLuVl9aC2q-5kT-w.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('', $this->nullKey, 'Cuon Alpinus', '', $nonce),
            'Test Vector 4E-2-1'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcPx4ghdniBZafFiuZCmL_gSedqCf3IGKcCCknXejXOw.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('', $this->fullKey, 'Cuon Alpinus',  '', $nonce),
            'Test Vector 4E-2-2'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADZzpgbhiJCh28Vif71vuWWwxhXdUANjmM7SFaBB2iexg.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('', $this->symmetricKey, 'Cuon Alpinus',  '', $nonce),
            'Test Vector 4E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4ZML5wEiTYzwTV8gHA2_RaIetKGSMg6ng6z7V7jEuXo2SJIg-zZvxY5lXDi-Q6bD_GKhb_XpmDtnPnq9pAsUjExs',
            $version4Encrypt('Love is stronger than hate or fear', $this->nullKey, '',  '', $nonce),
            'Test Vector 4E-3-1'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxZcJiVIIu3rXbou4eyn6fpEtTeYj3ZLF_v4TKM3alvEvY9USjTVmxnlGykFk7eN14muvfI5zHG6fbwNYzIxT0TF8',
            $version4Encrypt('Love is stronger than hate or fear', $this->fullKey, '',  '', $nonce),
            'Test Vector 4E-3-2'
        );
        $this->assertSame(
            'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnT6y4aSZRR7_IZfB9PctlUN6a0MxGjg114wNNChS7kg4OAYUF216LgLqxsdv3Ilqy63esZ1KFqRNxUDV-KC1n_ZU',
            $version4Encrypt('Love is stronger than hate or fear', $this->symmetricKey, '',  '', $nonce),
            'Test Vector 4E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjwjblm1eIris-mxcK32AHDPALuAlRtnPjBxsHPzJW1HPjQUKVheHoWIOqn9Ln6IYilRgAJrfgtacjkkKIjGAFH7JQ.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('Love is stronger than hate or fear', $this->nullKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 4E-4-1'
        );
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOthtd9RITEj35Dr87VatXBc-QpcNuw2T8SVZKmq_DoEiX6TxE5qkOuLxpH8ZLQaBFYIKDBm7n8Efxsd82J7ekIfBMLw.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('Love is stronger than hate or fear', $this->fullKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 4E-4-2'
        );
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtj3r1qul7e8a_KM_mVZNXjwl7hegQhve3g6UG5R_BROP3y5wJv7Egus21a2uKutj07DwAeKOiG1V_6xJJmT2QuWPBE.Q3VvbiBBbHBpbnVz',
            $version4Encrypt('Love is stronger than hate or fear', $this->symmetricKey, 'Cuon Alpinus', '', $nonce2),
            'Test Vector 4E-4-3'
        );

        $message = \json_encode(['data' => 'this is a secret message', 'exp' => '2022-01-01T00:00:00+00:00']);
        $footer = 'Paragon Initiative Enterprises';
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t7s-5fnLeq8Tyr9Jnluf-wQErjWBdneFpivTgRz56B-AA.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
            $version4Encrypt($message, $this->symmetricKey, $footer, '', $nonce2),
            'Test Vector 4E-5'
        );

        $footer = \json_encode(['kid' => 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN']);
        $this->assertSame(
            'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
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
