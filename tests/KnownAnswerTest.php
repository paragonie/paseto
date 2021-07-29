<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;

/**
 * Class KnownAnswerTest
 * @package ParagonIE\Paseto\Tests
 */
class KnownAnswerTest extends TestCase
{
    private $cacheKey;
    /** @var array<string, AsymmetricPublicKey|SymmetricKey> */
    private $keys = [];
    private $dir;

    public function setUp(): void
    {
        $this->cacheKey = sodium_crypto_shorthash_keygen();
        $this->dir = dirname(__DIR__) . '/docs/03-Implementation-Guide/Test-Vectors';
    }

    public function testV1()
    {
        $contents = json_decode(file_get_contents($this->dir . '/v1.json'), true);
        if (!is_array($contents)) {
            $this->markTestSkipped('Could not load test vector file');
        }
        $this->genericTests(new Version1(), $contents['tests']);
    }

    public function testV2()
    {
        $contents = json_decode(file_get_contents($this->dir . '/v2.json'), true);
        if (!is_array($contents)) {
            $this->markTestSkipped('Could not load test vector file');
        }
        $this->genericTests(new Version2(), $contents['tests']);
    }

    public function testV3()
    {
        $contents = json_decode(file_get_contents($this->dir . '/v3.json'), true);
        if (!is_array($contents)) {
            $this->markTestSkipped('Could not load test vector file');
        }
        $this->genericTests(new Version3(), $contents['tests']);
    }

    public function testV4()
    {
        $contents = json_decode(file_get_contents($this->dir . '/v4.json'), true);
        if (!is_array($contents)) {
            $this->markTestSkipped('Could not load test vector file');
        }

        $this->genericTests(new Version4(), $contents['tests']);
    }


    /**
     * @param ProtocolInterface $protocol
     * @param array $tests
     * @throws \SodiumException
     *
     * @psalm-suppress MixedArrayAccess
     */
    protected function genericTests(ProtocolInterface $protocol, array $tests)
    {
        $fixedEncrypt = NonceFixer::buildUnitTestEncrypt($protocol)->bindTo(null, $protocol);
        foreach ($tests as $test) {
            // First, assert that the payload decodes correctly.
            if (isset($test['public-key'])) {
                $decoded = $protocol::verify(
                    $test['token'],
                    $this->cacheKey($protocol, $test['public-key'], true),
                    $test['footer'] ?? '',
                    $test['implicit-assertion'] ?? ''
                );
            } elseif (isset($test['key'])) {
                $decoded = $protocol::decrypt(
                    $test['token'],
                    $this->cacheKey($protocol, $test['key']),
                    $test['footer'] ?? '',
                    $test['implicit-assertion'] ?? ''
                );
            } else {
                $this->fail('Key not provided');
            }
            $this->assertSame(json_encode($test['payload']), $decoded, $test['name']);

            // Next, assert that we get the same token (if local):
            if (isset($test['key'])) {
                $encoded = $fixedEncrypt(
                    json_encode($test['payload']),
                    $this->cacheKey($protocol, $test['key']),
                    $test['footer'] ?? '',
                    $test['implicit-assertion'] ?? '',
                    Hex::decode($test['nonce'])
                );
                $this->assertSame($test['token'], $encoded, $test['name']);
            }
        }
    }

    /**
     * Cache keys to save on memory.
     *
     * @param ProtocolInterface $protocol
     * @param string $hex
     * @param bool $public
     * @return AsymmetricPublicKey|SymmetricKey
     * @throws \SodiumException
     */
    protected function cacheKey(ProtocolInterface $protocol, string $hex, bool $public = false)
    {
        $lookup = Hex::encode(sodium_crypto_shorthash(
            ($public ? 'PUBLIC' : 'SECRET') . $protocol->header() . $hex,
            $this->cacheKey
        ));
        if (empty($this->keys[$lookup])) {
            $this->keys[$lookup] = $this->loadKey($protocol, $hex, $public);
        }
        return $this->keys[$lookup];
    }

    /**
     * @param ProtocolInterface $protocol
     * @param string $key
     * @param bool $public
     * @return AsymmetricPublicKey|SymmetricKey
     * @throws \Exception
     */
    protected function loadKey(ProtocolInterface $protocol, string $key, bool $public = false)
    {
        if ($public) {
            return new AsymmetricPublicKey($key, $protocol);
        }
        return new SymmetricKey(Hex::decode($key), $protocol);
    }
}
