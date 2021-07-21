<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Exception\SecurityException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;
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
     */
    protected function genericTests(ProtocolInterface $protocol, array $tests)
    {
        foreach ($tests as $test) {
            // Load key for this test (from cache, usually):
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
            $this->assertEquals(json_encode($test['payload']), $decoded, $test['name']);
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
            return new AsymmetricPublicKey(Hex::decode($key), $protocol);
        }
        return new SymmetricKey(Hex::decode($key), $protocol);
    }
}
