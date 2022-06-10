<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use Exception;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * Class KnownAnswerTest
 * @package ParagonIE\Paseto\Tests
 */
class KnownAnswerTest extends TestCase
{
    private string $cacheKey = '';
    /** @var array<string, AsymmetricPublicKey|SymmetricKey> */
    private array $keys = [];
    private string $dir = '';

    public function setUp(): void
    {
        $this->cacheKey = sodium_crypto_shorthash_keygen();
        $this->dir = __DIR__ . '/test-vectors';
    }

    /**
     * @throws SodiumException
     */
    public function testV3(): void
    {
        $contents = json_decode(file_get_contents($this->dir . '/v3.json'), true);
        if (!is_array($contents)) {
            $this->markTestSkipped('Could not load test vector file');
        }
        $this->genericTests(new Version3(), $contents['tests']);
    }

    /**
     * @throws SodiumException
     */
    public function testV4(): void
    {
        $contents = json_decode(file_get_contents($this->dir . '/v4.json'), true);
        if (!is_array($contents)) {
            $this->markTestSkipped('Could not load test vector file');
        }

        $this->genericTests(new Version4(), $contents['tests']);
    }


    /**
     * @throws SodiumException
     *
     * @psalm-suppress PossiblyInvalidArgument
     * @psalm-suppress PossiblyInvalidFunctionCall
     * @psalm-suppress MissingReturnType
     * @psalm-suppress MixedArgument
     * @psalm-suppress MixedAssignment
     * @psalm-suppress MixedArrayAccess
     */
    protected function genericTests(ProtocolInterface $protocol, array $tests): void
    {
        $decoded = null;
        $fixedEncrypt = NonceFixer::buildUnitTestEncrypt($protocol)->bindTo(null, $protocol);
        foreach ($tests as $test) {
            // First, assert that the payload decodes correctly.
            try {
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
            } catch (Exception $ex) {
                if ($test['expect-fail']) {
                    $this->assertTrue(true, "Test failed as expected");
                    continue;
                }
                throw $ex;
            }

            // If we're here, the first step did not fail, so let's assert this:
            $this->assertFalse($test['expect-fail'], 'This test was expected to fail: ' . $test['name']);

            // We should have the same plaintext payload:
            $this->assertSame($test['payload'], $decoded, $test['name']);

            // Next, assert that we get the same token (if local):
            if (isset($test['key'])) {
                $encoded = $fixedEncrypt(
                    $test['payload'],
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
     * @throws SodiumException
     * @throws Exception
     */
    protected function cacheKey(
        ProtocolInterface $protocol,
        string $hex,
        bool $public = false
    ): AsymmetricPublicKey|SymmetricKey {
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
     * @throws Exception
     */
    protected function loadKey(
        ProtocolInterface $protocol,
        string $key,
        bool $public = false
    ): AsymmetricPublicKey|SymmetricKey {
        if ($public) {
            return new AsymmetricPublicKey($key, $protocol);
        }
        return new SymmetricKey(Hex::decode($key), $protocol);
    }
}
