<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey as LegacyAsymmetricSecretKey,
    SymmetricKey as LegacySymmetricKey
};
use ParagonIE\Paseto\Keys\Base\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Keys\Version3\{
    AsymmetricSecretKey as V3AsymmetricSecretKey,
    SymmetricKey as V3SymmetricKey
};
use ParagonIE\Paseto\Keys\Version4\{
    AsymmetricSecretKey as V4AsymmetricSecretKey,
    SymmetricKey as V4SymmetricKey
};
use ParagonIE\Paseto\{
    Exception\InvalidPurposeException,
    Purpose,
    ReceivingKey,
    SendingKey
};
use PHPUnit\Framework\TestCase;
use Exception;

class PurposeTest extends TestCase
{
    protected bool $setUpAtRuntime = false;
    protected AsymmetricSecretKey $bsk;
    protected AsymmetricPublicKey $bpk;
    protected SymmetricKey $bk;
    protected AsymmetricSecretKey $lsk;
    protected AsymmetricPublicKey $lpk;
    protected SymmetricKey $lk;
    protected AsymmetricSecretKey $sk3;
    protected AsymmetricPublicKey $pk3;
    protected SymmetricKey $k3;
    protected AsymmetricSecretKey $sk4;
    protected AsymmetricPublicKey $pk4;
    protected SymmetricKey $k4;

    /**
     * @return void
     *
     * @throws Exception
     */
    public function setUp(): void
    {
        $this->bsk = AsymmetricSecretKey::generate();
        $this->bpk = $this->bsk->getPublicKey();
        $this->bk = SymmetricKey::generate();

        $this->lsk = LegacyAsymmetricSecretKey::generate();
        $this->lpk = $this->lsk->getPublicKey();
        $this->lk = LegacySymmetricKey::generate();

        $this->sk3 = V3AsymmetricSecretKey::generate();
        $this->pk3 = $this->sk3->getPublicKey();
        $this->k3 = V3SymmetricKey::generate();
        
        $this->sk4 = V4AsymmetricSecretKey::generate();
        $this->pk4 = $this->sk4->getPublicKey();
        $this->k4 = V4SymmetricKey::generate();
    }

    public function receivingKeyProvider(): array
    {
        if (!$this->setUpAtRuntime) {
            $this->setUp();
        }
        return [
            [$this->bk, 'local'],
            [$this->lpk, 'public'],
            [$this->pk3, 'public'],
            [$this->pk4, 'public'],
            [$this->lk, 'local']
        ];
    }

    public function sendingKeyProvider(): array
    {
        if (!$this->setUpAtRuntime) {
            $this->setUp();
        }
        return [
            [$this->bk, 'local'],
            [$this->lsk, 'public'],
            [$this->sk3, 'public'],
            [$this->sk4, 'public'],
            [$this->lk, 'local']
        ];
    }

    /**
     * @dataProvider receivingKeyProvider
     *
     * @param ReceivingKey $key
     * @param string $expected
     * @return void
     * @throws InvalidPurposeException
     */
    public function testReceivingMapping(ReceivingKey $key, string $expected): void
    {
        $purpose = Purpose::fromReceivingKey($key);
        $this->assertSame($expected, $purpose->rawString());
    }

    /**
     * @dataProvider sendingKeyProvider
     *
     * @param SendingKey $key
     * @param string $expected
     * @return void
     * @throws InvalidPurposeException
     */
    public function testSendingMapping(SendingKey $key, string $expected): void
    {
        $purpose = Purpose::fromSendingKey($key);
        $this->assertSame($expected, $purpose->rawString());
    }
}
