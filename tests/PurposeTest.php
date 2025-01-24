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
use PHPUnit\Framework\Attributes\DataProvider;
use Exception;

class PurposeTest extends TestCase
{
    protected static AsymmetricSecretKey $bsk;
    protected static AsymmetricPublicKey $bpk;
    protected static SymmetricKey $bk;
    protected static AsymmetricSecretKey $lsk;
    protected static AsymmetricPublicKey $lpk;
    protected static SymmetricKey $lk;
    protected static AsymmetricSecretKey $sk3;
    protected static AsymmetricPublicKey $pk3;
    protected static SymmetricKey $k3;
    protected static AsymmetricSecretKey $sk4;
    protected static AsymmetricPublicKey $pk4;
    protected static SymmetricKey $k4;

    /**
     * @throws Exception
     */
    protected static function setupKeys(): void
    {
        self::$bsk = AsymmetricSecretKey::generate();
        self::$bpk = self::$bsk->getPublicKey();
        self::$bk = SymmetricKey::generate();

        self::$lsk = LegacyAsymmetricSecretKey::generate();
        self::$lpk = self::$lsk->getPublicKey();
        self::$lk = LegacySymmetricKey::generate();

        self::$sk3 = V3AsymmetricSecretKey::generate();
        self::$pk3 = self::$sk3->getPublicKey();
        self::$k3 = V3SymmetricKey::generate();

        self::$sk4 = V4AsymmetricSecretKey::generate();
        self::$pk4 = self::$sk4->getPublicKey();
        self::$k4 = V4SymmetricKey::generate();
    }

    /**
     * @return array<array<AsymmetricPublicKey|SymmetricKey|string>>
     */
    public static function receivingKeyProvider(): array
    {
        self::setupKeys();

        return [
            [self::$bk, 'local'],
            [self::$lpk, 'public'],
            [self::$pk3, 'public'],
            [self::$pk4, 'public'],
            [self::$lk, 'local']
        ];
    }

    /**
     * @return array<array<AsymmetricSecretKey|SymmetricKey|string>>
     */
    public static function sendingKeyProvider(): array
    {
        self::setupKeys();

        return [
            [self::$bk, 'local'],
            [self::$lsk, 'public'],
            [self::$sk3, 'public'],
            [self::$sk4, 'public'],
            [self::$lk, 'local']
        ];
    }

    /**
     * @throws InvalidPurposeException
     */
    #[DataProvider('receivingKeyProvider')]
    public function testReceivingMapping(ReceivingKey $key, string $expected): void
    {
        $purpose = Purpose::fromReceivingKey($key);
        $this->assertSame($expected, $purpose->rawString());
    }

    /**
     * @throws InvalidPurposeException
     */
    #[DataProvider('sendingKeyProvider')]
    public function testSendingMapping(SendingKey $key, string $expected): void
    {
        $purpose = Purpose::fromSendingKey($key);
        $this->assertSame($expected, $purpose->rawString());
    }
}
