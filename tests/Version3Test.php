<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\{
    InvalidVersionException,
    PasetoException
};
use ParagonIE\Paseto\Keys\AsymmetricPublicKey as BasePK;
use ParagonIE\Paseto\Keys\Version3\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;
use Error;
use Exception;
use SodiumException;
use TypeError;

class Version3Test extends TestCase
{
    use TestTrait;

    /**
     * @throws Exception
     * @throws TypeError
     */
    public function testKeyGen(): void
    {
        $symmetric = Version3::generateSymmetricKey();
        $secret = Version3::generateAsymmetricSecretKey();

        $this->assertInstanceOf('ParagonIE\Paseto\Keys\SymmetricKey', $symmetric);
        $this->assertInstanceOf('ParagonIE\Paseto\Keys\AsymmetricSecretKey', $secret);
        $this->assertSame(Version3::getSymmetricKeyByteLength(), Binary::safeStrlen($symmetric->raw()));
        $this->assertGreaterThanOrEqual(48, Binary::safeStrlen($secret->raw())); // PEM encoded

        $asymmetric2 = new AsymmetricSecretKey("\x7f" . random_bytes(47), new Version3);
        $pk = $asymmetric2->getPublicKey();
        $this->assertInstanceOf(BasePK::class, $pk);

        $mapping = [
            [new Version3, true],
            [new Version4, false],
        ];
        foreach ($mapping as $row) {
            [$version, $expected] = $row;
            $this->assertSame($expected, $symmetric->isForVersion($version));
            $this->assertSame($expected, $secret->isForVersion($version));
            $this->assertSame($expected, $secret->getPublicKey()->isForVersion($version));
        }
    }

    /**
     * @throws Exception
     * @throws PasetoException
     */
    public function testPublicKeyEncode(): void
    {
        $sk = AsymmetricSecretKey::generate(new Version3);
        $pk = $sk->getPublicKey();

        $encoded = $pk->encode();
        $decoded = AsymmetricPublicKey::fromEncodedString($encoded, new Version3());
        $this->assertSame(
            $pk->raw(),
            $decoded->raw()
        );
    }

    /**
     * @covers Version3::decrypt()
     * @covers Version3::encrypt()
     *
     * @throws Error
     * @throws Exception
     * @throws SodiumException
     * @throws TypeError
     */
    public function testEncrypt(): void
    {
        $key = new SymmetricKey(random_bytes(32));
        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'exp' => $year . '-01-01T00:00:00'])
        ];


        foreach ($messages as $message) {
            $encrypted = Version3::encrypt($message, $key);
            $this->assertIsStringType( $encrypted);
            $this->assertSame('v3.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version3::decrypt($encrypted, $key);
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version3::decrypt($message, $key);
                $this->fail('Not a token');
            } catch (PasetoException $ex) {
            }
            try {
                Version3::decrypt($encrypted, $key, 'footer');
                $this->fail('Footer did not cause expected MAC failure.');
            } catch (PasetoException $ex) {
            }
            $encrypted = Version3::encrypt($message, $key, 'footer');
            $this->assertIsStringType( $encrypted);
            $this->assertSame('v3.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version3::decrypt($encrypted, $key, 'footer');
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);
            try {
                Version3::decrypt($encrypted, $key, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
        }

        try {
            Version4::encrypt('test', $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $encrypted = Version3::encrypt('test', $key);
        try {
            Version4::decrypt($encrypted, $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }

    /**
     * @covers Version3::sign()
     * @covers Version3::verify()
     *
     * @throws InvalidVersionException
     * @throws Exception
     * @throws TypeError
     */
    public function testSign(): void
    {
        $privateKey = AsymmetricSecretKey::generate(new Version3());
        $publicKey = $privateKey->getPublicKey();

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'exp' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version3::sign($message, $privateKey);
            $this->assertIsStringType($signed);
            $this->assertSame('v3.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version3::verify($signed, $publicKey);
            $this->assertIsStringType($decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signedWithFooter = Version3::sign($message, $privateKey, 'footer');
            $this->assertIsStringType($signedWithFooter);
            $this->assertSame('v3.public.', Binary::safeSubstr($signedWithFooter, 0, 10));
            try {
                Version3::verify($signedWithFooter, $publicKey, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
            $decode = Version3::verify($signedWithFooter, $publicKey, 'footer');
            $this->assertIsStringType($decode);
            $this->assertSame($message, $decode);
        }

        try {
            Version4::sign('test', $privateKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $signed = Version3::sign('test', $privateKey);
        try {
            Version4::verify($signed, $publicKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }
}
