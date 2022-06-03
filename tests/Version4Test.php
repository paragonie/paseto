<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\{
    InvalidVersionException,
    PasetoException
};
use ParagonIE\Paseto\Keys\Version4\{
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

class Version4Test extends TestCase
{
    use TestTrait;

    /**
     * @throws Exception
     * @throws TypeError
     */
    public function testKeyGen(): void
    {
        $symmetric = Version4::generateSymmetricKey();
        $secret = Version4::generateAsymmetricSecretKey();

        $this->assertInstanceOf('ParagonIE\Paseto\Keys\SymmetricKey', $symmetric);
        $this->assertInstanceOf('ParagonIE\Paseto\Keys\AsymmetricSecretKey', $secret);
        $this->assertSame(Version4::getSymmetricKeyByteLength(), Binary::safeStrlen($symmetric->raw()));
        $this->assertGreaterThanOrEqual(48, Binary::safeStrlen($secret->raw())); // PEM encoded

        $mapping = [
            [new Version3, false],
            [new Version4, true],
        ];
        foreach ($mapping as $row) {
            [$version, $expected] = $row;
            $this->assertSame($expected, $symmetric->isForVersion($version));
            $this->assertSame($expected, $secret->isForVersion($version));
            $this->assertSame($expected, $secret->getPublicKey()->isForVersion($version));
        }
    }

    /**
     * @throws PasetoException
     */
    public function testPublicKeyEncode(): void
    {
        $sk = AsymmetricSecretKey::generate();
        $pk = $sk->getPublicKey();

        $encoded = $pk->encode();
        $decoded = AsymmetricPublicKey::fromEncodedString($encoded, new Version4());
        $this->assertSame(
            $pk->raw(),
            $decoded->raw()
        );
    }

    /**
     * @covers Version4::decrypt()
     * @covers Version4::encrypt()
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
            $encrypted = Version4::encrypt($message, $key);
            $this->assertIsStringType( $encrypted);
            $this->assertSame('v4.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version4::decrypt($encrypted, $key);
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version4::decrypt($message, $key);
                $this->fail('Not a token');
            } catch (PasetoException $ex) {
            }
            try {
                Version4::decrypt($encrypted, $key, 'footer');
                $this->fail('Footer did not cause expected MAC failure.');
            } catch (PasetoException $ex) {
            }
            $encrypted = Version4::encrypt($message, $key, 'footer');
            $this->assertIsStringType( $encrypted);
            $this->assertSame('v4.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version4::decrypt($encrypted, $key, 'footer');
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);
            try {
                Version4::decrypt($encrypted, $key, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
        }

        try {
            Version3::encrypt('test', $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $encrypted = Version4::encrypt('test', $key);
        try {
            Version3::decrypt($encrypted, $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }

    /**
     * @covers Version4::sign()
     * @covers Version4::verify()
     *
     * @throws InvalidVersionException
     * @throws Exception
     * @throws TypeError
     */
    public function testSign(): void
    {
        $privateKey = Version4::generateAsymmetricSecretKey();
        $publicKey = $privateKey->getPublicKey();

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'exp' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version4::sign($message, $privateKey);
            $this->assertIsStringType( $signed);
            $this->assertSame('v4.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version4::verify($signed, $publicKey);
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version4::sign($message, $privateKey, 'footer');
            $this->assertIsStringType( $signed);
            $this->assertSame('v4.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version4::verify($signed, $publicKey, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
            $decode = Version4::verify($signed, $publicKey, 'footer');
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);
        }

        try {
            Version3::sign('test', $privateKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $signed = Version4::sign('test', $privateKey);
        try {
            Version3::verify($signed, $publicKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }
}
