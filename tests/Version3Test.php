<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Version3\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version2,
    Version3
};
use PHPUnit\Framework\TestCase;

class Version3Test extends TestCase
{
    use TestTrait;

    /**
     * @throws \Exception
     * @throws \TypeError
     */
    public function testKeyGen()
    {
        $symmetric = Version3::generateSymmetricKey();
        $secret = Version3::generateAsymmetricSecretKey();

        $this->assertInstanceOf('ParagonIE\Paseto\Keys\SymmetricKey', $symmetric);
        $this->assertInstanceOf('ParagonIE\Paseto\Keys\AsymmetricSecretKey', $secret);
        $this->assertSame(Version3::getSymmetricKeyByteLength(), Binary::safeStrlen($symmetric->raw()));
        $this->assertGreaterThanOrEqual(48, Binary::safeStrlen($secret->raw())); // PEM encoded
    }

    /**
     * @covers Version3::decrypt()
     * @covers Version3::encrypt()
     *
     * @throws \Error
     * @throws \Exception
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testEncrypt()
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
            Version2::encrypt('test', $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $encrypted = Version3::encrypt('test', $key);
        try {
            Version2::decrypt($encrypted, $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }

    /**
     * @covers Version3::sign()
     * @covers Version3::verify()
     *
     * @throws InvalidVersionException
     * @throws \Exception
     * @throws \TypeError
     */
    public function testSign()
    {
        $privateKey = Version3::generateAsymmetricSecretKey();
        $publicKey = $privateKey->getPublicKey();

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'exp' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version3::sign($message, $privateKey);
            $this->assertIsStringType( $signed);
            $this->assertSame('v3.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version3::verify($signed, $publicKey);
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version3::sign($message, $privateKey, 'footer');
            $this->assertIsStringType( $signed);
            $this->assertSame('v3.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version3::verify($signed, $publicKey, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
            $decode = Version3::verify($signed, $publicKey, 'footer');
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);
        }

        try {
            Version2::sign('test', $privateKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $signed = Version3::sign('test', $privateKey);
        try {
            Version2::verify($signed, $publicKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }
}
