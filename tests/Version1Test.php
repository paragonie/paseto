<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Version1\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version1\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version1\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use ParagonIE\Paseto\Protocol\Version2;
use PHPUnit\Framework\TestCase;

class Version1Test extends TestCase
{
    use TestTrait;

    /**
     * @throws \Exception
     * @throws \TypeError
     */
    public function testKeyGen()
    {
        $symmetric = Version1::generateSymmetricKey();
        $secret = Version1::generateAsymmetricSecretKey();

        $this->assertInstanceOf('ParagonIE\Paseto\Keys\SymmetricKey', $symmetric);
        $this->assertInstanceOf('ParagonIE\Paseto\Keys\AsymmetricSecretKey', $secret);

        $this->assertSame(Version1::getSymmetricKeyByteLength(), Binary::safeStrlen($symmetric->raw()));
        $this->assertGreaterThanOrEqual(1700, Binary::safeStrlen($secret->raw())); // PEM encoded
    }

    /**
     * @covers Version1::getNonce()
     *
     * @throws \TypeError
     */
    public function testNonceDerivation()
    {
        $msgA = 'The quick brown fox jumped over the lazy dog.';
        $msgB = 'The quick brown fox jumped over the lazy dof.';
        $nonce = Hex::decode('808182838485868788898a8b8c8d8e8f');

        $this->assertSame(
            '5e13b4f0fc111bf0cf9de4e97310b687858b51547e125790513cc1eaaef173cc',
            Hex::encode(Version1::getNonce($msgA, $nonce))
        );

        $this->assertSame(
            'e1ba992f5cccd31714fd8c73adcdadabb00d0f23955a66907170c10072d66ffd',
            Hex::encode(Version1::getNonce($msgB, $nonce))
        );
    }

    /**
     * @covers Version1::decrypt()
     * @covers Version1::encrypt()
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
            $encrypted = Version1::encrypt($message, $key);
            $this->assertIsStringType( $encrypted);
            $this->assertSame('v1.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version1::decrypt($encrypted, $key);
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version1::decrypt($message, $key);
                $this->fail('Not a token');
            } catch (PasetoException $ex) {
            }
            try {
                Version1::decrypt($encrypted, $key, 'footer');
                $this->fail('Footer did not cause expected MAC failure.');
            } catch (PasetoException $ex) {
            }
            $encrypted = Version1::encrypt($message, $key, 'footer');
            $this->assertIsStringType( $encrypted);
            $this->assertSame('v1.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version1::decrypt($encrypted, $key, 'footer');
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);
            try {
                Version1::decrypt($encrypted, $key, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
        }

        try {
            Version2::encrypt('test', $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $encrypted = Version1::encrypt('test', $key);
        try {
            Version2::decrypt($encrypted, $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }

    /**
     * @covers Version1::sign()
     * @covers Version1::verify()
     *
     * @throws InvalidVersionException
     * @throws \Exception
     * @throws \TypeError
     */
    public function testSign()
    {
        $rsa = Version1::getRsa();
        $keypair = $rsa->createKey(2048);
        $privateKey = new AsymmetricSecretKey($keypair['privatekey'], new Version1);
        $publicKey = new AsymmetricPublicKey($keypair['publickey'], new Version1);

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'exp' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version1::sign($message, $privateKey);
            $this->assertIsStringType( $signed);
            $this->assertSame('v1.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version1::verify($signed, $publicKey);
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version1::sign($message, $privateKey, 'footer');
            $this->assertIsStringType( $signed);
            $this->assertSame('v1.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version1::verify($signed, $publicKey, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
            $decode = Version1::verify($signed, $publicKey, 'footer');
            $this->assertIsStringType( $decode);
            $this->assertSame($message, $decode);
        }

        try {
            Version2::sign('test', $privateKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $signed = Version1::sign('test', $privateKey);
        try {
            Version2::verify($signed, $publicKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }
}
