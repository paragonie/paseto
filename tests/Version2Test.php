<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Version2\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version2\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version2\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use ParagonIE\Paseto\Protocol\Version2;
use PHPUnit\Framework\TestCase;

class Version2Test extends TestCase
{
    use TestTrait;

    /**
     * @throws \Exception
     * @throws \TypeError
     */
    public function testKeyGen()
    {
        $symmetric = Version2::generateSymmetricKey();
        $secret = Version2::generateAsymmetricSecretKey();

        $this->assertInstanceOf('ParagonIE\Paseto\Keys\SymmetricKey', $symmetric);
        $this->assertInstanceOf('ParagonIE\Paseto\Keys\AsymmetricSecretKey', $secret);

        $this->assertSame(Version2::getSymmetricKeyByteLength(), Binary::safeStrlen($symmetric->raw()));
        $this->assertSame(64, Binary::safeStrlen($secret->raw()));
    }

    /**
     * @covers Version2::decrypt()
     * @covers Version2::encrypt()
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
            \json_encode(['data' => 'this is a signed message', 'exp' => $year . '-01-01T00:00:00+00:00'])
        ];

        foreach ($messages as $message) {
            $encrypted = Version2::encrypt($message, $key);
            $this->assertIsStringType($encrypted);
            $this->assertSame('v2.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version2::decrypt($encrypted, $key);
            $this->assertIsStringType($decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version2::decrypt($message, $key);
                $this->fail('Not a token');
            } catch (PasetoException $ex) {
            }
            try {
                Version2::decrypt($encrypted, $key, 'footer');
                $this->fail('Footer did not cause expected MAC failure.');
            } catch (PasetoException $ex) {
            }
            $encrypted = Version2::encrypt($message, $key, 'footer');
            $this->assertIsStringType($encrypted);
            $this->assertSame('v2.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version2::decrypt($encrypted, $key, 'footer');
            $this->assertIsStringType($decode);
            $this->assertSame($message, $decode);

            $decode = Version2::decrypt($encrypted, $key);
            $this->assertIsStringType($decode);
            $this->assertSame($message, $decode);
            try {
                Version2::decrypt($encrypted, $key, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
        }

        try {
            Version1::encrypt('test', $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $encrypted = Version2::encrypt('test', $key);
        try {
            Version1::decrypt($encrypted, $key);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }

    /**
     * @covers Version2::sign()
     * @covers Version2::verify()
     *
     * @throws InvalidVersionException
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public function testSign()
    {
        $keypair = sodium_crypto_sign_keypair();
        $privateKey = new AsymmetricSecretKey(sodium_crypto_sign_secretkey($keypair));
        $publicKey = new AsymmetricPublicKey(sodium_crypto_sign_publickey($keypair));

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'exp' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version2::sign($message, $privateKey);
            $this->assertIsStringType($signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version2::verify($signed, $publicKey);
            $this->assertIsStringType($decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version2::sign($message, $privateKey, 'footer');
            $this->assertIsStringType($signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version2::verify($signed, $publicKey, '');
                $this->fail('Missing footer');
            } catch (PasetoException $ex) {
            }
            $decode = Version2::verify($signed, $publicKey, 'footer');
            $this->assertIsStringType($decode);
            $this->assertSame($message, $decode);
        }

        try {
            Version1::sign('test', $privateKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
        $signed = Version2::sign('test', $privateKey);
        try {
            Version1::verify($signed, $publicKey);
            $this->fail('Invalid version accepted');
        } catch (InvalidVersionException $ex) {
        }
    }

    /**
     * @covers AsymmetricSecretKey for version 2
     *
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public function testWeirdKeypairs()
    {
        $keypair = sodium_crypto_sign_keypair();
        $privateKey = new AsymmetricSecretKey(sodium_crypto_sign_secretkey($keypair));
        $publicKey = new AsymmetricPublicKey(sodium_crypto_sign_publickey($keypair));

        $seed = Binary::safeSubstr($keypair, 0, 32);
        $privateAlt = new AsymmetricSecretKey($seed);
        $publicKeyAlt = $privateAlt->getPublicKey();

        $this->assertSame(
            Base64UrlSafe::encode($privateAlt->raw()),
            Base64UrlSafe::encode($privateKey->raw())
        );
        $this->assertSame(
            Base64UrlSafe::encode($publicKeyAlt->raw()),
            Base64UrlSafe::encode($publicKey->raw())
        );
    }
}
