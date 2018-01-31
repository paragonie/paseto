<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricAuthenticationKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version2;
use PHPUnit\Framework\TestCase;

class Version2Test extends TestCase
{
    /**
     * @covers Version2::decrypt()
     * @covers Version2::encrypt()
     */
    public function testEncrypt()
    {
        $key = new SymmetricKey(random_bytes(32));
        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year . '-01-01T00:00:00+00:00'])
        ];

        foreach ($messages as $message) {
            $encrypted = Version2::encrypt($message, $key);
            $this->assertInternalType('string', $encrypted);
            $this->assertSame('v2.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version2::decrypt($encrypted, $key);
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version2::decrypt($message, $key);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $encrypted = Version2::encrypt($message, $key, 'footer');
            $this->assertInternalType('string', $encrypted);
            $this->assertSame('v2.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version2::decrypt($encrypted, $key, 'footer');
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers Version2::sign()
     * @covers Version2::verify()
     */
    public function testSign()
    {
        $keypair = sodium_crypto_sign_keypair();
        $privateKey = new AsymmetricSecretKey(sodium_crypto_sign_secretkey($keypair));
        $publicKey = new AsymmetricPublicKey(sodium_crypto_sign_publickey($keypair));

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version2::sign($message, $privateKey);
            $this->assertInternalType('string', $signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version2::verify($signed, $publicKey);
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version2::sign($message, $privateKey, 'footer');
            $this->assertInternalType('string', $signed);
            $this->assertSame('v2.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version2::verify($signed, $publicKey);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version2::verify($signed, $publicKey, 'footer');
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers AsymmetricSecretKey for version 2
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
