<?php
namespace ParagonIE\PAST\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\PAST\Keys\AsymmetricPublicKey;
use ParagonIE\PAST\Keys\AsymmetricSecretKey;
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\PAST\Keys\SymmetricEncryptionKey;
use ParagonIE\PAST\Protocol\Version2;
use PHPUnit\Framework\TestCase;

class Version2Test extends TestCase
{
    /**
     * @covers Version2::auth()
     * @covers Version2::verify()
     */
    public function testAuth()
    {
        $key = new SymmetricAuthenticationKey(random_bytes(32));
        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $auth = Version2::auth($message, $key);
            $this->assertTrue(\is_string($auth));
            $this->assertSame('v2.auth.', Binary::safeSubstr($auth, 0, 8));

            $decode = Version2::authVerify($auth, $key);
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);

            // Now with a footer
            $auth = Version2::auth($message, $key, 'footer');
            $this->assertTrue(\is_string($auth));
            $this->assertSame('v2.auth.', Binary::safeSubstr($auth, 0, 8));
            try {
                Version2::authVerify($auth, $key);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version2::authVerify($auth, $key, 'footer');
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers Version2::decrypt()
     * @covers Version2::encrypt()
     */
    public function testEncrypt()
    {
        $key = new SymmetricEncryptionKey(random_bytes(32));
        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $encrypted = Version2::encrypt($message, $key);
            $this->assertTrue(\is_string($encrypted));
            $this->assertSame('v2.enc.', Binary::safeSubstr($encrypted, 0, 7));

            $decode = Version2::decrypt($encrypted, $key);
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version2::decrypt($message, $key);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $encrypted = Version2::encrypt($message, $key, 'footer');
            $this->assertTrue(\is_string($encrypted));
            $this->assertSame('v2.enc.', Binary::safeSubstr($encrypted, 0, 7));

            $decode = Version2::decrypt($encrypted, $key, 'footer');
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers Version2::seal()
     * @covers Version2::unseal()
     */
    public function testSeal()
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
            $sealed = Version2::seal($message, $publicKey);
            $this->assertTrue(\is_string($sealed));
            $this->assertSame('v2.seal.', Binary::safeSubstr($sealed, 0, 8));

            $decode = Version2::unseal($sealed, $privateKey);
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);

            // Now with a footer
            $sealed = Version2::seal($message, $publicKey, 'footer');
            $this->assertTrue(\is_string($sealed));
            $this->assertSame('v2.seal.', Binary::safeSubstr($sealed, 0, 8));

            try {
                Version2::unseal($sealed, $privateKey);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version2::unseal($sealed, $privateKey, 'footer');
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers Version2::sign()
     * @covers Version2::signVerify()
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
            $this->assertTrue(\is_string($signed));
            $this->assertSame('v2.sign.', Binary::safeSubstr($signed, 0, 8));

            $decode = Version2::signVerify($signed, $publicKey);
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version2::sign($message, $privateKey, 'footer');
            $this->assertTrue(\is_string($signed));
            $this->assertSame('v2.sign.', Binary::safeSubstr($signed, 0, 8));
            try {
                Version2::signVerify($signed, $publicKey);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version2::signVerify($signed, $publicKey, 'footer');
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);
        }
    }
}
