<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricAuthenticationKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use PHPUnit\Framework\TestCase;

class Version1Test extends TestCase
{
    /**
     * @covers Version1::getNonce()
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
     */
    public function testEncrypt()
    {
        $key = new SymmetricKey(random_bytes(32));
        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $encrypted = Version1::encrypt($message, $key);
            $this->assertInternalType('string', $encrypted);
            $this->assertSame('v1.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version1::decrypt($encrypted, $key);
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version1::decrypt($message, $key);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $encrypted = Version1::encrypt($message, $key, 'footer');
            $this->assertInternalType('string', $encrypted);
            $this->assertSame('v1.local.', Binary::safeSubstr($encrypted, 0, 9));

            $decode = Version1::decrypt($encrypted, $key, 'footer');
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers Version1::sign()
     * @covers Version1::verify()
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
            \json_encode(['data' => 'this is a signed message', 'expires' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version1::sign($message, $privateKey);
            $this->assertInternalType('string', $signed);
            $this->assertSame('v1.public.', Binary::safeSubstr($signed, 0, 10));

            $decode = Version1::verify($signed, $publicKey);
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version1::sign($message, $privateKey, 'footer');
            $this->assertInternalType('string', $signed);
            $this->assertSame('v1.public.', Binary::safeSubstr($signed, 0, 10));
            try {
                Version1::verify($signed, $publicKey);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version1::verify($signed, $publicKey, 'footer');
            $this->assertInternalType('string', $decode);
            $this->assertSame($message, $decode);
        }
    }
}
