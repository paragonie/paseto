<?php
namespace ParagonIE\PAST\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\PAST\Keys\AsymmetricPublicKey;
use ParagonIE\PAST\Keys\AsymmetricSecretKey;
use ParagonIE\PAST\Keys\SymmetricAuthenticationKey;
use ParagonIE\PAST\Keys\SymmetricEncryptionKey;
use ParagonIE\PAST\Protocol\Version1;
use PHPUnit\Framework\TestCase;

class Version1Test extends TestCase
{
    /**
     * @covers Version1::auth()
     * @covers Version1::verify()
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
            $auth = Version1::auth($message, $key);
            $this->assertTrue(\is_string($auth));
            $this->assertSame('v1.auth.', Binary::safeSubstr($auth, 0, 8));

            $decode = Version1::authVerify($auth, $key);
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);

            // Now with a footer
            $auth = Version1::auth($message, $key, 'footer');
            $this->assertTrue(\is_string($auth));
            $this->assertSame('v1.auth.', Binary::safeSubstr($auth, 0, 8));
            try {
                Version1::authVerify($auth, $key);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version1::authVerify($auth, $key, 'footer');
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers Version1::decrypt()
     * @covers Version1::encrypt()
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
            $encrypted = Version1::encrypt($message, $key);
            $this->assertTrue(\is_string($encrypted));
            $this->assertSame('v1.enc.', Binary::safeSubstr($encrypted, 0, 7));

            $decode = Version1::decrypt($encrypted, $key);
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);

            // Now with a footer
            try {
                Version1::decrypt($message, $key);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $encrypted = Version1::encrypt($message, $key, 'footer');
            $this->assertTrue(\is_string($encrypted));
            $this->assertSame('v1.enc.', Binary::safeSubstr($encrypted, 0, 7));

            $decode = Version1::decrypt($encrypted, $key, 'footer');
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);
        }
    }

    /**
     * @covers Version1::sign()
     * @covers Version1::signVerify()
     */
    public function testSign()
    {
        $rsa = Version1::getRsa(false);
        $keypair = $rsa->createKey(2048);
        $privateKey = new AsymmetricSecretKey($keypair['privatekey'], 'v1');
        $publicKey = new AsymmetricPublicKey($keypair['publickey'], 'v1');

        $year = (int) (\date('Y')) + 1;
        $messages = [
            'test',
            \json_encode(['data' => 'this is a signed message', 'expires' => $year . '-01-01T00:00:00'])
        ];

        foreach ($messages as $message) {
            $signed = Version1::sign($message, $privateKey);
            $this->assertTrue(\is_string($signed));
            $this->assertSame('v1.sign.', Binary::safeSubstr($signed, 0, 8));

            $decode = Version1::signVerify($signed, $publicKey);
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);

            // Now with a footer
            $signed = Version1::sign($message, $privateKey, 'footer');
            $this->assertTrue(\is_string($signed));
            $this->assertSame('v1.sign.', Binary::safeSubstr($signed, 0, 8));
            try {
                Version1::signVerify($signed, $publicKey);
                $this->fail('Missing footer');
            } catch (\Exception $ex) {
            }
            $decode = Version1::signVerify($signed, $publicKey, 'footer');
            $this->assertTrue(\is_string($decode));
            $this->assertSame($message, $decode);
        }
    }
    public function testAlterations()
    {
        $key = new SymmetricAuthenticationKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $messsage = \json_encode(['data' => 'this is a signed message', 'exp' => '2039-01-01T00:00:00']);
        $footer = \json_encode(['key-id' => 'gandalf0']);

        $this->assertSame(
            'v1.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9oneoWrZWNIceku3gc3mxky87q171X2AaPG1yXkluTTuEf0O2vJSSxnzXZKLm5tHq',
            Version1::auth($messsage, $key)
        );

        $this->assertSame(
            'v1.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9wCeZ4vYcmi6EdjT3W0UYpniF8S37SDRyYVDD8JQbk6tvxQyH2sip8TnMwU3sN8SK.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
            Version1::auth($messsage, $key, $footer)
        );
        try {
            Version1::authVerify(
                'v2.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9hHAIS4KV4dbi2kvBjiUEapFTCN6SZYdZpv-u40HYsIvH32u0mu1_DN224We-oQBu.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
                $key,
                $footer
            );
            $this->fail('Incorrect version number was accepted');
        } catch (\Exception $ex) {
        }

        try {
            Version1::authVerify(
                'v1.auth.fyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9hHAIS4KV4dbi2kvBjiUEapFTCN6SZYdZpv-u40HYsIvH32u0mu1_DN224We-oQBu.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
                $key,
                $footer
            );
            $this->fail('Invalid MAC was accepted');
        } catch (\Exception $ex) {
        }

        try {
            Version1::authVerify(
                'v1.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9hHAIS4KV4dbi2kvBjiUEapFTCN6SZYdZpv-u40HYsIvH32u0mu1_EN224We-oQBu.eyJrZXktaWQiOiJnYW5kYWxmMCJ9',
                $key,
                $footer
            );
            $this->fail('Invalid MAC was accepted');
        } catch (\Exception $ex) {
        }

        try {
            Version1::authVerify(
                'v1.auth.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCJ9hHAIS4KV4dbi2kvBjiUEapFTCN6SZYdZpv-u40HYsIvH32u0mu1_DN224We-oQBu.fyJrZXktaWQiOiJnYW5kYWxmMCJ9',
                $key,
                $footer
            );
            $this->fail('Invalid MAC was accepted');
        } catch (\Exception $ex) {
        }
    }
}
