<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Hex
};
use ParagonIE\Paseto\Util;
use PHPUnit\Framework\TestCase;

/**
 * Class UtilTest
 * @package ParagonIE\Paseto\Tests
 */
class UtilTest extends TestCase
{
    /**
     * @covers Util::HKDF()
     * @ref https://tools.ietf.org/html/rfc5869
     *
     * @throws \Error
     * @throws \TypeError
     */
    public function testHKDFTestVectors()
    {
        $ikm = Hex::decode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $salt = Hex::decode('000102030405060708090a0b0c');
        $info = Hex::decode('f0f1f2f3f4f5f6f7f8f9');

        $this->assertSame(
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
            Hex::encode(
                Util::HKDF('sha256', $ikm, 42, $info, $salt)
            ),
            'Test Case #1 from the RFC'
        );

        // Test case 2:
        $ikm = Hex::decode(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627' .
            '28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'
        );
        $salt = Hex::decode(
            '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687' .
            '88898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
        );
        $info = Hex::decode(
            'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7' .
            'd8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        );

        $this->assertSame(
            'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271' .
            'cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
            Hex::encode(
                Util::HKDF('sha256', $ikm, 82, $info, $salt)
            ),
            'Test Case #2 from the RFC'
        );

        $ikm = Hex::decode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $this->assertSame(
            '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
            Hex::encode(
                Util::HKDF('sha256', $ikm, 42, '', '')
            ),
            'Test Case #3 from the RFC'
        );
    }

    /**
     * @covers Util::preAuthEncode()
     * @throws \TypeError
     */
    public function testPreAuthEncode()
    {
        $this->assertSame(
            '0000000000000000',
            Hex::encode(Util::preAuthEncode(...[])),
            'Empty array'
        );
        $this->assertSame(
            '0000000000000000',
            Hex::encode(Util::preAuthEncode()),
            'Empty array'
        );
        $this->assertSame(
            '01000000000000000000000000000000',
            Hex::encode(Util::preAuthEncode(...[''])),
            'Array of empty string'
        );
        $this->assertSame(
            '01000000000000000000000000000000',
            Hex::encode(Util::preAuthEncode('')),
            'Array of empty string'
        );
        $this->assertSame(
            '020000000000000000000000000000000000000000000000',
            Hex::encode(Util::preAuthEncode(...['', ''])),
            'Array of empty strings'
        );
        $this->assertSame(
            '020000000000000000000000000000000000000000000000',
            Hex::encode(Util::preAuthEncode('', '')),
            'Array of empty strings'
        );
        $this->assertSame(
            '0100000000000000070000000000000050617261676f6e',
            Hex::encode(Util::preAuthEncode(...['Paragon'])),
            'Array of non-empty string'
        );
        $this->assertSame(
            '0100000000000000070000000000000050617261676f6e',
            Hex::encode(Util::preAuthEncode('Paragon')),
            'Array of non-empty string'
        );
        $this->assertSame(
            '0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665',
            Hex::encode(Util::preAuthEncode(...['Paragon', 'Initiative'])),
            'Array of two non-empty strings'
        );
        $this->assertSame(
            '0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665',
            Hex::encode(Util::preAuthEncode('Paragon', 'Initiative')),
            'Array of two non-empty strings'
        );
        $this->assertSame(
            '0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665',
            Hex::encode(Util::preAuthEncode(...[
                'Paragon' . chr(10) . str_repeat("\0", 7) . 'Initiative'
            ])),
            'Ensure that faked padding results in different prefixes'
        );
        $this->assertSame(
            '0100000000000000190000000000000050617261676f6e0a00000000000000496e6974696174697665',
            Hex::encode(Util::preAuthEncode(
                'Paragon' . chr(10) . str_repeat("\0", 7) . 'Initiative'
            )),
            'Ensure that faked padding results in different prefixes'
        );
    }

    /**
     * @covers Util::validateAndRemoveFooter()
     */
    public function testValidateAndRemoveFooter()
    {
        $token = Base64UrlSafe::encode(random_bytes(30));
        $footer = random_bytes(10);
        $combined = $token . '.' . Base64UrlSafe::encodeUnpadded($footer);

        $this->assertSame(
            $token,
            Util::validateAndRemoveFooter($combined, $footer)
        );

        try {
            Util::validateAndRemoveFooter($combined, 'wrong');
            $this->fail('Invalid footer was accepted');
        } catch (\Exception $ex) {
        }
    }
}
