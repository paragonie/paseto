<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Hex
};
use ParagonIE\Paseto\Exception\EncodingException;
use ParagonIE\Paseto\Util;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TypeError;

/**
 * Class UtilTest
 * @package ParagonIE\Paseto\Tests
 */
class UtilTest extends TestCase
{
    /**
     * @throws EncodingException
     */
    public function testDepth()
    {
        $this->assertSame(1, Util::calculateJsonDepth('"abc"'));
        $this->assertSame(2, Util::calculateJsonDepth('{"abc":"def"}'));
        $this->assertSame(3, Util::calculateJsonDepth('{"abc":{"abc":"def"}}'));
        $this->assertSame(4, Util::calculateJsonDepth('{"abc":{"abc":{"abc":"def"}}}'));
        $this->assertSame(2, Util::calculateJsonDepth('{"abc":"{\"test\":\"foo\"}"}'));
        $this->assertSame(3, Util::calculateJsonDepth('{"abc":"{\"test\":\"foo\"}","def":[{"abc":"def"}]}'));
        $this->assertSame(3, Util::calculateJsonDepth('{"abc":"{\"test\":\"foo\"}" ,"def":[{"abc":"def"}]}'));
        $depth = random_int(1024, 8192);
        $this->assertSame(
            $depth + 1,
            Util::calculateJsonDepth(
                '{"a":' .
                str_repeat('[', $depth) .
                '1, 2, 3' .
                str_repeat(']', $depth) .
                '}'
            )
        );
    }

    /**
     * @throws EncodingException
     */
    public function testInvalid()
    {
        $this->expectException(EncodingException::class);
        Util::calculateJsonDepth('{"a":[}');
    }

    /**
     * @covers Util::preAuthEncode()
     * @throws TypeError
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

    public static function strtokProvider(): array
    {
        $r = Base64UrlSafe::encodeUnpadded(random_bytes(32));
        return [
            ['Paragon Initiative Enterprises', ' ', 'Paragon'],
            ['Initiative Enterprises', ' ', 'Initiative'],
            ['Enterprises', ' ', 'Enterprises'],
            ['', ' ', false],
            [
                $r . "\n" . Base64UrlSafe::encodeUnpadded(random_bytes(16)),
                "\n",
                $r
            ],
        ];
    }

    #[DataProvider('strtokProvider')]
    public function testStopAtDelimiter(string $input, string $delim, string|false $output): void
    {
        $result = Util::stopAtDelimiter($input, $delim);
        $this->assertSame($output, $result, 'Expected result was not returned');
        $built_in = strtok($input, $delim);
        $this->assertSame($built_in, $result, 'Regression with built-in strtok() behavior');
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
