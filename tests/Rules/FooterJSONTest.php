<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests\Rules;

use ParagonIE\Paseto\Exception\EncodingException;
use ParagonIE\Paseto\Rules\FooterJSON;
use PHPUnit\Framework\TestCase;

/**
 * Class FooterJSONTest
 * @package ParagonIE\Paseto\Tests\Rules
 */
class FooterJSONTest extends TestCase
{
    public function testDepth()
    {
        $this->assertSame(1, FooterJSON::calculateDepth('"abc"'));
        $this->assertSame(2, FooterJSON::calculateDepth('{"abc":"def"}'));
        $this->assertSame(3, FooterJSON::calculateDepth('{"abc":{"abc":"def"}}'));
        $this->assertSame(4, FooterJSON::calculateDepth('{"abc":{"abc":{"abc":"def"}}}'));
        $this->assertSame(2, FooterJSON::calculateDepth('{"abc":"{\"test\":\"foo\"}"}'));
        $this->assertSame(3, FooterJSON::calculateDepth('{"abc":"{\"test\":\"foo\"}","def":[{"abc":"def"}]}'));
        $depth = random_int(1024, 8192);
        $this->assertSame(
            $depth + 1,
                FooterJSON::calculateDepth(
                '{"a":' .
                    str_repeat('[', $depth) .
                        '1, 2, 3' .
                    str_repeat(']', $depth) .
                '}'
            )
        );
    }

    public function testInvalid()
    {
        $this->expectException(EncodingException::class);
        FooterJSON::calculateDepth('{"a":[}');
    }
}
