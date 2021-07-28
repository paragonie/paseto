<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests\Rules;

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
    }
}
