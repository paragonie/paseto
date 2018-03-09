<?php
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\ProtocolCollection;
use PHPUnit\Framework\TestCase;

/**
 * Class ReadmeTest
 *
 * Unit tests to verify the examples given in the README.
 *
 * @package ParagonIE\Paseto\Tests
 */
class ReadmeTest extends TestCase
{
    /**
     * @throws \Error
     * @throws \Exception
     * @throws \ParagonIE\Paseto\Exception\InvalidVersionException
     * @throws \TypeError
     */
    public function testLocal()
    {
        $version2 = new Version2();
        $token = 'v2.local.QAxIpVe-ECVNI1z4xQbm_qQYomyT3h8FtV8bxkz8pBJWkT8f7HtlOpbroPDEZUKop_vaglyp76CzYy375cHmKCW8e1CCkV0Lflu4GTDyXMqQdpZMM1E6OaoQW27gaRSvWBrR3IgbFIa0AkuUFw.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz';
        $key = new SymmetricKey(Hex::decode('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'), $version2);

        $parser = Parser::getLocal($key, ProtocolCollection::v2());
        $object = $parser->parse($token);
        $this->assertEquals(
            new \DateTime('2039-01-01T00:00:00+00:00'),
            $object->getExpiration()
        );

        $this->assertSame(
            'this is a signed message',
            $object->get('data')
        );
    }

    /**
     * @throws \Exception
     * @throws \TypeError
     */
    public function testPublic()
    {
        $version2 = new Version2();
        $token = 'v2.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZGF0YSI6InRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSJ91gC7-jCWsN3mv4uJaZxZp0btLJgcyVwL-svJD7f4IHyGteKe3HTLjHYTGHI1MtCqJ-ESDLNoE7otkIzamFskCA';

        /*
        $secretKey = new ParagonIE\Paseto\Keys\AsymmetricSecretKey(
            Hex::decode(
                'f03171650aad288cc2dd6343f95feefff3c8f25e36629d5753965c856ab1a070' .
                '11324397f535562178d53ff538e49d5a162242970556b4edd950c87c7d86648a'
            ),
            $version2
        );
        */
        $publicKey = new AsymmetricPublicKey(
            Hex::decode('11324397f535562178d53ff538e49d5a162242970556b4edd950c87c7d86648a'),
            $version2
        );

        $parser = Parser::getPublic($publicKey, ProtocolCollection::v2());
        $object = $parser->parse($token);
        $this->assertEquals(
            new \DateTime('2039-01-01T00:00:00+00:00'),
            $object->getExpiration()
        );

        $this->assertSame(
            'this is a signed message',
            $object->get('data')
        );
    }
}
