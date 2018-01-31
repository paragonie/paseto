<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use PHPUnit\Framework\TestCase;

/**
 * Class Version1VectorTest
 *
 * Contains test vectors for building compatible implementations in other languages.
 *
 * @package ParagonIE\Paseto\Tests
 */
class Version1VectorTest extends TestCase
{
    /**
     * @throws \Error
     * @throws \TypeError
     */
    public function testEncrypt()
    {
        $nullKey = new SymmetricKey(\str_repeat("\0", 32));
        $fullKey = new SymmetricKey(\str_repeat("\xff", 32));
        $symmetricKey = new SymmetricKey(
            Hex::decode(
                '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f'
            )
        );
        $nonce = str_repeat("\0", 32);
        //$nonce2 = hash('sha256', 'Paragon Initiative Enterprises, LLC', true);
        $nonce2 = Hex::decode('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2');

        // Empty message, empty footer, empty nonce
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXyNMehtdOLJS_vq4YzYdaZ6vwItmpjx-Lt3AtVanBmiMyzFyqJMHCaWVMpEMUyxUg',
            Version1::encrypt('', $nullKey, '', $nonce),
            'Test Vector 1E-1-1'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTWgetvu2STfe7gxkDpAOk_IXGmBeea4tGW6HsoH12oKElAWap57-PQMopNurtEoEdk',
            Version1::encrypt('', $fullKey, '', $nonce),
            'Test Vector 1E-1-2'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV8OmiMvoZgzer20TE8kb3R0QN9Ay-ICSkDD1-UDznTCdBiHX1fbb53wdB5ng9nCDY',
            Version1::encrypt('', $symmetricKey, '', $nonce),
            'Test Vector 1E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVhyXOB4vmrFm9GvbJdMZGArV5_10Kxwlv4qSb-MjRGgFzPg00-T2TCFdmc9BMvJAA.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $nullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-1'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVna3s7WqUwfQaVM8ddnvjPkrWkYRquX58-_RgRQTnHn7hwGJwKT3H23ZDlioSiJeo.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $fullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-2'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTW9MRfGNyfC8vRpl8xsgnsWt-zHinI9bxLIVF0c6INWOv0_KYIYEaZjrtumY8cyo7M.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $symmetricKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA45LtwQCqG8LYmNfBHIX-4Uxfm8KzaYAUUHqkxxv17MFxsEvk-Ex67g9P-z7EBFW09xxSt21Xm1ELB6pxErl4RE1gGtgvAm9tl3rW2-oy6qHlYx2',
            Version1::encrypt('Love is stronger than hate or fear', $nullKey, '', $nonce),
            'Test Vector 1E-3-1'
        );
        $this->assertSame(
            'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47lQ79wMmeM7sC4c0-BnsXzIteEQQBQpu_FyMznRnzYg4gN-6Kt50rXUxgPPfwDpOr3lUb5U16RzIGrMNemKy0gRhfKvAh1b8N57NKk93pZLpEz',
            Version1::encrypt('Love is stronger than hate or fear', $fullKey, '', $nonce),
            'Test Vector 1E-3-2'
        );
        $this->assertSame(
            'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47hvAicYf1zfZrxPrLeBFdbEKO3JRQdn3gjqVEkR1aXXttscmmZ6t48tfuuudETldFD_xbqID74_TIDO1JxDy7OFgYI_PehxzcapQ8t040Fgj9k',
            Version1::encrypt('Love is stronger than hate or fear', $symmetricKey, '', $nonce),
            'Test Vector 1E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYbivwqsESBnr82_ZoMFFGzolJ6kpkOihkulB4K_JhfMHoFw4E9yCR6ltWX3e9MTNSud8mpBzZiwNXNbgXBLxF_Igb5Ixo_feIonmCucOXDlLVUT.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $nullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-1'
        );
        $this->assertSame(
            'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYZ8rQTA12SNb9cY8jVtVyikY2jj_tEBzY5O7GJsxb5MdQ6cMSnDz2uJGV20vhzVDgvkjdEcN9D44VaHid26qy1_1YlHjU6pmyTmJt8WT21LqzDl.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $fullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-2'
        );
        $this->assertSame(
            'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $symmetricKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-3'
        );
    }
}
