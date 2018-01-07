<?php
declare(strict_types=1);
namespace ParagonIE\PAST\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\PAST\Keys\SymmetricKey;
use ParagonIE\PAST\Protocol\Version1;
use PHPUnit\Framework\TestCase;

/**
 * Class Version1VectorTest
 *
 * Contains test vectors for building compatible implementations in other languages.
 *
 * @package ParagonIE\PAST\Tests
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
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTUue6xNG8kSnhp-PNl5yjB7PLBUYeYpOWbUOcbzEZOE2S406fY8aZ0A5RxrtPLK18A',
            Version1::encrypt('', $nullKey, '', $nonce),
            'Test Vector 1E-1-1'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXqlg33A7vg7xv5WYNntfrfJ9_KLrVLfJ4VJ8zmvB-DoBMt4vYUN6YpG9rZlR0OM7E',
            Version1::encrypt('', $fullKey, '', $nonce),
            'Test Vector 1E-1-2'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVKn21yi3P8LDmRv2DVNizuWZRyXP2YerlhRwGQG_CX3ldCTuPlqdhryzFasIVj2Sc',
            Version1::encrypt('', $symmetricKey, '', $nonce),
            'Test Vector 1E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXlwbDEQouBNa2J96IHMxC8RAi20_Ip23MhOOJZ1Xc_6qemYhTTeIgNao49i72uHVU.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $nullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-1'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV7vylFo8CRlNRxZtUtVWt4oBqnbn1jKdeGB8vBUahMCCONAJm4paTaVVF-KRwy-KY.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $fullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-2'
        );
        $this->assertSame(
            'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTUv93eHKnMdTD_SkpLb3KIJOPnltvunV9x0PN5OvF6YE5O9JLi7xre6yGlL4WO7KoE.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $symmetricKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA467KsdrRzbGwGK1-p_8Ea0zS79yN83i7ZvkmVGvvXe_3NG9BO5OFzFr-oP6TKEd4rw40mArWe3vzCThv-qKjxpzDHqc-zoLyMRYdTddwC2SRZTr',
            Version1::encrypt('Love is stronger than hate or fear', $nullKey, '', $nonce),
            'Test Vector 1E-3-1'
        );
        $this->assertSame(
            'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA44pvNtYCBLkJrkyKGZqmfK_wSD-tm9HYByq5QvHvY8aD8rdFJpPO3K2u872acREkrBEfhkjDRpIgYuN-NvehxFMT_O015rnwbgCXQtGj6gH3LP9',
            Version1::encrypt('Love is stronger than hate or fear', $fullKey, '', $nonce),
            'Test Vector 1E-3-2'
        );
        $this->assertSame(
            'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA44OLHUSW9hrhQQLd-WpmNHLUopO6bR-HHXWVAzZVulIhH7Zpf-WmM4Bw9C2MKxFbTdD_cTNhrMz4cz5TBtBkvM1_PLhGUeQJh9e3zgYekK2Ydpi',
            Version1::encrypt('Love is stronger than hate or fear', $symmetricKey, '', $nonce),
            'Test Vector 1E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYaqhM4jYa4b2pza6TwSozaD9oWrnEW2UWvUMEdDjoes4zHCh-wC563PBDyeRuvqqaUii-UE4FEmi2ivUvvUdtlRkdkE2fUCs-OfY7hDepwQWtcK.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $nullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-1'
        );
        $this->assertSame(
            'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYDEK-BZWCja0kP5Vv6cr1KBZKTuZMNYwHD2yhUyeuS7C9QDC2qm4An238P_Yo2J7XOdMAMdM9EKlrUxwjMC1P_JkRIaDBZwXaNYq7T41D1pc9n.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $fullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-2'
        );
        $this->assertSame(
            'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYXzLfMpQFsrJQxfPEeFhGtRyEFfPKoo9rdjP0jTHABY0CkzOk56kUd4I_a9ByhwqZjaaWpDoPC2gzxXKRCCRQdJSGCfxEX5zL_vXrtuAgCuYMJ.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $symmetricKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-3'
        );
    }
}
