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
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD57Ff2IMST2Ce2qg0ZPjFe4CsCGRd6m6oLmwoo-dbTm0IKXUuTZMd11n5mfPxh1_0',
            Version1::encrypt('', $nullKey, '', $nonce),
            'Test Vector 1E-1-1'
        );
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACFZTMTd_W089p_pcQh0tAiGocoLk8rLG7Q0azZtOvHnXy9hYDWF5Nae_T9xbgjtjc',
            Version1::encrypt('', $fullKey, '', $nonce),
            'Test Vector 1E-1-2'
        );
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUeEsqw-ZhyFF-Mksw6hllOj5hY4DX3FKzZIsdyLcvg1Zu4i3dHxm3WARtm9EaY1s',
            Version1::encrypt('', $symmetricKey, '', $nonce),
            'Test Vector 1E-1-3'
        );

        // Empty message, non-empty footer, empty nonce
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACiE0lUwxWYCmwMtEsbiHxbce7Tnhyy8ALCCc-O8SqWXdG3FZPNINi-4KvqDNkrHMc.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $nullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-1'
        );
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADJfuWTfmxqFyY7R4he2G_fQVSnHS-feF6xneIhQNpNDWnJO6uzkOX0ipFKNUXAW0s.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $fullKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-2'
        );
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABzlWwRkThbKp2e1aTeLfopi1q0zHxm9DH9r_M9FTYYEkcHa8pNJQ6ghgNiUX7QKr0.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('', $symmetricKey, 'Cuon Alpinus', $nonce),
            'Test Vector 1E-2-3'
        );

        // Non-empty message, empty footer, empty nonce
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC4sdkaonM1w7X6fOIESRceamoluGO9D-x16v2tqkQdTALufsUTMf8aLKsfgTLtyRAShxCQjqOiaV8pgfI2dklREHFlkvJRtY7fbCZvatObpm',
            Version1::encrypt('Love is stronger than hate or fear', $nullKey, '', $nonce),
            'Test Vector 1E-3-1'
        );
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAecLuLXtMaDudUaN0lFk5cJmidk7DpaN8iU6n2LsQVU0pxqDXaoSFnD4MKsnY1xr7SA7y4AtERq0zxOuXk2jjKuCDrs2pGR6h8e44WighVOP1v',
            Version1::encrypt('Love is stronger than hate or fear', $fullKey, '', $nonce),
            'Test Vector 1E-3-2'
        );
        $this->assertSame(
            'v1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABTIAxi7TEHI4fPGBb-OitN2GhiUSB1_jGP42SusDUAZivbhRm_RVAdJ50tjxYLmVyMO6rsYwKZJMzmHs9BkBedX7GECMeVSzfnEwxS9A_G-2hd',
            Version1::encrypt('Love is stronger than hate or fear', $symmetricKey, '', $nonce),
            'Test Vector 1E-3-3'
        );

        // Non-empty message, non-empty footer, non-empty nonce
        $this->assertSame(
            'v1.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_KYJUT471ipjijHv8Kc7P6a_lWoNMyk-aIz_q04SaYCOFVGTZJUC58QvLmZRnsV8H-a2Y4KHuenktIZisGDZAuh2fpFFF2dh9vijhrtg00h8SMj.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $nullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-1'
        );
        $this->assertSame(
            'v1.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_J7dTvpTwyddq0ZmY-Zsb7qa-KAJ9kB3mt_RtAOBw-Oo_-brRpZ90wkDVy8ynu6sJ8G6bqEFA5dANOAsE1u4Cw0m-_HdFBkwsYi0BrK_HPW6RI7.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $fullKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-2'
        );
        $this->assertSame(
            'v1.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_IQHovl-qxc4DPjApcZ3b_BjpiVrYKsnxnA3bo11cNqaTEcLJpnfQv27tdF-HD7ttiQuNbO4irV3UF57sn6ttmzgh_pdsxwEjLHPG3cN1BanJT9.Q3VvbiBBbHBpbnVz',
            Version1::encrypt('Love is stronger than hate or fear', $symmetricKey, 'Cuon Alpinus', $nonce2),
            'Test Vector 1E-4-3'
        );
    }
}
