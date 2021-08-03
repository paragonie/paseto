<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version3;
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase
{
    public function testV3SampleKeys()
    {
        $parameters = [
            [
                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MIGkAgEBBDAnSUGZvzGcMqhaW2kAaY0uvxVvLbAeJWeD+eaCYNzJiEoPr1eKuvBb\n" .
                "hFvi/Ft/41qgBwYFK4EEACKhZANiAARpPMZ8TLmF1d4ZlZR6hUJsWxze4M8TN9iS\n" .
                "waAjnoeGiIBT9fmpllDA8TR5lYvfS5zcN5ZcLtFHm4akAuen2cWEWtUYfxMfiGYx\n" .
                "jIXJ55iqSEuhXlvJ+NNMzBTjPvk/moc=\n" .
                "-----END EC PRIVATE KEY-----",
                '03693cc67c4cb985d5de1995947a85426c5b1cdee0cf1337d892c1a0239e8786888053f5f9a99650c0f13479958bdf4b9c'
            ],

            [
                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MIGkAgEBBDDtEwLf2DPbrLWLYq42hdr15W6+xwgR8X1c9mXMe0728YGfVF2oQ4We\n" .
                "1q9/i6m3sLagBwYFK4EEACKhZANiAATuATlkGO95N59tpwl2a9zUiGqLDq5k+ARa\n" .
                "DGbupLQde6cyKzHcPj8remWkjkFNiZB+vctHKtn55KeY4D8PViv2l6TVBorzdYjR\n" .
                "Z7OdnDOTd5S/q4psBWPW5kRZFrX1tOI=\n" .
                "-----END EC PRIVATE KEY-----",
                '02ee01396418ef79379f6da709766bdcd4886a8b0eae64f8045a0c66eea4b41d7ba7322b31dc3e3f2b7a65a48e414d8990'
            ]
        ];
        foreach ($parameters as $params) {
            $this->sampleKeyTrail(...$params);
        }
    }

    public function sampleKeyTrail(string $secret, string $public)
    {
        $sk = AsymmetricSecretKey::v3($secret);
        $pk = $sk->getPublicKey();
        $this->assertSame($public, $pk->toHexString());
        $pk2 = AsymmetricPublicKey::fromEncodedString($pk->encode(), new Version3);
        $this->assertSame($public, $pk2->toHexString());
    }
}
