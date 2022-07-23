<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey
};
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\{
    PasetoException,
    SecurityException,
};
use ParagonIE\Paseto\Keys\Version4\SymmetricKey;
use ParagonIE\Paseto\Util;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase
{
    public function pemProvider(): array
    {
        return [
            [
                AsymmetricSecretKey::fromEncodedString(
                    'wqVipiU9_hsPvCayOadBKSHtAK0E3b6tgdTmipTXrLjSFM53nvNcUwtHPmBSU-sT',
                    new Version3
                ),

                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MIGkAgEBBDDCpWKmJT3+Gw+8JrI5p0EpIe0ArQTdvq2B1OaKlNesuNIUznee81xT\n" .
                "C0c+YFJT6xOgBwYFK4EEACKhZANiAAQRNcO/V8llj27Z1RNuzI0Sy/sTF1k4VolI\n" .
                "vrQjq+b30Kpd5AlLFzLkWOh8SGr1KM9dZj1vlRSWeoVGrXy99zOeu25vetkzYFMa\n" .
                "v9ZrBkjdv13uTEY5uWuKviAFmzAYnf4=\n" .
                "-----END EC PRIVATE KEY-----",

                "-----BEGIN PUBLIC KEY-----\n" .
                "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEETXDv1fJZY9u2dUTbsyNEsv7ExdZOFaJ\n" .
                "SL60I6vm99CqXeQJSxcy5FjofEhq9SjPXWY9b5UUlnqFRq18vfcznrtub3rZM2BT\n" .
                "Gr/WawZI3b9d7kxGOblrir4gBZswGJ3+\n" .
                "-----END PUBLIC KEY-----"
            ],
            [
                AsymmetricSecretKey::fromEncodedString(
                    't6Rbm0ASlC9TnLprftH5iSVq0yo1_7QEdPMiUXbiGFbD2VZn-_XpTgHTuMrH3oiu2eDNo9vVRgvh39Exl5RBGg',
                    new Version4
                ),

                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MC4CAQAwBQYDK2VwBCIEILekW5tAEpQvU5y6a37R+YklatMqNf+0BHTzIlF24hhW\n" .
                "w9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n" .
                "-----END EC PRIVATE KEY-----",

                "-----BEGIN PUBLIC KEY-----\n" .
                "MCowBQYDK2VwAyEAw9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n" .
                "-----END PUBLIC KEY-----"
            ],
        ];
    }

    /**
     * @dataProvider pemProvider
     */
    public function testExportPem(AsymmetricSecretKey $sk, string $skPem, string $pkPem): void
    {
        $this->assertSame($skPem, $sk->encodePem());
        $pk = $sk->getPublicKey();
        $this->assertSame(
            Util::dos2unix($pk->encodePem()),
            Util::dos2unix($pkPem)
        );
    }

    public function testV3SampleKeys(): void
    {
        $parameters = [
            [
                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MIGkAgEBBDAnSUGZvzGcMqhaW2kAaY0uvxVvLbAeJWeD+eaCYNzJiEoPr1eKuvBb\n" .
                "hFvi/Ft/41qgBwYFK4EEACKhZANiAARpPMZ8TLmF1d4ZlZR6hUJsWxze4M8TN9iS\n" .
                "waAjnoeGiIBT9fmpllDA8TR5lYvfS5zcN5ZcLtFHm4akAuen2cWEWtUYfxMfiGYx\n" .
                "jIXJ55iqSEuhXlvJ+NNMzBTjPvk/moc=\n" .
                "-----END EC PRIVATE KEY-----",
                '03693cc67c4cb985d5de1995947a85426c5b1cdee0cf1337d892c1a0239e8786888053f5f9a99650c0f13479958bdf4b9c',
                'J0lBmb8xnDKoWltpAGmNLr8Vby2wHiVng_nmgmDcyYhKD69XirrwW4Rb4vxbf-Na'
            ],

            [
                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MIGkAgEBBDDtEwLf2DPbrLWLYq42hdr15W6+xwgR8X1c9mXMe0728YGfVF2oQ4We\n" .
                "1q9/i6m3sLagBwYFK4EEACKhZANiAATuATlkGO95N59tpwl2a9zUiGqLDq5k+ARa\n" .
                "DGbupLQde6cyKzHcPj8remWkjkFNiZB+vctHKtn55KeY4D8PViv2l6TVBorzdYjR\n" .
                "Z7OdnDOTd5S/q4psBWPW5kRZFrX1tOI=\n" .
                "-----END EC PRIVATE KEY-----",
                '02ee01396418ef79379f6da709766bdcd4886a8b0eae64f8045a0c66eea4b41d7ba7322b31dc3e3f2b7a65a48e414d8990',
                '7RMC39gz26y1i2KuNoXa9eVuvscIEfF9XPZlzHtO9vGBn1RdqEOFntavf4upt7C2'
            ]
        ];
        foreach ($parameters as $params) {
            $this->sampleKeyTrail(...$params);
        }
    }

    public function sampleKeyTrail(string $secret, string $public, string $base64): void
    {
        $sk = AsymmetricSecretKey::v3($secret);
        $pk = $sk->getPublicKey();
        $this->assertSame($public, $pk->toHexString());
        $pk2 = AsymmetricPublicKey::fromEncodedString($pk->encode(), new Version3);
        $this->assertSame($public, $pk2->toHexString());

        $skEncode = $sk->encode();
        $this->assertSame($base64, $skEncode);

        $from = AsymmetricSecretKey::fromEncodedString($skEncode, new Version3);
        $this->assertSame(
            $from->encode(),
            $base64,
            'Re-encoding fails'
        );
    }

    public function testInvalidEdDSAKey()
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Slow test on sodium_compat');
        }
        $keypair1 = sodium_crypto_sign_keypair();
        $keypair2 = sodium_crypto_sign_keypair();

        $good1 = Binary::safeSubstr($keypair1, 0, 64);
        $good2 = Binary::safeSubstr($keypair2, 0, 64);
        $bad = Binary::safeSubstr($keypair1, 0, 32) . Binary::safeSubstr($keypair2, 32, 32);

        (new AsymmetricSecretKey($good1, new Version4()))->assertSecretKeyValid();
        (new AsymmetricSecretKey($good2, new Version4()))->assertSecretKeyValid();

        $this->expectException(SecurityException::class);
        (new AsymmetricSecretKey($bad, new Version4()))->assertSecretKeyValid();
    }

    public function testShortV3SymmetricKey()
    {
        $this->expectException(PasetoException::class);
        new SymmetricKey(random_bytes(31), new Version3());
    }

    public function testShortV4SymmetricKey()
    {
        $this->expectException(PasetoException::class);
        new SymmetricKey(random_bytes(31), new Version4());
    }

    public function testLongV3SymmetricKey()
    {
        $this->expectException(PasetoException::class);
        new SymmetricKey(random_bytes(33), new Version3());
    }

    public function testLongV4SymmetricKey()
    {
        $this->expectException(PasetoException::class);
        new SymmetricKey(random_bytes(33), new Version4());
    }
}
