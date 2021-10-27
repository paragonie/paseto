<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase
{
    public function pemProvider()
    {
        $rsa = "-----BEGIN RSA PRIVATE KEY-----\n" .
            "MIIEogIBAAKCAQEAu74jdb19cuzn1yu/5tMScdXERyTqwl8L14UdURXHr+XN7aUa\n" .
            "+EttiS7B2DSaLWk4ikhkKBCfo2oMyceK2eJX4QbCGGqsX43aAuqfzRM+/B+g36Ta\n" .
            "W46+VeoQY+/KSNKlnVsZiQvliiuPkfQXpG/720qyZz8NumI+12jxcyq5Zbit38FM\n" .
            "WCcAz9pgAILHqz+cPHsI0JOQKWf7duKnzpiiDME7/5CQUdSavkld8t9u+YIZVYiu\n" .
            "nMA8Ch8D4b2UByCn1eferfiuqbRAbQ7jMvxbrhiFsJ7epeCtQyNL/8VhPoeUXWcY\n" .
            "2S5/wdogG6S2UItSkXfrrq1ErzLGmBdpQceSRQIDAQABAoIBAE5UOxkxkPh1DRmC\n" .
            "AFO+tpBV/sksBuJHo3os6Jle++xQdcVzwDfdyHqWznt1HupZXySapWbt4Jzeby10\n" .
            "mmLjg4S4PBzRzM8lMNNMrpVyNTIdxBHrBstyV8kimeoILp6JfF2Vl6bNFty55fGg\n" .
            "JIkPy8WneZ2H+iNMQCnBeBNzvNxKI4AA98YHDx7zusvssOfiOJBcZkapy4FGuEQd\n" .
            "E1hzlCEZOH/kFlC5YSCKZinJBxDDuofMde3WImZg7tch4AHtVhXbkuEz5vJTvSkj\n" .
            "xLZY/fN92/PMAj0KaLf9ql40CDOoO1fxCs+WNZ8+c52400brow7WoPGmQXCJaUvh\n" .
            "1oZ/jNUCgYEA+jVSc4QouBDdAJX41NINV4HSLjJIjdyg6fukt6agHlHG25idxoZ6\n" .
            "C3HDsQ05CbhmLtdbV2SyL8BDabxp+bB6J1HDfpQSUeP5s/1uCXQNxwHaroeHAkbj\n" .
            "1bbEM448B5C3yzOy+lcW6rL63We0YyUFtJK7atFL+XVzq57zsmszKhMCgYEAwBao\n" .
            "3ACF6v1Mgd08HCtXlVg0FBD5YBpBVogfIYxIINFx4kJynPV6iylSzVYoah/y58EL\n" .
            "YqNztrD7rRhQt8kYS1Nk/4TvOjHBtNPC6bLR0PQlzXudcfvoPL6KryKFtFlF8Ool\n" .
            "pG722U6JZeK87K4+GM72VBcp7qtfKNroFvg6XUcCgYAI5zTT33QDeLYkezGrgP3w\n" .
            "izILasaiJaOkL8wgrNEtwwMsdTXIBqj5F0c7WZkZ+3HHYOpjJbYhdNnxPT8YH2t5\n" .
            "rN+IY61U0NjYDU2KOcEmdBKPZBUSGl7BVHd88W3DzM7C8/mkIrENzIuBq6oiHy3\n" .
            "fDEnD+OAMOm4xaMuSho7+QKBgGzxLQnBXjJdQHPytnG/fyfbY4Xx7o07tszN3OIY\n" .
            "/ptmTjGlv/0XGE4uvKBqefdecVRRXxStYSY/EC4muTjS2211ObXVfhxCNftJkqUa\n" .
            "XvckUQBOWIhZ92fkJSGY8b3MV+d/1KOCr4uliDV5t+6AEAXf80LT9FtBZHH2XWUR\n" .
            "mYBnAoGADYbniwU6Drr+iPKt706N17pQB/47h9ETKFGzbwslno0D3miRSEscY9wX\n" .
            "rcDqfuZcf03QTIrXzrNpiiiTvkTvybE7Hrtq9qremXbpwGRRSUGEoXesfp1M0irj\n" .
            "MCAbY+0YcS2FdflNKiYuK/0VyXcmzYtpPK2N7OEihHNwIW/CBdE=\n" .
            "-----END RSA PRIVATE KEY-----";
        return [
            [new AsymmetricSecretKey($rsa, new Version1), $rsa],
            [
                AsymmetricSecretKey::fromEncodedString(
                    't6Rbm0ASlC9TnLprftH5iSVq0yo1_7QEdPMiUXbiGFbD2VZn-_XpTgHTuMrH3oiu2eDNo9vVRgvh39Exl5RBGg',
                    new Version2
                ),
                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MC4CAQAwBQYDK2VwBCIEILekW5tAEpQvU5y6a37R+YklatMqNf+0BHTzIlF24hhW\n" .
                "w9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n" .
                "-----END EC PRIVATE KEY-----"
            ],
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
                "-----END EC PRIVATE KEY-----"
            ],
            [
                AsymmetricSecretKey::fromEncodedString(
                    't6Rbm0ASlC9TnLprftH5iSVq0yo1_7QEdPMiUXbiGFbD2VZn-_XpTgHTuMrH3oiu2eDNo9vVRgvh39Exl5RBGg',
                    new Version4
                ),
                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MC4CAQAwBQYDK2VwBCIEILekW5tAEpQvU5y6a37R+YklatMqNf+0BHTzIlF24hhW\n" .
                "w9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n" .
                "-----END EC PRIVATE KEY-----"
            ],
        ];
    }

    /**
     * @dataProvider pemProvider
     */
    public function testExportPem(AsymmetricSecretKey $sk, string $pem)
    {
        $this->assertSame($pem, $sk->encodePem());
    }

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
}
