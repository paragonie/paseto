<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\SecurityException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Util;
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
        $rsaSecret = "-----BEGIN RSA PRIVATE KEY-----\n" .
            "MIIEpAIBAAKCAQEAwM+9K1eihqGJrrmYuZ1Yq28tuEX8Y6gFDGob9XEYIyZBkFzf\n" .
            "FGTl1PZY+b9wuXYdbN85IEj2etr8I62lG6EoVBe+TklU/L1NQ4tHWSUxHFmHrvM+\n" .
            "iV7qKdE09B9WOXN1bI5ckyl3u7tDRJGxeuFqz/WjFQXEzBxhQ8SIS1LdMyl7uO9N\n" .
            "eY+/Rx988BV8yRp1eA56xRItwrqgqhbUw8uPRImfPfPz5CAfm2KAL0vP7acsP5/l\n" .
            "1mQ4qqKhEomHZhfGsMAihEtoFKJsTPDYN8/1Zses8+4TmQ5A6XZCyJOP5RdugiJf\n" .
            "+s5vz62sl1SH4Ua5/FK4AB5M7KXPe/7H0UnmtwIDAQABAoIBAQCPtYaqmmvh6t7j\n" .
            "IyRJHJTtWjV6hndik+YHZcMnAj9aW3Y8smv3GGkRfPe+VkkfgoDWF97NSHSmBzgt\n" .
            "I4zPdiPH4daPJSs6IaJH+LSaJhVfqv9tj5GJ8/uWZX8RgZXTxlG8MrOfYCYE/8NY\n" .
            "hTsCeqcRD2WZEq6m73QzfXWUptOGAFVjiCBRep5JGI/EMpUCLyqoclDf+tI58xgX\n" .
            "PFNKUK4Qy3jVOaeWcPY8uWWhG93ImfiFfjU9EyXR62v3+PQf+e60NFbR0Z3YeIAe\n" .
            "RNRiXIX1ZVznlvCmwHxic9vyzViJgnVqrSaScIgifLXd8omvJySIxMmzdo8haywR\n" .
            "UgV+5PBpAoGBAPaBF7PPjzzbQPdvnHDa5RC4TU9YOOuy26hpKZaX9DUYlhcabY3x\n" .
            "kXpIwJadyW3W9+UG1c9US+kS+8DIsqH1Q/BKHevqd4qGgP7IQsneSt6PI15GUUwR\n" .
            "LaDpdfLZzFTsqM3ElVnOFlqo8ifsUPYT6IM0A4XEr/UHuJqnHYhPbAwzAoGBAMg9\n" .
            "J1nii7/snem3/hxd9rAD1Vm4qhmKeU1dBVELouZXUQkrkTCsd+hMHAnD+zuKKF9r\n" .
            "8mGKPhJiVIRFz0Pa5u5+DgcrmttxUzUkxG5bG7xkEEcgWJQ0FgCcOCVtChNfDabJ\n" .
            "pM+hSR1xNgl9IM4RhAical9xlVpnnGZ8b0wR73dtAoGARY7F3nJaS+TenzO6ZEoQ\n" .
            "SziGcDZH0ZKl0w7hsmHsgjMO3zQQ5/XbhDMVTSr3FOyNBO551MhHp1w49/xqE7N+\n" .
            "2UZAzTpbQxaTPdHKruXwIH8pjseu1xUd2AMoyj9VHj2toGqxbibuPeTgeA2CBv41\n" .
            "JRi/Sbbno+/q0pEHj1hB9+sCgYEAu65uGta3rB1o6a62M/pyhQoiyCTI8oWTKssc\n" .
            "d5lTh1iiMNkwDhIplYb45MJX0beuHbo9BeWgRnT5yLzyByS/PRzToy7gx/xRREeB\n" .
            "AfrNZWfYxgHwZIDpeoryKUopnnyCfCkWHDKNKFZ7kqtAu0U5nySUo37/wSvKMVlC\n" .
            "rGdHL4UCgYB5TyKK52uHR5gkB536JL1yLOQJh1lboojBI8xtLk5CglurwnM7Jyo4\n" .
            "z35jrPsWsuje6KwldW0LPwsHScAuhAW4rbLTBXD6EuHfQG0MIDlwWv+/1JIaWiq1\n" .
            "Xch7+gCwqoGd6qthsw/J7bx9Htj8rqFQcbS9Lc+Ynoa+cdZ3PxpsNg==\n" .
            "-----END RSA PRIVATE KEY-----";

        $rsaPublic = "-----BEGIN PUBLIC KEY-----\n" .
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwM+9K1eihqGJrrmYuZ1Y\n" .
            "q28tuEX8Y6gFDGob9XEYIyZBkFzfFGTl1PZY+b9wuXYdbN85IEj2etr8I62lG6Eo\n" .
            "VBe+TklU/L1NQ4tHWSUxHFmHrvM+iV7qKdE09B9WOXN1bI5ckyl3u7tDRJGxeuFq\n" .
            "z/WjFQXEzBxhQ8SIS1LdMyl7uO9NeY+/Rx988BV8yRp1eA56xRItwrqgqhbUw8uP\n" .
            "RImfPfPz5CAfm2KAL0vP7acsP5/l1mQ4qqKhEomHZhfGsMAihEtoFKJsTPDYN8/1\n" .
            "Zses8+4TmQ5A6XZCyJOP5RdugiJf+s5vz62sl1SH4Ua5/FK4AB5M7KXPe/7H0Unm\n" .
            "twIDAQAB\n" .
            "-----END PUBLIC KEY-----";

        return [
            [new AsymmetricSecretKey($rsaSecret, new Version1), $rsaSecret, $rsaPublic],
            [
                AsymmetricSecretKey::fromEncodedString(
                    't6Rbm0ASlC9TnLprftH5iSVq0yo1_7QEdPMiUXbiGFbD2VZn-_XpTgHTuMrH3oiu2eDNo9vVRgvh39Exl5RBGg',
                    new Version2
                ),

                "-----BEGIN EC PRIVATE KEY-----\n" .
                "MC4CAQAwBQYDK2VwBCIEILekW5tAEpQvU5y6a37R+YklatMqNf+0BHTzIlF24hhW\n" .
                "w9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n" .
                "-----END EC PRIVATE KEY-----",

                "-----BEGIN PUBLIC KEY-----\n" .
                "MCowBQYDK2VwAyEAw9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n" .
                "-----END PUBLIC KEY-----"
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
    public function testExportPem(AsymmetricSecretKey $sk, string $skPem, string $pkPem)
    {
        $this->assertSame($skPem, $sk->encodePem());
        $pk = $sk->getPublicKey();
        $this->assertSame(
            Util::dos2unix($pk->encodePem()),
            Util::dos2unix($pkPem)
        );
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

    public function ed25519provider()
    {
        return [
            [new Version2],
            [new Version4],
        ];
    }

    /**
     * @dataProvider ed25519provider
     */
    public function testInvalidEdDSAKey(ProtocolInterface $version)
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Slow test on sodium_compat');
        }
        $keypair1 = sodium_crypto_sign_keypair();
        $keypair2 = sodium_crypto_sign_keypair();

        $good1 = Binary::safeSubstr($keypair1, 0, 64);
        $good2 = Binary::safeSubstr($keypair2, 0, 64);
        $bad = Binary::safeSubstr($keypair1, 0, 32) . Binary::safeSubstr($keypair2, 32, 32);

        (new AsymmetricSecretKey($good1, $version))->assertSecretKeyValid();
        (new AsymmetricSecretKey($good2, $version))->assertSecretKeyValid();

        $this->expectException(SecurityException::class);
        (new AsymmetricSecretKey($bad, $version))->assertSecretKeyValid();
    }
}
