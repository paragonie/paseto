<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Version3;

use Exception;
use Mdanter\Ecc\EccFactory;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\EasyECC\ECDSA\ConstantTimeMath;
use ParagonIE\EasyECC\ECDSA\PublicKey;
use ParagonIE\EasyECC\ECDSA\SecretKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey as BaseSecretKey;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Util;
use TypeError;

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\Paseto\Keys\Version3
 */
class AsymmetricSecretKey extends BaseSecretKey
{
    /**
     * AsymmetricSecretKey constructor.
     *
     * @param string $keyData
     *
     * @throws Exception
     * @throws TypeError
     */
    public function __construct(
        #[\SensitiveParameter]
        string $keyData
    ) {
        parent::__construct($keyData, new Version3());
    }

    public static function generate(ProtocolInterface $protocol = null): self
    {
        return new self(
            Util::dos2unix(SecretKey::generate(Version3::CURVE)->exportPem())
        );
    }

    public function encode(): string
    {
        if (Binary::safeStrlen($this->key) > 48) {
            return Base64UrlSafe::encodeUnpadded(
                Hex::decode(
                    gmp_strval(
                        SecretKey::importPem($this->key)->getSecret(),
                        16
                    )
                )
            );
        }

        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    public function encodePem(): string
    {
        return Util::dos2unix($this->key);
    }

    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);

        if (Binary::safeStrlen($decoded) === 48) {
            return new self(
                (new SecretKey(
                    new ConstantTimeMath(),
                    EccFactory::getNistCurves()->generator384(),
                    \gmp_init(Hex::encode($decoded), 16)
                ))->exportPem()
            );
        }

        return new self($decoded);
    }

    public function getPublicKey(): AsymmetricPublicKey
    {
        /** @var PublicKey $pk */
        if (Binary::safeStrlen($this->key) === 48) {
            $pk = PublicKey::promote(
                (new SecretKey(
                    new ConstantTimeMath(),
                    EccFactory::getNistCurves()->generator384(),
                    gmp_init(Hex::encode($this->key), 16)
                ))->getPublicKey()
            );
        } else {
            /** @var PublicKey $pk */
            $pk = SecretKey::importPem($this->key)->getPublicKey();
        }
        return new AsymmetricPublicKey(
            PublicKey::importPem($pk->exportPem())->toString() // Compressed point
        );
    }
}
