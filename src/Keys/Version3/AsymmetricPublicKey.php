<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Version3;

use Exception;
use FG\ASN1\Exception\ParserException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\EasyECC\ECDSA\PublicKey;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey as BasePublicKey;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Util;
use TypeError;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\Paseto\Keys\Version3
 */
class AsymmetricPublicKey extends BasePublicKey
{
    /**
     * AsymmetricPublicKey constructor.
     *
     * @param string $keyData
     *
     * @throws Exception
     * @throws TypeError
     */
    public function __construct(string $keyData)
    {
        $len = Binary::safeStrlen($keyData);
        if ($len === 98) {
            $keyData = Version3::getPublicKeyPem($keyData);
        } elseif ($len === 49) {
            $keyData = Version3::getPublicKeyPem(Hex::encode($keyData));
        }

        parent::__construct($keyData, new Version3());
    }

    public function encode(): string
    {
        if (Binary::safeStrlen($this->key) === 49) {
            Base64UrlSafe::encodeUnpadded($this->key);
        } elseif (Binary::safeStrlen($this->key) === 98) {
            Base64UrlSafe::encodeUnpadded(Hex::decode($this->key));
        }
        try {
            return Base64UrlSafe::encodeUnpadded(
                Hex::decode(
                    Version3::getPublicKeyCompressed($this->key)
                )
            );
        } catch (ParserException $ex) {
            throw new PasetoException("ASN.1 Parser Exception", 0, $ex);
        }
    }

    public function encodePem(): string
    {
        if (Binary::safeStrlen($this->key) > 49) {
            return $this->key;
        }
        return Util::dos2unix(
            PublicKey::fromString($this->key, 'P384')
                ->exportPem()
        );
    }

    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        $decodeString = Base64UrlSafe::decode($encoded);
        $length = Binary::safeStrlen($encoded);
        if ($length === 98) {
            $decoded = Version3::getPublicKeyPem($decodeString);
        } elseif ($length === 49) {
            $decoded = Version3::getPublicKeyPem(Hex::encode($decodeString));
        } else {
            $decoded = $decodeString;
        }

        return new self($decoded);
    }

    public function toHexString(): string
    {
        if (Binary::safeStrlen($this->key) === 98) {
            return $this->key;
        }

        if (Binary::safeStrlen($this->key) !== 49) {
            return Version3::getPublicKeyCompressed($this->key);
        }

        return Hex::encode($this->key);
    }
}
