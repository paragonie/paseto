<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Keys\Version4;

use Exception;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey as BasePublicKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Util;
use TypeError;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\Paseto\Keys\Version4
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
        if ($len === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES << 1) {
            // Try hex-decoding
            $keyData = Hex::decode($keyData);
        } else if ($len !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new PasetoException(
                'Public keys must be 32 bytes long; ' . $len . ' given.',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }

        parent::__construct($keyData, new Version4());
    }

    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    public function encodePem(): string
    {
        $encoded = Base64::encode(
            Hex::decode('302a300506032b6570032100') . $this->raw()
        );
        return "-----BEGIN PUBLIC KEY-----\n" .
            Util::dos2unix(chunk_split($encoded, 64)).
            "-----END PUBLIC KEY-----";
    }

    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        $decoded = Base64UrlSafe::decode($encoded);
        return new self($decoded);
    }

    public function toHexString(): string
    {
        return Hex::encode($this->key);
    }
}
