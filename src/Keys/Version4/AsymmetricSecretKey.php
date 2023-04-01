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
use ParagonIE\Paseto\Keys\AsymmetricSecretKey as BaseSecretKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Util;
use TypeError;

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\Paseto\Keys\Version4
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
    public function __construct(string $keyData)
    {
        $len = Binary::safeStrlen($keyData);
        if ($len === SODIUM_CRYPTO_SIGN_KEYPAIRBYTES) {
            $keyData = Binary::safeSubstr($keyData, 0, 64);
        } elseif ($len !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            if ($len !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
                throw new PasetoException(
                    'Secret keys must be 32 or 64 bytes long; ' . $len . ' given.',
                    ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
                );
            }
            $keypair = sodium_crypto_sign_seed_keypair($keyData);
            $keyData = Binary::safeSubstr($keypair, 0, 64);
        }

        parent::__construct($keyData, new Version4());
    }

    public static function generate(ProtocolInterface $protocol = null): self
    {
        return new self(
            sodium_crypto_sign_secretkey(
                sodium_crypto_sign_keypair()
            )
        );
    }

    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->key);
    }

    public function encodePem(): string
    {
        $encoded = Base64::encode(
            Hex::decode('302e020100300506032b657004220420') . $this->raw()
        );
        return "-----BEGIN EC PRIVATE KEY-----\n" .
            Util::dos2unix(chunk_split($encoded, 64)).
            "-----END EC PRIVATE KEY-----";
    }

    public static function fromEncodedString(string $encoded, ProtocolInterface $version = null): self
    {
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);
        return new self($decoded);
    }

    public function getPublicKey(): AsymmetricPublicKey
    {
        return new AsymmetricPublicKey(
            sodium_crypto_sign_publickey_from_secretkey($this->key)
        );
    }
}
