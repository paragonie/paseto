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
use function str_replace, strlen, strtok, substr;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\Paseto\Keys\Version4
 */
class AsymmetricPublicKey extends BasePublicKey
{
    private const PEM_ENCODE_PREFIX = '302a300506032b6570032100';

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
            Hex::decode(self::PEM_ENCODE_PREFIX) . $this->raw()
        );
        return "-----BEGIN PUBLIC KEY-----\n" .
            Util::dos2unix(chunk_split($encoded, 64)).
            "-----END PUBLIC KEY-----";
    }

    public static function fromEncodedString(
        string $encoded,
        ?ProtocolInterface $version = null,
    ): self
    {
        $decoded = Base64UrlSafe::decode($encoded);
        return new self($decoded);
    }

    public function toHexString(): string
    {
        return Hex::encode($this->key);
    }

    /**
     * @param string $pem
     * @param ProtocolInterface|null $protocol
     * @return self
     *
     * @throws Exception
     */
    public static function importPem(string $pem, ?ProtocolInterface $protocol = null): self
    {
        $formattedKey = str_replace('-----BEGIN PUBLIC KEY-----', '', $pem);
        $formattedKey = str_replace('-----END PUBLIC KEY-----', '', $formattedKey);
        if (!is_string($formattedKey)) {
            throw new PasetoException('Invalid PEM format', ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR);
        }

        $tokenizedKey = strtok($formattedKey, "\n") ?: throw new PasetoException(
            'Invalid PEM format',
            ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR,
        );

        $key = Base64::decode($tokenizedKey);
        $prefix = Hex::decode(self::PEM_ENCODE_PREFIX);

        return new self(substr($key, strlen($prefix)));
    }
}
