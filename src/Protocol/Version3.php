<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Protocol;

use Exception;
use FG\ASN1\Exception\ParserException as ASN1ParserException;
use ParagonIE\ConstantTime\{Base64UrlSafe, Binary, Hex};
use ParagonIE\EasyECC\{EasyECC, ECDSA\PublicKey, ECDSA\SecretKey, Exception\InvalidPublicKeyException};
use Override;
use ParagonIE\Paseto\{ProtocolInterface, Util};
use ParagonIE\Paseto\Exception\{ExceptionCode, InvalidVersionException, PasetoException, SecurityException};
use ParagonIE\Paseto\Keys\{Base\AsymmetricPublicKey, Base\AsymmetricSecretKey, Base\SymmetricKey};
use ParagonIE\Paseto\Keys\Version3\{AsymmetricSecretKey as V3AsymmetricSecretKey, SymmetricKey as V3SymmetricKey};
use ParagonIE\Paseto\Parsing\{Header, PasetoMessage};
use SodiumException;
use Throwable;
use TypeError;
use function hash_equals;
use function hash_hmac;
use function is_null;
use function is_string;
use function openssl_decrypt;
use function openssl_encrypt;
use function random_bytes;

/**
 * Class Version3
 * @package ParagonIE\Paseto\Protocol
 * @api
 */
class Version3 implements ProtocolInterface
{
    const HEADER = 'v3';
    const CIPHER_MODE = 'aes-256-ctr';
    const HASH_ALGO = 'sha384';
    const CURVE = 'P384';

    const SYMMETRIC_KEY_BYTES = 32;

    const NONCE_SIZE = 32;
    const MAC_SIZE = 48;
    const SIGN_SIZE = 96; // 384-bit ECDSA = 96-byte signature

    /**
     * Must be constructable with no arguments so an instance may be passed
     * around in a type safe way.
     */
    public function __construct()
    {
    }

    /**
     * @return int
     */
    #[Override]
    public static function getSymmetricKeyByteLength(): int
    {
        return (int) static::SYMMETRIC_KEY_BYTES;
    }

    /**
     * Generate an asymmetric secret key for use with v3.public tokens.
     *
     * @return AsymmetricSecretKey
     *
     * @throws Exception
     * @throws TypeError
     */
    #[Override]
    public static function generateAsymmetricSecretKey(): AsymmetricSecretKey
    {
        return V3AsymmetricSecretKey::generate(new self());
    }

    /**
     * Generate a symmetric key for use with v3.local tokens.
     *
     * @return SymmetricKey
     *
     * @throws Exception
     * @throws TypeError
     */
    #[Override]
    public static function generateSymmetricKey(): SymmetricKey
    {
        return V3SymmetricKey::generate(new self());
    }

    /**
     * A unique header string with which the protocol can be identified.
     *
     * @return string
     */
    #[Override]
    public static function header(): string
    {
        return (string) static::HEADER;
    }

    /**
     * Does this protocol support implicit assertions?
     * Yes.
     *
     * @return bool
     */
    #[Override]
    public static function supportsImplicitAssertions(): bool
    {
        return true;
    }

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     *
     * @throws PasetoException
     */
    #[Override]
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        return self::__encrypt($data, $key, $footer, $implicit);
    }

    /**
     * Encrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @param string $nonceForUnitTesting
     * @return string
     *
     * @throws PasetoException
     * @throws TypeError
     */
    protected static function __encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = '',
        string $nonceForUnitTesting = ''
    ): string {
        /*
         * PASETO Version 3 - Encrypt - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v3 tokens only.
         */
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        return static::aeadEncrypt(
            $data,
            static::header() . '.local.', // PASETO Version 3 - Encrypt - Step 2
            $key,
            $footer,
            $implicit,
            $nonceForUnitTesting
        );
    }

    /**
     * Decrypt a message using a shared key.
     *
     * @param string $data
     * @param SymmetricKey $key
     * @param string|null $footer
     * @param string $implicit
     * @return string
     *
     * @throws PasetoException
     * @throws TypeError
     */
    #[Override]
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        ?string $footer = null,
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 3 - Decrypt - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v3 tokens only.
         */
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        // PASETO Version 3 - Decrypt - Step 2:
        if (is_null($footer)) {
            $footer = Util::extractFooter($data);
            $data = Util::removeFooter($data);
        } else {
            $data = Util::validateAndRemoveFooter($data, $footer);
        }
        return self::aeadDecrypt(
            $data,
            static::header() . '.local.',
            $key,
            $footer,
            $implicit
        );
    }

    /**
     * Sign a message. Public-key digital signatures.
     *
     * @param string $data
     * @param AsymmetricSecretKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     *
     * @throws Exception
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws SecurityException
     * @throws SodiumException
     * @throws TypeError
     */
    #[Override]
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 3 - Sign - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v3 tokens only.
         */
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        // PASETO Version 3 - Sign - Step 1:
        $header = self::header() . '.public.';
        $easyEcc = new EasyECC(self::CURVE);
        // PASETO Version 3 - Sign - Step 2 & 3:
        $pk = Hex::decode($key->getPublicKey()->toHexString());
        if (Binary::safeStrlen($pk) !== 49) {
            throw new PasetoException(
                'Invalid public key length: ' . Binary::safeStrlen($pk),
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }
        $signature = Hex::decode($easyEcc->sign(
            Util::preAuthEncode($pk, $header, $data, $footer, $implicit),
            SecretKey::importPem($key->raw()),
            true
        ));
        if (Binary::safeStrlen($signature) !== 96) {
            throw new PasetoException(
                'Invalid signature length: ' . Binary::safeStrlen($signature),
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }
        // PASETO Version 3 - Sign - Step 4:
        return (new PasetoMessage(
            Header::fromString($header),
            $data . $signature,
            $footer
        ))->toString();
    }

    /**
     * Verify a signed message. Public-key digital signatures.
     *
     * @param string $signMsg
     * @param AsymmetricPublicKey $key
     * @param string|null $footer
     * @param string $implicit
     * @return string
     *
     * @throws ASN1ParserException
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws SodiumException
     * @throws InvalidPublicKeyException
     */
    #[Override]
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        ?string $footer = null,
        string $implicit = ''
    ): string {
        /*
         * PASETO Version 3 - Verify - Step 1
         *
         * We already have a type-safety check on local/public. The following check
         * constrains the key to v3 tokens only.
         */
        if (!($key->getProtocol() instanceof Version3)) {
            throw new InvalidVersionException(
                'The given key is not intended for this version of PASETO.',
                ExceptionCode::WRONG_KEY_FOR_VERSION
            );
        }
        // PASETO Version 3 - Verify - Step 2:
        if (is_null($footer)) {
            $footer = Util::extractFooter($signMsg);
        } else {
            $signMsg = Util::validateAndRemoveFooter($signMsg, $footer);
        }
        $signMsg = Util::removeFooter($signMsg);

        // PASETO Version 3 - Verify - Step 3:
        $expectHeader = static::header() . '.public.';
        $headerLength = Binary::safeStrlen($expectHeader);
        $givenHeader = Binary::safeSubstr($signMsg, 0, $headerLength);
        if (!hash_equals($expectHeader, $givenHeader)) {
            throw new PasetoException(
                'Invalid message header.',
                ExceptionCode::INVALID_HEADER
            );
        }

        // PASETO Version 3 - Verify - Step 4:
        $decoded = Base64UrlSafe::decodeNoPadding(
            Binary::safeSubstr($signMsg, $headerLength)
        );
        $len = Binary::safeStrlen($decoded);

        if ($len <= self::SIGN_SIZE) {
            throw new PasetoException(
                'Invalid message length.',
                ExceptionCode::INVALID_MESSAGE_LENGTH
            );
        }

        $message = Binary::safeSubstr($decoded, 0, $len - self::SIGN_SIZE);
        $signature = Binary::safeSubstr($decoded, $len - self::SIGN_SIZE);

        $easyEcc = new EasyECC(self::CURVE);

        // PASETO Version 3 - Verify - Step 5 & 6:
        $pk = Hex::decode($key->toHexString());
        if (Binary::safeStrlen($pk) !== 49) {
            throw new PasetoException(
                'Invalid public key length: ' . Binary::safeStrlen($pk),
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }
        $valid = $easyEcc->verify(
            Util::preAuthEncode($pk, $givenHeader, $message, $footer, $implicit),
            PublicKey::fromString($key->toHexString(), 'P384'),
            Hex::encode($signature),
            true
        );

        // PASETO Version 3 - Verify - Step 7:
        if (!$valid) {
            throw new PasetoException(
                'Invalid signature for this message',
                ExceptionCode::INVALID_SIGNATURE
            );
        }
        return $message;
    }

    /**
     * Authenticated Encryption with Associated Data -- Encryption
     *
     * Algorithm: AES-256-CTR + HMAC-SHA384 (Encrypt then MAC)
     *
     * @param string $plaintext
     * @param string $header
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @param string $nonceForUnitTesting
     * @return string
     *
     * @throws Exception
     * @throws PasetoException
     * @throws SecurityException
     */
    public static function aeadEncrypt(
        string $plaintext,
        string $header,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = '',
        string $nonceForUnitTesting = ''
    ): string {
        // PASETO Version 3 - Encrypt - Step 3:
        if ($nonceForUnitTesting) {
            $nonce = $nonceForUnitTesting;
        } else {
            $nonce = random_bytes(self::NONCE_SIZE);
        }
        // PASETO Version 3 - Encrypt - Step 4:
        list($encKey, $authKey, $nonce2) = $key->splitV3($nonce);

        /** @var string|bool $ciphertext */
        // PASETO Version 3 - Encrypt - Step 5:
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            $nonce2
        );
        Util::wipe($encKey);
        if (!is_string($ciphertext)) {
            throw new PasetoException(
                'Encryption failed.',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }
        // PASETO Version 3 - Encrypt - Step 6 & 7:
        $mac = hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer, $implicit),
            $authKey,
            true
        );
        Util::wipe($authKey);

        // PASETO Version 3 - Encrypt - Step 8:
        return (new PasetoMessage(
            Header::fromString($header),
            $nonce . $ciphertext . $mac,
            $footer
        ))->toString();
    }

    /**
     * Authenticated Encryption with Associated Data -- Decryption
     *
     * @param string $message
     * @param string $header
     * @param SymmetricKey $key
     * @param string $footer
     * @param string $implicit
     * @return string
     *
     * @throws PasetoException
     * @throws TypeError
     */
    public static function aeadDecrypt(
        string $message,
        string $header,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = ''
    ): string {
        $expectedLen = Binary::safeStrlen($header);
        $givenHeader = Binary::safeSubstr($message, 0, $expectedLen);

        // PASETO Version 3 - Decrypt - Step 3:
        if (!hash_equals($header, $givenHeader)) {
            throw new PasetoException(
                'Invalid message header.',
                ExceptionCode::INVALID_HEADER
            );
        }

        // PASETO Version 3 - Decrypt - Step 4:
        try {
            $decoded = Base64UrlSafe::decodeNoPadding(
                Binary::safeSubstr($message, $expectedLen)
            );
        } catch (Throwable $ex) {
            throw new PasetoException(
                'Invalid encoding detected',
                ExceptionCode::INVALID_BASE64URL,
                $ex
            );
        }
        $len = Binary::safeStrlen($decoded);

        if ($len <= self::NONCE_SIZE + self::MAC_SIZE) {
            throw new PasetoException(
                'Invalid message length.',
                ExceptionCode::INVALID_MESSAGE_LENGTH
            );
        }

        $nonce = Binary::safeSubstr($decoded, 0, self::NONCE_SIZE);
        $ciphertext = Binary::safeSubstr(
            $decoded,
            self::NONCE_SIZE,
            $len - (self::NONCE_SIZE + self::MAC_SIZE)
        );
        $mac = Binary::safeSubstr($decoded, $len - self::MAC_SIZE);

        // PASETO Version 3 - Decrypt - Step 5:
        list($encKey, $authKey, $nonce2) = $key->splitV3($nonce);

        // PASETO Version 3 - Decrypt - Step 6 & 7:
        $calc = hash_hmac(
            self::HASH_ALGO,
            Util::preAuthEncode($header, $nonce, $ciphertext, $footer, $implicit),
            $authKey,
            true
        );
        Util::wipe($authKey);

        // PASETO Version 3 - Decrypt - Step 8:
        if (!hash_equals($calc, $mac)) {
            Util::wipe($encKey);
            throw new SecurityException(
                'Invalid MAC for given ciphertext.',
                ExceptionCode::INVALID_MAC
            );
        }

        // PASETO Version 3 - Decrypt - Step 9:
        /** @var string|bool $plaintext */
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER_MODE,
            $encKey,
            OPENSSL_RAW_DATA,
            $nonce2
        );
        Util::wipe($encKey);

        if (!is_string($plaintext)) {
            throw new PasetoException(
                'Encryption failed.',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }

        return $plaintext;
    }

    /**
     * Given a compressed point, get the PEM-formatted public key.
     *
     * @param string $compressedPoint
     * @return string
     *
     * @throws InvalidPublicKeyException
     */
    public static function getPublicKeyPem(string $compressedPoint): string
    {
        return Util::dos2unix(PublicKey::fromString($compressedPoint, 'P384')->exportPem());
    }

    /**
     * @param string $pemEncoded
     * @return string
     * @throws ASN1ParserException
     */
    public static function getPublicKeyCompressed(string $pemEncoded): string
    {
        return PublicKey::importPem($pemEncoded)->toString();
    }
}
