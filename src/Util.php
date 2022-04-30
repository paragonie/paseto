<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paseto\Exception\{
    EncodingException,
    ExceptionCode,
    PasetoException
};
use SodiumException;
use TypeError;
use function array_pop,
    array_slice,
    count,
    explode,
    hash_equals,
    hash_hmac,
    hash_hkdf,
    implode,
    is_callable,
    is_null,
    pack,
    preg_replace,
    preg_match_all,
    sodium_memzero,
    str_repeat,
    str_replace;

/**
 * Class Util
 * @package ParagonIE\Paseto
 */
abstract class Util
{
    /**
     * Calculate the depth of a JSON string without passing it to json_decode()
     *
     * @param string $json
     * @return int
     *
     * @throws EncodingException
     */
    public static function calculateJsonDepth(string $json): int
    {
        // Remove quotes quotes first:
        $stripped = str_replace('\"', '', $json);

        // Remove whitespace:
        $stripped = preg_replace('/\s+/', '', $stripped);

        // Strip everything out of quotes:
        $stripped = preg_replace('#"[^"]+"([:,}\]])#', '$1', $stripped);

        // Remove everything that isn't a map or list definition
        $stripped = preg_replace('#[^\[\]{}]#', '', $stripped);

        $previous = '';
        $depth = 1;
        while (!empty($stripped) && $stripped !== $previous) {
            $previous = $stripped;
            // Remove pairs of tokens
            $stripped = str_replace(['[]', '{}'], [], $stripped);
            ++$depth;
        }
        if (!empty($stripped)) {
            throw new EncodingException(
                'Invalid JSON string provided',
                ExceptionCode::INVALID_JSON
            );
        }
        return $depth;
    }

    /**
     * Count the number of instances of `":` without a preceding backslash.
     *
     * @param string $json
     * @return int
     */
    public static function countJsonKeys(string $json): int
    {
        return preg_match_all('#[^\\\]":#', $json);
    }

    /**
     * Normalize line-endings to UNIX-style (LF rather than CRLF).
     *
     * @param string $in
     * @return string
     */
    public static function dos2unix(string $in): string
    {
        return str_replace("\r\n", "\n", $in);
    }

    /**
     * Computes the HKDF key derivation function specified in
     * http://tools.ietf.org/html/rfc5869.
     *
     * Adapted from defuse/php-encryption
     * @ref https://github.com/defuse/php-encryption/blob/aa72b8bc85311dbcc56c080823f0be12d78331c7/src/Core.php#L116-L190
     *
     * @param string      $hash   Hash Function
     * @param string      $ikm    Initial Keying Material
     * @param int         $length How many bytes?
     * @param string      $info   What sort of key are we deriving?
     * @param string|null $salt
     * @return string
     *
     * @psalm-suppress MixedInferredReturnType This always returns a string!
     * @throws PasetoException
     * @throws TypeError
     */
    public static function HKDF(
        string $hash,
        string $ikm,
        int $length,
        string $info = '',
        string $salt = null
    ): string {
        static $nativeHKDF = null;
        if ($nativeHKDF === null) {
            $nativeHKDF = is_callable('hash_hkdf');
        }
        if ($nativeHKDF) {
            return hash_hkdf($hash, $ikm, $length, $info, $salt ?? '');
        }

        $digest_length = Binary::safeStrlen(
            hash($hash, '', true)
        );

        // Sanity-check the desired output length.
        if (empty($length) || $length < 0 || $length > 255 * $digest_length) {
            throw new PasetoException(
                'Bad output length requested of HKDF.',
                ExceptionCode::HKDF_BAD_LENGTH
            );
        }

        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (is_null($salt)) {
            $salt = str_repeat("\x00", $digest_length);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = hash_hmac($hash, $ikm, $salt, true);

        // HKDF-Expand:

        // This check is useless, but it serves as a reminder to the spec.
        if (Binary::safeStrlen($prk) < $digest_length) {
            throw new PasetoException(
                'An unexpected condition occurred in the HKDF internals',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }

        // T(0) = ''
        $t          = '';
        $last_block = '';
        for ($block_index = 1; Binary::safeStrlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = hash_hmac(
                $hash,
                $last_block . $info . pack('C', $block_index),
                $prk,
                true
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }

        // ORM = first L octets of T
        return Binary::safeSubstr($t, 0, $length);
    }

    /**
     * @param int $long
     * @return string
     */
    public static function longToBytes(int $long): string
    {
        return pack('P', $long);
    }

    /**
     * Format the Additional Associated Data.
     *
     * Prefix with the length (64-bit unsigned little-endian integer)
     * followed by each message. This provides a more explicit domain
     * separation between each piece of the message.
     *
     * Each length is masked with PHP_INT_MAX using bitwise AND (&) to
     * clear out the MSB of the total string length.
     *
     * @param string ...$pieces
     * @return string
     */
    public static function preAuthEncode(string ...$pieces): string
    {
        $accumulator = self::longToBytes(count($pieces) & PHP_INT_MAX);
        foreach ($pieces as $piece) {
            $len = Binary::safeStrlen($piece);
            $accumulator .= self::longToBytes($len & PHP_INT_MAX);
            $accumulator .= $piece;
        }
        return $accumulator;
    }

    /**
     * If a footer was included with the message, extract it.
     * Otherwise, return an empty string.
     *
     * @param string $payload
     * @return string
     *
     * @throws TypeError
     */
    public static function extractFooter(string $payload): string
    {
        /** @var array<int, string> $pieces */
        $pieces = explode('.', $payload);
        if (count($pieces) > 3) {
            return Base64UrlSafe::decode(array_pop($pieces));
        }
        return '';
    }

    /**
     * If a footer was included with the message, remove it.
     *
     * @param string $payload
     * @return string
     *
     * @throws TypeError
     */
    public static function removeFooter(string $payload): string
    {
        $pieces = explode('.', $payload);
        if (count($pieces) > 3) {
            return implode('.', array_slice($pieces, 0, 3));
        }
        return $payload;
    }

    /**
     * If a footer was included with the message, first verify that
     * it's equivalent to the one we expect, then remove it from the
     * token payload.
     *
     * @param string $payload
     * @param string $footer
     * @return string
     *
     * @throws PasetoException
     * @throws TypeError
     */
    public static function validateAndRemoveFooter(
        string $payload,
        string $footer = ''
    ): string {
        if (empty($footer)) {
            return $payload;
        }
        $footer = Base64UrlSafe::encodeUnpadded($footer);
        $payload_len = Binary::safeStrlen($payload);
        $footer_len = Binary::safeStrlen($footer) + 1;

        $trailing = Binary::safeSubstr(
            $payload,
            $payload_len - $footer_len,
            $footer_len
        );
        if (!hash_equals('.' . $footer, $trailing)) {
            throw new PasetoException(
                'Invalid message footer',
                ExceptionCode::FOOTER_MISMATCH_EXPECTED
            );
        }
        return Binary::safeSubstr($payload, 0, $payload_len - $footer_len);
    }

    /**
     * Wipe this value from memory.
     *
     * @param string $byRef
     * @return void
     * @param-out string $byRef
     *
     * @psalm-suppress ReferenceConstraintViolation
     */
    public static function wipe(string &$byRef): void
    {
        try {
            sodium_memzero($byRef);
        } catch (SodiumException $ex) {
            $byRef ^= $byRef;
        }
    }
}
