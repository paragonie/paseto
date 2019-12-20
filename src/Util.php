<?php

declare(strict_types=1);

namespace ParagonIE\Paseto;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\Paseto\Exception\PasetoException;

/**
 * Class Util
 * @package ParagonIE\Paseto
 */
abstract class Util
{
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
     *
     * @return string
     * @psalm-suppress MixedInferredReturnType This always returns a string!
     * @throws PasetoException
     * @throws \TypeError
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
            $nativeHKDF = \is_callable('\\hash_hkdf');
        }
        if ($nativeHKDF) {
            /**
             * @psalm-suppress UndefinedFunction
             * This is wrapped in an is_callable() check.
             */
            return (string) \hash_hkdf($hash, $ikm, $length, $info, $salt ?? '');
        }

        $digest_length = Binary::safeStrlen(
            \hash_hmac($hash, '', '', true)
        );

        // Sanity-check the desired output length.
        if (empty($length) || $length < 0 || $length > 255 * $digest_length) {
            throw new PasetoException(
                'Bad output length requested of HKDF.'
            );
        }

        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (\is_null($salt)) {
            $salt = \str_repeat("\x00", $digest_length);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = \hash_hmac($hash, $ikm, $salt, true);

        // HKDF-Expand:

        // This check is useless, but it serves as a reminder to the spec.
        if (Binary::safeStrlen($prk) < $digest_length) {
            throw new PasetoException(
                'An unexpected condition occurred in the HKDF internals'
            );
        }

        // T(0) = ''
        $t          = '';
        $last_block = '';
        for ($block_index = 1; Binary::safeStrlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = \hash_hmac(
                $hash,
                $last_block . $info . \chr($block_index),
                $prk,
                true
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }

        // ORM = first L octets of T
        /** @var string $orm */
        $orm = Binary::safeSubstr($t, 0, $length);
        return (string) $orm;
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
        $accumulator = \ParagonIE_Sodium_Core_Util::store64_le(\count($pieces) & PHP_INT_MAX);
        foreach ($pieces as $piece) {
            $len = Binary::safeStrlen($piece);
            $accumulator .= \ParagonIE_Sodium_Core_Util::store64_le($len & PHP_INT_MAX);
            $accumulator .= $piece;
        }
        return $accumulator;
    }

    /**
     * If a footer was included with the message, first verify that
     * it's equivalent to the one we expect, then remove it from the
     * token payload.
     *
     * @param string $payload
     * @return string
     * @throws \TypeError
     */
    public static function extractFooter(string $payload): string
    {
        /** @var array<int, string> $pieces */
        $pieces = \explode('.', $payload);
        if (\count($pieces) > 3) {
            return Base64UrlSafe::decode((string) \array_pop($pieces));
        }
        return '';
    }

    /**
     * If a footer was included with the message, first verify that
     * it's equivalent to the one we expect, then remove it from the
     * token payload.
     *
     * @param string $payload
     * @return string
     * @throws \TypeError
     */
    public static function removeFooter(string $payload): string
    {
        $pieces = \explode('.', $payload);
        if (\count($pieces) > 3) {
            return \implode('.', \array_slice($pieces, 0, 3));
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
     * @throws PasetoException
     * @throws \TypeError
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
        if (!\hash_equals('.' . $footer, $trailing)) {
            throw new PasetoException('Invalid message footer');
        }
        return Binary::safeSubstr($payload, 0, $payload_len - $footer_len);
    }
}
