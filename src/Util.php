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
    implode,
    pack,
    preg_replace,
    preg_match_all,
    sodium_memzero,
    str_replace;
use ParagonIE_Sodium_Core_Util as SodiumUtil;

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
        if ($stripped === null) {
            throw new EncodingException('Invalid JSON string provided', ExceptionCode::INVALID_JSON);
        }

        // Strip everything out of quotes:
        $stripped = preg_replace('#"[^"]+"([:,}\]])#', '$1', $stripped);
        if ($stripped === null) {
            throw new EncodingException('Invalid JSON string provided', ExceptionCode::INVALID_JSON);
        }

        // Remove everything that isn't a map or list definition
        $stripped = preg_replace('#[^\[\]{}]#', '', $stripped);

        $previous = '';
        $depth = 1;
        /** @psalm-suppress RiskyTruthyFalsyComparison */
        while (!empty($stripped) && $stripped !== $previous) {
            $previous = $stripped;
            // Remove pairs of tokens
            $stripped = str_replace(['[]', '{}'], [], $stripped);
            ++$depth;
        }
        /** @psalm-suppress RiskyTruthyFalsyComparison */
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
        $keyCount = preg_match_all('#[^\\\]":#', $json);
        if ($keyCount === false) {
            throw new EncodingException('Invalid JSON string provided', ExceptionCode::INVALID_JSON);
        }

        return $keyCount;
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
        $pieces = explode('.', $payload);
        if (count($pieces) > 3) {
            return Base64UrlSafe::decodeNoPadding(array_pop($pieces));
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
     * Return a substring of $input that terminates before the first instance of $delim.
     *
     * Unlike the built-in C function, our algorithm is constant-time.
     *
     * @param string $input
     * @param string $delim
     * @return string|false
     */
    public static function stopAtDelimiter(string $input, string $delim): string|false
    {
        $inLength = SodiumUtil::strlen($input);
        $dLen = SodiumUtil::strlen($delim);
        if ($inLength < $dLen) {
            return false;
        }

        // Final value for this string
        $terminate = 0;
        // We want to work with bytes:
        $bytes = SodiumUtil::stringToIntArray($input);
        $d = SodiumUtil::stringToIntArray($delim);
        $max = $inLength - $dLen;
        $found = 0;

        // Iterate over all of $bytes, compare window,
        for ($i = 0; $i < $max; ++$i) {
            $cmp = 0;
            for ($j = 0; $j < $dLen; ++$j) {
                $cmp |= ($bytes[$i + $j] ^ $d[$j]);
            }
            // 1 if $cmp === 0, 0x00 otherwise
            $result = (($cmp - 1) >> 8) & 1;
            /*
             * $found === 0
             *    $terminate = $terminate
             * $result === 1, $found === 0
             *   $terminate = $i
             * $result === 0, $found === 0
             *   $terminate = $terminate
             */
            $terminate = ($terminate & $found) ^ (~$found & (((-$result) & $i)));
            $found |= -$result;
        }
        $terminate = ($terminate & $found) ^ (($inLength) & ~$found);
        return SodiumUtil::intArrayToString(
            array_slice($bytes, 0, $terminate)
        );
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
     * @param-out ?string $byRef
     */
    public static function wipe(string &$byRef): void
    {
        try {
            sodium_memzero($byRef);
        } catch (SodiumException $ex) {
            $byRef ^= $byRef;
            unset($byRef);
        }
    }
}
