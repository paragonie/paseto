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
 * @api
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
     * Strip all newlines (CR, LF) characters from a string.
     *
     * @param string $input
     * @return string
     */
    public static function stripNewlines(string $input): string
    {
        $bytes = SodiumUtil::stringToIntArray($input);
        $length = count($bytes);

        // First value is a dummy value, to overwrite it in constant-time
        $return = array_fill(0, $length + 1, 0);
        // Output index:
        $j = 1;

        // Now let's strip:
        for ($i = 0; $i < $length; ++$i) {
            $char = ($bytes[$i]);

            // Determine if we're stripping this character or not?
            $isCR = ((($char ^ 0x0d) - 1) >> 8) & 1;
            $isLF = ((($char ^ 0x0a) - 1) >> 8) & 1;
            $isNewline = $isCR | $isLF;

            // Set destination index: 0 if $isNewLine, $j otherwise
            $swap = -$isNewline;

            // if ($isNewLine), $dest === 0, else $dest === $j
            $dest = (~$swap & $j) ^ $swap;

            // Now let's overwrite the index (0 or $j) with $char:
            $return[$dest] = $char;

            // We only advance $j if we didn't encounter a newline:
            $j += 1 - $isNewline;
        }
        return SodiumUtil::intArrayToString(array_slice($return, 1, $j - 1));
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
