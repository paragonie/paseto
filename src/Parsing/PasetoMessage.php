<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Parsing;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Paseto\Exception\{
    SecurityException,
    InvalidVersionException,
    InvalidPurposeException
};

/**
 * Class PasetoMessage
 * @package ParagonIE\Paseto\Parsing
 */
final class PasetoMessage
{
    /** @var Header */
    private $header;

    /** @var string */
    private $payload;

    /** @var string */
    private $footer;

    /**
     * Parse a string into a deconstructed PasetoMessage object.
     *
     * @param string $tainted      Tainted user-provided string.
     *
     * @throws SecurityException
     * @throws InvalidVersionException
     * @throws InvalidPurposeException
     */
    public function __construct(string $tainted)
    {
        /** @var array<int, string> $pieces */
        $pieces = \explode('.', $tainted);
        $count = \count($pieces);
        if ($count < 3 || $count > 4) {
            throw new SecurityException('Truncated or invalid token');
        }

        $this->header = new Header($pieces[0], $pieces[1]);
        $this->payload = Base64UrlSafe::decode($pieces[2]);
        $this->footer = $count > 3 ? Base64UrlSafe::decode($pieces[3]) : '';
    }

    public function header(): Header
    {
        return $this->header;
    }

    public function payload(): string
    {
        return $this->payload;
    }

    public function footer(): string
    {
        return $this->footer;
    }
}
