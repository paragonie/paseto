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
     * PasetoMessage constructor.
     *
     * @param Header $header
     * @param string $payload
     * @param string $footer
     */
    public function __construct(Header $header, string $payload, string $footer)
    {
        $this->header  = $header;
        $this->payload = $payload;
        $this->footer  = $footer;
    }

    /**
     * Parse a string into a deconstructed PasetoMessage object.
     *
     * @param string $tainted      Tainted user-provided string.
     * @return self
     *
     * @throws SecurityException
     * @throws InvalidVersionException
     * @throws InvalidPurposeException
     * @throws \TypeError
     */
    public static function fromString(string $tainted): self
    {
        /** @var array<int, string> $pieces */
        $pieces = \explode('.', $tainted);
        $count = \count($pieces);
        if ($count < 3 || $count > 4) {
            throw new SecurityException('Truncated or invalid token');
        }

        $header = new Header($pieces[0], $pieces[1]);
        $payload = Base64UrlSafe::decode($pieces[2]);
        $footer = $count > 3 ? Base64UrlSafe::decode($pieces[3]) : '';

        return new self($header, $payload, $footer);
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

    /**
     * @return string
     * @throws \TypeError
     */
    public function toString(): string
    {
        $message =  $this->header->toString()
            . Base64UrlSafe::encodeUnpadded($this->payload)
        ;

        if ($this->footer === '') {
            return $message;
        }

        return $message . "." . Base64UrlSafe::encodeUnpadded($this->footer);
    }
}
