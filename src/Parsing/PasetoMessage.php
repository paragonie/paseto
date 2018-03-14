<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Parsing;

use ParagonIE\Paseto\Exception\{
    SecurityException,
    InvalidVersionException,
    InvalidPurposeException
};

final class PasetoMessage
{
    /**
     * @var Header
     */

    private $header;
    /**
     * @var string
     */
    private $encodedPayload;

    /**
     * @var string
     */
    private $encodedFooter;

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
        $this->encodedPayload = $pieces[2];
        $this->encodedFooter = $count > 3 ? $pieces[3] : '';
    }

    public function header(): Header
    {
        return $this->header;
    }

    public function encodedPayload(): string
    {
        return $this->encodedPayload;
    }

    public function encodedFooter(): string
    {
        return $this->encodedFooter;
    }
}
