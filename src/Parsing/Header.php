<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Parsing;

use ParagonIE\Paseto\{
    Exception\ExceptionCode,
    Exception\InvalidPurposeException,
    Exception\InvalidVersionException,
    Exception\SecurityException,
    ProtocolInterface,
    ProtocolCollection,
    Purpose
};
use function count, explode;

/**
 * Class Header
 * @package ParagonIE\Paseto\Parsing
 */
final class Header
{
    private ProtocolInterface $protocol;
    private Purpose $purpose;

    /**
     * Validate message header strings
     *
     * @param string $protocol      Tainted user-provided string.
     * @param string $purpose      Tainted user-provided string.
     *
     * @throws InvalidPurposeException
     * @throws InvalidVersionException
     */
    public function __construct(string $protocol, string $purpose)
    {
        $this->protocol = ProtocolCollection::protocolFromHeaderPart($protocol);
        $this->purpose  = new Purpose($purpose);
    }

    /**
     * Parse a string into a deconstructed Header object.
     *
     * @param string $tainted      Tainted user-provided string.
     * @return self
     *
     * @throws SecurityException
     */
    public static function fromString(string $tainted): self
    {
        $pieces = explode('.', $tainted);
        $count = count($pieces);
        if ($count !== 3 or $pieces[2] !== '') {
            // we expect "version.purpose." format
            throw new SecurityException(
                'Truncated or invalid header',
                ExceptionCode::INVALID_HEADER
            );
        }

        return new Header($pieces[0], $pieces[1]);
    }

    public function protocol(): ProtocolInterface
    {
        return $this->protocol;
    }

    public function purpose(): Purpose
    {
        return $this->purpose;
    }

    public function toString(): string
    {
        return $this->protocol->header() . '.' .
            $this->purpose->rawString() . '.';
    }
}
