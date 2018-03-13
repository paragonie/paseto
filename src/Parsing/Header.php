<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Parsing;

use ParagonIE\Paseto\{
    ProtocolInterface,
    ProtocolCollection,
    Purpose
};

final class Header
{
    /**
     * @var ProtocolInterface
     */
    private $protocol;

    /**
     * @var Purpose
     */
    private $purpose;

    /**
     * Validate message header strings
     *
     * @param string $protocol      Tainted user-provided string.
     * @param string $purpose      Tainted user-provided string.
     *
     * @throws InvalidVersionException
     * @throws InvalidPurposeException
     */
    public function __construct(string $protocol, string $purpose)
    {
        $this->protocol = ProtocolCollection::protocolFromHeaderPart($protocol);
        $this->purpose  = new Purpose($purpose);
    }

    public function protocol(): ProtocolInterface
    {
        return $this->protocol;
    }

    public function purpose(): Purpose
    {
        return $this->purpose;
    }
}
