<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Exception\SecurityException;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2
};
use ParagonIE\Paseto\Exception\InvalidVersionException;

/**
 * Class ProtocolCollection
 * @package ParagonIE\Paseto
 */
final class ProtocolCollection
{
    /**
     * Our built-in whitelist of protocol types is defined here.
     * @const array<int, class-string<ProtocolInterface>>
     */
    const WHITELIST = [
        Version1::class,
        Version2::class,
    ];

    /** @var array<int, ProtocolInterface> */
    private $protocols;

    /** @var array<string, ProtocolInterface> */
    private static $headerLookup = [];

    /**
     * @param ProtocolInterface ...$protocols
     * @throws \LogicException
     * @throws InvalidVersionException
     */
    public function __construct(ProtocolInterface ...$protocols)
    {
        if (empty($protocols)) {
            throw new \LogicException('At least one version is necessary');
        }

        /** @var ProtocolInterface $protocol */
        foreach ($protocols as $protocol) {
            self::throwIfUnsupported($protocol);
        }

        $this->protocols = $protocols;
    }

    /**
     * Does the collection contain the given protocol
     * @param ProtocolInterface $protocol
     *
     * @return bool
     */
    public function has(ProtocolInterface $protocol): bool
    {
        return \in_array($protocol, $this->protocols);
    }

    /**
     * Is the given protocol supported?
     *
     * @param ProtocolInterface $protocol
     * @return bool
     */
    public static function isValid(ProtocolInterface $protocol): bool
    {
        return \in_array(\get_class($protocol), self::WHITELIST, true);
    }

    /**
     * Throws if the given protocol is unsupported
     *
     * @param ProtocolInterface $protocol
     * @throws InvalidVersionException
     * @return void
     */
    public static function throwIfUnsupported(ProtocolInterface $protocol)
    {
        if (!self::isValid($protocol)) {
            throw new InvalidVersionException(
                'Unsupported version: ' . $protocol::header()
            );
        }
    }

    /**
     * @param string $headerPart
     * @return ProtocolInterface
     * @throws InvalidVersionException
     * @psalm-suppress UndefinedClass  A BC break introduced in Psalm v1.0.2
     *                                 stopped respecting what we were doing.
     */
    public static function protocolFromHeaderPart(string $headerPart): ProtocolInterface {
        if (empty(self::$headerLookup)) {
            foreach (self::WHITELIST as $protocolClass) {
                self::$headerLookup[$protocolClass::header()] = new $protocolClass;
            }
        }

        if (!\array_key_exists($headerPart, self::$headerLookup)) {
            throw new InvalidVersionException('Disallowed or unsupported version');
        }

        return self::$headerLookup[$headerPart];
    }

    /**
     * Get a collection of all supported protocols
     *
     * @return self
     * @throws InvalidVersionException
     */
    public static function default(): self
    {
        return new self(...\array_map(
            function (string $p): ProtocolInterface {
                /** @var ProtocolInterface */
                $protocol = new $p;
                return $protocol;
            },
            self::WHITELIST
        ));
    }

    /**
     * Get a collection containing protocol version 1.
     *
     * @return self
     * @throws InvalidVersionException
     * @throws SecurityException
     */
    public static function v1(): self
    {
        return new self(new Version1);
    }

    /**
     * Get a collection containing protocol version 2.
     *
     * @return self
     * @throws InvalidVersionException
     */
    public static function v2(): self
    {
        return new self(new Version2);
    }
}
