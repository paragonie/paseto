<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Exception\{
    ExceptionCode,
    InvalidVersionException,
    SecurityException
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use function array_key_exists,
    array_map,
    get_class,
    in_array;
use LogicException;
use TypeError;

/**
 * Class ProtocolCollection
 * @package ParagonIE\Paseto
 */
final class ProtocolCollection
{
    /**
     * Our built-in allow-list of protocol types is defined here.
     *
     * @const array<int, class-string<ProtocolInterface>>
     * @var array<int, class-string<ProtocolInterface>>
     */
    const ALLOWED = [
        Version3::class,
        Version4::class,
    ];

    /** @var array<array-key, ProtocolInterface> */
    private array $protocols;

    /** @var array<string, ProtocolInterface> */
    private static array $headerLookup = [];

    /**
     * @param ProtocolInterface ...$protocols
     *
     * @throws LogicException
     * @throws InvalidVersionException
     */
    public function __construct(ProtocolInterface ...$protocols)
    {
        if (empty($protocols)) {
            throw new LogicException(
                'At least one version is necessary',
                ExceptionCode::BAD_VERSION
            );
        }

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
        return in_array($protocol, $this->protocols);
    }

    /**
     * Is the given protocol supported?
     *
     * @param ProtocolInterface $protocol
     * @return bool
     */
    public static function isValid(ProtocolInterface $protocol): bool
    {
        return in_array(get_class($protocol), self::ALLOWED, true);
    }

    /**
     * Throws if the given protocol is unsupported
     *
     * @param ProtocolInterface $protocol
     * @return void
     *
     * @throws InvalidVersionException
     */
    public static function throwIfUnsupported(ProtocolInterface $protocol)
    {
        if (!self::isValid($protocol)) {
            throw new InvalidVersionException(
                'Unsupported version: ' . $protocol::header(),
                ExceptionCode::BAD_VERSION
            );
        }
    }

    /**
     * Return the PASETO protocol version for a given header snippet
     *
     * @param string $headerPart
     *
     * @return ProtocolInterface
     * @throws InvalidVersionException
     */
    public static function protocolFromHeaderPart(string $headerPart): ProtocolInterface {
        if (empty(self::$headerLookup)) {
            foreach (self::ALLOWED as $protocolClass) {
                if (!method_exists($protocolClass, 'header')) {
                    throw new TypeError(
                        "Object {$protocolClass} does not have a header() method",
                        ExceptionCode::IMPOSSIBLE_CONDITION
                    );
                }
                self::$headerLookup[$protocolClass::header()] = new $protocolClass;
            }
        }

        if (!array_key_exists($headerPart, self::$headerLookup)) {
            throw new InvalidVersionException(
                'Disallowed or unsupported version',
                ExceptionCode::BAD_VERSION
            );
        }

        return self::$headerLookup[$headerPart];
    }

    /**
     * Get a collection of all supported protocols
     *
     * @return self
     *
     * @throws InvalidVersionException
     */
    public static function default(): self
    {
        return new self(...array_map(
            function (string $p): ProtocolInterface {
                return new $p;
            },
            self::ALLOWED
        ));
    }

    /**
     * Get a collection containing protocol version 1.
     *
     * @return self
     *
     * @throws InvalidVersionException
     * @throws SecurityException
     *
     * @deprecated See Version3 instead.
     */
    public static function v1(): self
    {
        throw new InvalidVersionException("Version 1 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * Get a collection containing protocol version 2.
     *
     * @return self
     *
     * @throws InvalidVersionException
     *
     * @deprecated See Version4 instead.
     */
    public static function v2(): self
    {
        throw new InvalidVersionException("Version 2 was removed", ExceptionCode::OBSOLETE_PROTOCOL);
    }

    /**
     * Get a collection containing protocol version 3.
     *
     * @return self
     *
     * @throws InvalidVersionException
     */
    public static function v3(): self
    {
        return new self(new Version3);
    }

    /**
     * Get a collection containing protocol version 4.
     *
     * @return self
     *
     * @throws InvalidVersionException
     */
    public static function v4(): self
    {
        return new self(new Version4);
    }
}
