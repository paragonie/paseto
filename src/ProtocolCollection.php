<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2
};

use ParagonIE\Paseto\Exception\InvalidVersionException;

final class ProtocolCollection
{
    // Our built-in whitelist of protocol types is defined here.
    /**
     * @const array<int, string>
     */
    const WHITELIST = [
        Version1::class,
        Version2::class,
    ];

    /** @var array<int, ProtocolInterface> */
    private $protocols;

    /** @var array<string, ProtocolInterface> */
    static $headerLookup = [];

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
            if (!self::isValid($protocol)) {
                throw new InvalidVersionException('Disallowed or unsupported version');
            }
        }

        $this->protocols = $protocols;
    }

    /**
     * Does the collection contain the given protocol
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
     * @param string $header
     * @return ProtocolInterface
     * @throws InvalidVersionException
     */
    public static function protocolFromHeader(string $header): ProtocolInterface {
        if (empty(self::$headerLookup)) {
            /** @var string $protocolClass */
            foreach (self::WHITELIST as $protocolClass) {
                self::$headerLookup[$protocolClass::header()] = new $protocolClass;
            }
        }

        if (!\array_key_exists($header, self::$headerLookup)) {
            throw new InvalidVersionException('Disallowed or unsupported version');
        }

        return self::$headerLookup[$header];
    }

    /**
     * Get a collection of all supported protocols
     *
     * @return self
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
}
