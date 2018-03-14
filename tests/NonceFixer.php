<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Keys\SymmetricKey;

abstract class NonceFixer {
    public static function buildUnitTestEncrypt(ProtocolInterface $protocol): \Closure {
        return static function (
            string $data,
            SymmetricKey $key,
            string $footer = '',
            string $nonceForUnitTesting = ''
        ) use ($protocol): string {
            return $protocol::__encrypt($data, $key, $footer, $nonceForUnitTesting);
        };
    }

    public static function buildSetExplicitNonce(): \Closure {
        return function (string $nonce) {
            /** @noinspection Annotator */
            $this->unitTestEncrypter = static function (ProtocolInterface $protocol) use ($nonce) {
                $class = new class {
                    private static $nonce;
                    private static $protocol;

                    public static function setNonce(string $nonce)
                    {
                        self::$nonce = $nonce;
                    }

                    public static function setProtocol(ProtocolInterface $protocol)
                    {
                        self::$protocol = $protocol;
                    }

                    public static function encrypt(
                        string $data,
                        SymmetricKey $key,
                        string $footer = ''
                    ): string {
                        return NonceFixer::buildUnitTestEncrypt(self::$protocol)->bindTo(null, self::$protocol)(
                            $data,
                            $key,
                            $footer,
                            self::$nonce
                        );
                    }
                };

                $class::setNonce($nonce);
                $class::setProtocol($protocol);

                return $class;
            };
        };
    }
}
