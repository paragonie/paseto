<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use Exception;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;
use TypeError;

class LucidityTest extends TestCase
{
    /**
     * @return array[]
     * @throws Exception
     */
    public function luciditySymmetric(): array
    {
        $v4_lk = Version4::generateSymmetricKey();
        $v4_sk = Version4::generateAsymmetricSecretKey();
        $v4_pk = $v4_sk->getPublicKey();

        $v3_lk = new SymmetricKey($v4_lk->raw(), new Version3);
        return [
            [
                new Version4,
                $v4_lk,
                $v4_pk
            ], [
                new Version4,
                $v4_lk,
                $v4_sk
            ], [
                new Version4,
                $v4_lk,
                $v3_lk
            ]
        ];
    }

    /**
     * @param Version3|Version4 $protocol
     * @param KeyInterface $validKey
     * @param KeyInterface $invalidKey
     *
     * @dataProvider luciditySymmetric
     * @throws Exception
     * @throws PasetoException
     */
    public function testLocalLucidity(
        $protocol,
        KeyInterface $validKey,
        KeyInterface $invalidKey
    ) {
        $dummy = '{"test":true}';
        $encode = $protocol::encrypt($dummy, $validKey);
        $decode = $protocol::decrypt($encode, $validKey);
        $this->assertSame($decode, $dummy);

        $this->expectException(PasetoException::class);
        try {
            $protocol::decrypt($encode, $invalidKey);
        } catch (TypeError $ex) {
            throw new PasetoException('TypeError', 0, $ex);
        }
    }
}
