<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\{
    Builder,
    Exception\InvalidKeyException,
    Exception\PasetoException,
    JsonToken,
    Parser,
    ProtocolInterface,
    Purpose,
    ReceivingKey,
    ReceivingKeyRing,
    SendingKey,
    SendingKeyRing
};
use PHPUnit\Framework\TestCase;
use Exception;
use TypeError;

/**
 * @covers Builder
 * @covers Parser
 * @covers ReceivingKeyRing
 * @covers SendingKeyRing
 */
class MultiKeyTest extends TestCase
{
    /** @var ProtocolInterface[] $versions */
    protected array $versions;

    public function setUp(): void
    {
        $this->versions = [new Version3, new Version4];
    }

    /**
     * @throws PasetoException
     * @throws InvalidKeyException
     * @throws Exception
     */
    protected function getReceivingKeyring(ProtocolInterface $v): array
    {
        $sk = AsymmetricSecretKey::generate($v);
        $rKeyring = (new ReceivingKeyRing())
            ->setVersion($v)
            ->addKey('gandalf0', SymmetricKey::generate($v))
            ->addKey('legolas1', $sk->getPublicKey());
        return [$sk, $rKeyring];
    }

    /**
     * @throws InvalidKeyException
     * @throws PasetoException
     */
    protected function getSendingKeyring(ProtocolInterface $v): SendingKeyRing
    {
        return (new SendingKeyRing())
            ->setVersion($v)
            ->addKey('gandalf0', SymmetricKey::generate($v))
            ->addKey('legolas1', AsymmetricSecretKey::generate($v));
    }

    /**
     * @throws PasetoException
     */
    public function testKeyRings(): void
    {
        foreach ($this->versions as $v) {
            $this->doReceivingTest($v);
            $this->doSendingTest($v);
        }
    }

    /**
     * @param ProtocolInterface $v
     * @throws PasetoException
     */
    protected function doReceivingTest(ProtocolInterface $v): void
    {
        /**
         * @var AsymmetricSecretKey $sk
         * @var ReceivingKeyRing $keyring
         */
        list($sk, $keyring) = $this->getReceivingKeyring($v);

        // These need to pass the type checks
        $localKey = $keyring->fetchKey('gandalf0');
        $this->assertInstanceOf(SymmetricKey::class, $localKey);
        $localBuilder = Builder::getLocal($localKey);
        $publicBuilder = Builder::getPublic($sk);

        // Set some things
        $localBuilder->setSubject('foo');
        $publicBuilder->setSubject('foo');
        $localBuilder->setFooterArray(['kid' => 'gandalf0']);
        $publicBuilder->setFooterArray(['kid' => 'legolas1']);

        // Build a token
        $localToken = $localBuilder->toString();
        $publicToken = $publicBuilder->toString();

        // Now let's set up a parser:
        $localParser = Parser::getLocalWithKeyring($keyring);
        $publicParser = Parser::getPublicWithKeyring($keyring);

        // Do the tokens we built parse?
        $parseLocal  = $localParser->parse($localToken);
        $parsePublic = $publicParser->parse($publicToken);
        $this->assertInstanceOf(JsonToken::class, $parseLocal);
        $this->assertInstanceOf(JsonToken::class, $parsePublic);
        $this->assertSame('foo', $parseLocal->getSubject());
        $this->assertSame('foo', $parsePublic->getSubject());

        // Now let's get crafty:
        $fail = false;
        try {
            $localParser->parse($publicToken);
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted invalid token");

        $fail = false;
        try {
            $publicParser->parse($localToken);
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted invalid token");

        // Remember these? Let's swap their values:
        $localBuilder->setFooterArray(['kid' => 'legolas1']);
        $publicBuilder->setFooterArray(['kid' => 'gandalf0']);
        $badLocalToken = $localBuilder->toString();
        $badPublicToken = $publicBuilder->toString();

        // Now these should both fail because kid fetches the wrong key:
        $fail = false;
        try {
            $localParser->parse($badLocalToken);
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted token with invalid key ID");
        $fail = false;
        try {
            $publicParser->parse($badPublicToken);
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted token with invalid key ID");

        // Finally, let's set an invalid version (but correct purposE):
        $header = $v::header() === 'v1' ? 'v4' : 'v1';
        $badLocalToken = $header . Binary::safeSubstr($localToken, 2);
        $badPublicToken = $header . Binary::safeSubstr($publicToken, 2);

        $fail = false;
        try {
            $localParser->parse($badLocalToken);
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted invalid token version");

        $fail = false;
        try {
            $publicParser->parse($badPublicToken);
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted invalid token version");
    }

    /**
     * @param ProtocolInterface $v
     * @throws PasetoException
     */
    protected function doSendingTest(ProtocolInterface $v): void
    {
        $keyring = $this->getSendingKeyring($v);
        $localBuilder = Builder::getLocalWithKeyRing($keyring, $v);
        $publicBuilder = Builder::getPublicWithKeyRing($keyring, $v);
        $localBuilder->setSubject('foo');
        $publicBuilder->setSubject('foo');

        $localBuilder->setFooterArray(['kid' => 'gandalf0']);
        $publicBuilder->setFooterArray(['kid' => 'legolas1']);

        // The absence of an exception being thrown is sufficient proof.
        $localToken = $localBuilder->toString();
        $publicToken = $publicBuilder->toString();

        // Now let's switch their Key IDs
        $localBuilder->setFooterArray(['kid' => 'legolas1']);
        $publicBuilder->setFooterArray(['kid' => 'gandalf0']);

        // Assert failure
        $fail = false;
        try {
            $localBuilder->toString();
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted an invalid key id");

        $fail = false;
        try {
            $publicBuilder->toString();
        } catch (PasetoException $ex) {
            $fail = true;
        }
        $this->assertTrue($fail, "Parser accepted an invalid key id");

        // Let's initialize a Parser with a congruent keyring
        $keyring2 = $keyring->deriveReceivingKeyRing();
        $localParser = Parser::getLocalWithKeyRing($keyring2);
        $publicParser = Parser::getPublicWithKeyRing($keyring2);

        // Ensure the token we generated parses
        $parseLocal = $localParser->parse($localToken);
        $parsePublic = $publicParser->parse($publicToken);
        $this->assertInstanceOf(JsonToken::class, $parseLocal);
        $this->assertInstanceOf(JsonToken::class, $parsePublic);
        $this->assertSame('foo', $parseLocal->getSubject());
        $this->assertSame('foo', $parsePublic->getSubject());
    }

    /**
     * @return array[]
     * @throws Exception
     */
    public function typeCheckData(): array
    {
        $v3_lk = Version3::generateSymmetricKey();
        $v3_sk = Version3::generateAsymmetricSecretKey();
        $v3_pk = $v3_sk->getPublicKey();
        $v4_lk = Version4::generateSymmetricKey();
        $v4_sk = Version4::generateAsymmetricSecretKey();
        $v4_pk = $v4_sk->getPublicKey();

        return [
            // Receiving keys, version 3
            [
                (new ReceivingKeyRing())->setVersion(new Version3()),
                $v3_lk,
                false
            ], [
                (new ReceivingKeyRing())->setVersion(new Version3()),
                $v3_sk,
                true
            ], [
                (new ReceivingKeyRing())->setVersion(new Version3()),
                $v3_pk,
                false
            ],

            // Receiving keys, version 4
            [
                (new ReceivingKeyRing())->setVersion(new Version4()),
                $v4_lk,
                false
            ], [
                (new ReceivingKeyRing())->setVersion(new Version4()),
                $v4_sk,
                true
            ], [
                (new ReceivingKeyRing())->setVersion(new Version4()),
                $v4_pk,
                false
            ],

            // Sending keys, version 3
            [
                (new SendingKeyRing())->setVersion(new Version3()),
                $v3_lk,
                false
            ], [
                (new SendingKeyRing())->setVersion(new Version3()),
                $v3_sk,
                false
            ], [
                (new SendingKeyRing())->setVersion(new Version3()),
                $v3_pk,
                true
            ],
            // Sending keys, version 4
            [
                (new SendingKeyRing())->setVersion(new Version4()),
                $v4_lk,
                false
            ], [
                (new SendingKeyRing())->setVersion(new Version4()),
                $v4_sk,
                false
            ], [
                (new SendingKeyRing())->setVersion(new Version4()),
                $v4_pk,
                true
            ],

            // Type confusion: Receiving, version 4, with v3 key
            [
                (new ReceivingKeyRing())->setVersion(new Version4()),
                $v3_lk,
                true
            ], [
                (new ReceivingKeyRing())->setVersion(new Version4()),
                $v3_sk,
                true
            ], [
                (new ReceivingKeyRing())->setVersion(new Version4()),
                $v3_pk,
                true
            ],
            // Type confusion: Receiving, version 3, with v4 key
            [
                (new ReceivingKeyRing())->setVersion(new Version3()),
                $v4_lk,
                true
            ], [
                (new ReceivingKeyRing())->setVersion(new Version3()),
                $v4_sk,
                true
            ], [
                (new ReceivingKeyRing())->setVersion(new Version3()),
                $v4_pk,
                true
            ],

            // Type confusion: Sending, version 4, with v3 key
            [
                (new SendingKeyRing())->setVersion(new Version4()),
                $v3_lk,
                true
            ], [
                (new SendingKeyRing())->setVersion(new Version4()),
                $v3_sk,
                true
            ], [
                (new SendingKeyRing())->setVersion(new Version4()),
                $v3_pk,
                true
            ],

            // Type confusion: Sending, version 3, with v4 key
            [
                (new SendingKeyRing())->setVersion(new Version3()),
                $v4_lk,
                true
            ], [
                (new SendingKeyRing())->setVersion(new Version3()),
                $v4_sk,
                true
            ], [
                (new SendingKeyRing())->setVersion(new Version3()),
                $v4_pk,
                true
            ],

            // Version 3 -- purpose checks -- receiving
            [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version3()),
                $v3_lk,
                false
            ], [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version3()),
                $v3_pk,
                true
            ], [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version3()),
                $v3_lk,
                true
            ], [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version3()),
                $v3_pk,
                false
            ],

            // Version 4 -- purpose checks -- receiving
            [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version4()),
                $v4_lk,
                false
            ], [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version4()),
                $v4_pk,
                true
            ], [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version4()),
                $v4_lk,
                true
            ], [
                (new ReceivingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version4()),
                $v4_pk,
                false
            ],

            // Version 3 -- purpose checks -- sending
            [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version3()),
                $v3_lk,
                false
            ], [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version3()),
                $v3_sk,
                true
            ], [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version3()),
                $v3_lk,
                true
            ], [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version3()),
                $v3_sk,
                false
            ],

            // Version 4 -- purpose checks -- sending
            [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version4()),
                $v4_lk,
                false
            ], [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::local())
                    ->setVersion(new Version4()),
                $v4_sk,
                true
            ], [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version4()),
                $v4_lk,
                true
            ], [
                (new SendingKeyRing())
                    ->setPurpose(Purpose::public())
                    ->setVersion(new Version4()),
                $v4_sk,
                false
            ]
        ];
    }

    /**
     * @dataProvider typeCheckData
     *
     * @param SendingKeyRing|ReceivingKeyRing $keyring
     * @param SendingKey|ReceivingKey $key
     * @param bool $expectFail
     *
     * @psalm-suppress PossiblyInvalidArgument
     * @throws PasetoException
     */
    public function testTypeChecks(
        SendingKeyRing|ReceivingKeyRing$keyring,
        SendingKey|ReceivingKey $key,
        bool $expectFail
    ): void {
        if ($expectFail) {
            $this->expectException(PasetoException::class);
        }
        try {
            $keyring->addKey('foo', $key);
            $received = $keyring->fetchKey('foo');
            $this->assertInstanceOf(get_class($key), $received);
        } catch (TypeError $ex) {
            throw new PasetoException('TypeError', 0, $ex);
        }
    }
}
