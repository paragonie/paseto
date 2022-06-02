<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\{
    Builder,
    JsonToken,
    Parser,
    ProtocolCollection,
    ProtocolInterface,
    Purpose
};
use ParagonIE\Paseto\Exception\{
    EncodingException,
    InvalidKeyException,
    InvalidPurposeException,
    InvalidVersionException,
    PasetoException,
    RuleViolation,
    SecurityException
};
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Keys\Version4\{
    AsymmetricSecretKey as V4AsymmetricSecretKey,
    SymmetricKey as V4SymmetricKey
};
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Rules\{
    FooterJSON,
    NotExpired
};
use PHPUnit\Framework\TestCase;
use Exception;
use TypeError;

/**
 * Class ParserTest
 * @package ParagonIE\Paseto\Tests
 */
class ParserTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testTypeSafety()
    {
        $keypair = sodium_crypto_sign_keypair();
        $publicKey = new AsymmetricPublicKey(sodium_crypto_sign_publickey($keypair), new Version4());

        // Let's encrypt a bad oken using the Ed25519 public key
        $badKey = new SymmetricKey(sodium_crypto_sign_publickey($keypair), new Version4());
        $badToken = Version4::encrypt('arbitrary test string', $badKey);

        try {
            new Parser(
                ProtocolCollection::v4(),
                Purpose::local(),
                $publicKey
            );
            $this->fail('Invalid key type was accepted by parser');
        } catch (PasetoException $ex) {
            $this->assertInstanceOf(InvalidKeyException::class, $ex);
        }

        // We have a v1.local parser, the token's version should be invalid:
        $parser = new Parser(
            ProtocolCollection::v3(),
            Purpose::local(),
            $badKey
        );
        try {
            $parser->parse($badToken);
            $this->fail('Invalid purpose was accepted by parser');
        } catch (PasetoException $ex) {
            $this->assertInstanceOf(InvalidVersionException::class, $ex);
        }

        // We have a V4.public parser, the token's purpose should be invalid:
        $parser = new Parser(
            ProtocolCollection::v4(),
            Purpose::public(),
            $publicKey
        );
        try {
            $parser->parse($badToken);
            $this->fail('Invalid purpose was accepted by parser');
        } catch (PasetoException $ex) {
            $this->assertInstanceOf(InvalidPurposeException::class, $ex);
        }
    }

    /**
     * @covers Parser::parse()
     *
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     * @throws PasetoException
     * @throws RuleViolation
     */
    public function testAuthToken(): void
    {
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY', new Version4());
        $V4key = new V4SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');

        $serialized = 'v4.local.3Atiz79AbVaUEEiOQfqn9TFl1quac0NDsvu_XAP5qb-8tVtXhgw-WUJJslrqnoTysNES5vl4JusgyU59TfaLKENLdfd0VXamZsnl9meNmMPxWbW4I2-dkgI3K5iINgakojSVZUOAlUfZT64S_VU-Tzm2-A8ObGh1_nwxV56gGWs7LkKUUg';
        $parser = (new Parser())
            ->setPurpose(Purpose::local())
            ->setKey($key);
        $V4parser = (new Parser())
            ->setPurpose(Purpose::local())
            ->setKey($V4key);


        $token = $parser->parse($serialized);
        $V4token = $V4parser->parse($serialized);

        $this->assertSame(
            '2039-01-01T00:00:00+00:00',
            $token->getExpiration()->format(\DateTime::ATOM),
            'Mismatched expiration date/time'
        );
        $this->assertSame(
            '2039-01-01T00:00:00+00:00',
            $V4token->getExpiration()->format(\DateTime::ATOM),
            'Mismatched expiration date/time'
        );
        $this->assertSame(
            'this is a signed message',
            $token->get('data'),
            'Custom claim not found'
        );

        $this->assertTrue($parser->validate($token));
        $this->assertTrue($parser->validate($V4token));
        $parser->addRule(new NotExpired(new \DateTime('2007-01-01T00:00:00')));
        $V4parser->addRule(new NotExpired(new \DateTime('2007-01-01T00:00:00')));
        $this->assertTrue($parser->validate($token));
        $this->assertTrue($V4parser->validate($token));

        $cloned = clone $parser;
        $cloned->addRule(new NotExpired(new \DateTime('2050-01-01T23:59:59')));
        $this->assertFalse($cloned->validate($token));

        try {
            $cloned->parse($serialized);
            $this->fail('Validation logic is being ignored.');
        } catch (PasetoException $ex) {
        }
        $parser->parse($serialized);

        $builder = (Builder::getLocal($key, new Version4(), $token));
        $V4builder = (Builder::getLocal($V4key, new Version4(), $V4token));
        // Switch to asymmetric-key crypto:
        $builder->setPurpose(Purpose::public())
                ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY', new Version4()), true);
        $V4builder->setPurpose(Purpose::public())
                ->setKey(new V4AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v4.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZGF0YSI6InRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSJ9rw4iANpORWlZ0BGwQlDe_No2ATE_GDBr1kRh_PADJlm0Myrj7ZfdlDMna_7gxae4qaJBgOc3jotNuWzW-cHlAg',
            (string) $builder,
            'Switching to signing caused a different signature'
        );
        $this->assertSame(
            'v4.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiZGF0YSI6InRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSJ9rw4iANpORWlZ0BGwQlDe_No2ATE_GDBr1kRh_PADJlm0Myrj7ZfdlDMna_7gxae4qaJBgOc3jotNuWzW-cHlAg',
            (string) $V4builder,
            'Switching to signing caused a different signature'
        );
    }

    /**
     * @param SymmetricKey $key
     * @param ProtocolInterface|null $v
     * @return string
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     * @throws PasetoException
     */
    protected function getDummyToken(SymmetricKey $key, ?ProtocolInterface $v = null): string
    {
        if (!$v) {
            $v = $key->getProtocol();
        }
        $builder = (new Builder())
            ->setVersion($v)
            ->setPurpose(Purpose::local())
            ->setKey($key)
            ->setClaims([
                'a' => 'b',
                'c' => 'd',
                'e' => [
                    'f' => 1,
                    'g' => [
                        'x' => 234
                    ],
                    'h' => 'ijk'
                ],
                'l' => json_encode(['pq' => 'rs'])
            ]);
        return $builder->toString();
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function testLimitedJsonClaimCount(): void
    {
        // Setup
        $V4key = new V4SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $dummy = $this->getDummyToken($V4key);

        $parser = (new Parser())
            ->setAllowedVersions(ProtocolCollection::V4())
            ->setPurpose(Purpose::local())
            ->setKey($V4key)
            ->setMaxClaimCount(16);

        // OK
        $this->assertInstanceOf(JsonToken::class, $parser->parse($dummy));

        $this->expectException(EncodingException::class);
        $parser->setMaxClaimCount(2)->parse($dummy);
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function testLimitedJsonClaimDepth(): void
    {
        // Setup
        $V4key = new V4SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $dummy = $this->getDummyToken($V4key);

        $parser = (new Parser())
            ->setAllowedVersions(ProtocolCollection::V4())
            ->setPurpose(Purpose::local())
            ->setKey($V4key)
            ->setMaxClaimDepth(16);

        // OK
        $this->assertInstanceOf(JsonToken::class, $parser->parse($dummy));

        $this->expectException(EncodingException::class);
        $parser->setMaxClaimDepth(3)->parse($dummy);
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function testLimitedJsonLength(): void
    {
        // Setup
        $V4key = new V4SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $dummy = $this->getDummyToken($V4key);

        $parser = (new Parser())
            ->setAllowedVersions(ProtocolCollection::V4())
            ->setPurpose(Purpose::local())
            ->setKey($V4key)
            ->setMaxJsonLength(8192);

        // OK
        $this->assertInstanceOf(JsonToken::class, $parser->parse($dummy));

        $this->expectException(EncodingException::class);
        $parser->setMaxJsonLength(16)->parse($dummy);
    }

    /**
     * @throws InvalidPurposeException
     * @throws PasetoException
     * @throws SecurityException
     */
    public function testExtractFooter(): void
    {
        $footers = [
            [
                'token' => 'v4.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0',
                'footer' => ''
            ],
            [
                'token' => 'v4.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz',
                'footer' => 'Cuon Alpinus'
            ],
            [
                'token' => 'v4.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
                'footer' => 'Paragon Initiative Enterprises'
            ]
        ];
        foreach ($footers as $f) {
            $this->assertSame(
                $f['footer'],
                Parser::extractFooter($f['token'])
            );
        }
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidPurposeException
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws Exception
     */
    public function testFooterJSON(): void
    {
        $expires = (new \DateTime('NOW'))
            ->add(new \DateInterval('P01D'));
        $key = SymmetricKey::generate(new Version4());
        $builder = (new Builder())
            ->setKey($key)
            ->setPurpose(Purpose::local())
            ->setVersion(new Version4())
            ->setExpiration($expires)
            ->setFooterArray(['a' => 1]);

        $parser = (new Parser(ProtocolCollection::v4(), Purpose::local(), $key))
            ->addRule(new FooterJSON(2, 4096, 4));

        // This should be OK:
        $in = $builder->toString();
        $this->assertInstanceOf(JsonToken::class, $parser->parse($in));

        $builder->setFooterArray(['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5]);
        $in = $builder->toString();
        try {
            $parser->parse($in);
            $this->fail('Failed to catch rule violation: too many keys');
        } catch (RuleViolation $ex) {
            $this->assertStringContainsString('Footer has too many keys', $ex->getMessage());
        }

        $builder->setFooterArray(['a' => ['b' => 2]]);
        $in = $builder->toString();
        try {
            $parser->parse($in);
            $this->fail('Failed to catch rule violation: too many keys');
        } catch (RuleViolation $ex) {
            $this->assertStringContainsString('Maximum stack depth exceeded', $ex->getMessage());
        }

        $parser = (new Parser(ProtocolCollection::v4(), Purpose::local(), $key))
            ->addRule(new FooterJSON(2, 8192, 128));

        $junk = [];
        for ($i = 0; $i < 257; ++$i) {
            $junk['a' . $i] = 0;
        }
        $builder->setFooterArray($junk);
        $in = $builder->toString();
        try {
            $parser->parse($in);
            $this->fail('Failed to catch rule violation: too many keys');
        } catch (RuleViolation $ex) {
            $this->assertStringContainsString('Footer has too many keys', $ex->getMessage());
        }
        $parser = (new Parser(ProtocolCollection::v4(), Purpose::local(), $key))
            ->addRule(new FooterJSON(2, 1024, 128));

        $junk = [];
        for ($i = 0; $i < 257; ++$i) {
            $junk['a' . $i] = 0;
        }
        $builder->setFooterArray($junk);
        $in = $builder->toString();
        try {
            $parser->parse($in);
            $this->fail('Failed to catch rule violation: too long');
        } catch (RuleViolation $ex) {
            $this->assertStringContainsString('Footer is too long', $ex->getMessage());
        }
    }

    /**
     * @throws PasetoException
     * @throws Exception
     * @throws TypeError
     */
    public function testTokenSignVerify(): void
    {
        $secretKey = new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY', new Version4());
        $publicKey = $secretKey->getPublicKey();
        $parser = new Parser(ProtocolCollection::default(), Purpose::public(), $publicKey);
        $tainted = 'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9_LCndxFrGmFDZbUAgixuWRPZv7J67DA6AT69KfJU2APR8J-APE1RxlKrdFyumd2h_GjcU4tdNgHlgZpuKf3BCQ';

        $token = $parser->parse($tainted);
        $this->assertInstanceOf(JsonToken::class, $token);
    }
}
