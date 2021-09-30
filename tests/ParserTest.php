<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\EncodingException;
use ParagonIE\Paseto\Exception\InvalidKeyException;
use ParagonIE\Paseto\Exception\InvalidPurposeException;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Exception\RuleViolation;
use ParagonIE\Paseto\JsonToken;
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Keys\Version2\{
    AsymmetricSecretKey as V2AsymmetricSecretKey,
    SymmetricKey as V2SymmetricKey
};
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Rules\FooterJSON;
use ParagonIE\Paseto\Rules\NotExpired;
use PharIo\Version\Version;
use PHPUnit\Framework\TestCase;

/**
 * Class ParserTest
 * @package ParagonIE\Paseto\Tests
 */
class ParserTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testTypeSafety()
    {
        $keypair = sodium_crypto_sign_keypair();
        $publicKey = new AsymmetricPublicKey(sodium_crypto_sign_publickey($keypair), new Version2());

        // Let's encrypt a bad oken using the Ed25519 public key
        $badKey = new SymmetricKey(sodium_crypto_sign_publickey($keypair), new Version2());
        $badToken = Version2::encrypt('arbitrary test string', $badKey);

        try {
            new Parser(
                ProtocolCollection::v2(),
                Purpose::local(),
                $publicKey
            );
            $this->fail('Invalid key type was accepted by parser');
        } catch (PasetoException $ex) {
            $this->assertInstanceOf(InvalidKeyException::class, $ex);
        }

        // We have a v1.local parser, the token's version should be invalid:
        $parser = new Parser(
            ProtocolCollection::v1(),
            Purpose::local(),
            $badKey
        );
        try {
            $parser->parse($badToken);
            $this->fail('Invalid purpose was accepted by parser');
        } catch (PasetoException $ex) {
            $this->assertInstanceOf(InvalidVersionException::class, $ex);
        }

        // We have a v2.public parser, the token's purpose should be invalid:
        $parser = new Parser(
            ProtocolCollection::v2(),
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
     * @throws PasetoException
     * @throws \Exception
     * @throws \ParagonIE\Paseto\Exception\RuleViolation
     * @throws \TypeError
     */
    public function testAuthToken()
    {
        $key = new SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY', new Version2());
        $v2key = new V2SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        // $nonce = crypto_generichash('Paragon Initiative Enterprises, LLC', '', 24);
        $nonce = Hex::decode('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b');

        $serialized = 'v2.local.3fNxan9FHjedQRSONRnT7Ce_KhhpB0NrlHwAGsCb54x0FhrjBfeNN4uPHFiO5H0iPCZSjwfEkkfiGeYpE6KAfr1Zm3G-VTe4lcXtgDyKATYULT-zLPfshRqisk4n7EbGufWuqilYvYXMCiYbaA';
        $parser = (new Parser())
            ->setPurpose(Purpose::local())
            ->setKey($key);
        $v2parser = (new Parser())
            ->setPurpose(Purpose::local())
            ->setKey($v2key);

        $token = $parser->parse($serialized);
        $v2token = $v2parser->parse($serialized);

        $builder = (Builder::getLocal($key, new Version2(), $token));
        NonceFixer::buildSetExplicitNonce(false)->bindTo($builder, $builder)($nonce);

        $v2builder = (Builder::getLocal($v2key, new Version2(), $v2token));
        NonceFixer::buildSetExplicitNonce(false)->bindTo($v2builder, $v2builder)($nonce);

        $this->assertSame(
            '2039-01-01T00:00:00+00:00',
            $token->getExpiration()->format(\DateTime::ATOM),
            'Mismatched expiration date/time'
        );
        $this->assertSame(
            '2039-01-01T00:00:00+00:00',
            $v2token->getExpiration()->format(\DateTime::ATOM),
            'Mismatched expiration date/time'
        );
        $this->assertSame(
            'this is a signed message',
            $token->get('data'),
            'Custom claim not found'
        );
        $this->assertSame($serialized, (string) $builder);
        $this->assertSame($serialized, (string) $v2builder);

        $this->assertTrue($parser->validate($token));
        $this->assertTrue($parser->validate($v2token));
        $parser->addRule(new NotExpired(new \DateTime('2007-01-01T00:00:00')));
        $v2parser->addRule(new NotExpired(new \DateTime('2007-01-01T00:00:00')));
        $this->assertTrue($parser->validate($token));
        $this->assertTrue($v2parser->validate($token));

        $cloned = clone $parser;
        $cloned->addRule(new NotExpired(new \DateTime('2050-01-01T23:59:59')));
        $this->assertFalse($cloned->validate($token));

        try {
            $cloned->parse($serialized);
            $this->fail('Validation logic is being ignored.');
        } catch (PasetoException $ex) {
        }
        $parser->parse($serialized);

        // Switch to asymmetric-key crypto:
        $builder->setPurpose(Purpose::public())
                ->setKey(new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY', new Version2()), true);
        $v2builder->setPurpose(Purpose::public())
                ->setKey(new V2AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY'), true);
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9BAOu3lUQMVHnBcPSkuORw51yiGGQ3QFUMoJO9U0gRAdAOPQEZFsd0YM_GZuBcmrXEOD1Re-Ila8vfPrfM5S6Ag',
            (string) $builder,
            'Switching to signing caused a different signature'
        );
        $this->assertSame(
            'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9BAOu3lUQMVHnBcPSkuORw51yiGGQ3QFUMoJO9U0gRAdAOPQEZFsd0YM_GZuBcmrXEOD1Re-Ila8vfPrfM5S6Ag',
            (string) $v2builder,
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
        $v2key = new V2SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $dummy = $this->getDummyToken($v2key);

        $parser = (new Parser())
            ->setAllowedVersions(ProtocolCollection::v2())
            ->setPurpose(Purpose::local())
            ->setKey($v2key)
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
        $v2key = new V2SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $dummy = $this->getDummyToken($v2key);

        $parser = (new Parser())
            ->setAllowedVersions(ProtocolCollection::v2())
            ->setPurpose(Purpose::local())
            ->setKey($v2key)
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
        $v2key = new V2SymmetricKey('YELLOW SUBMARINE, BLACK WIZARDRY');
        $dummy = $this->getDummyToken($v2key);

        $parser = (new Parser())
            ->setAllowedVersions(ProtocolCollection::v2())
            ->setPurpose(Purpose::local())
            ->setKey($v2key)
            ->setMaxJsonLength(8192);

        // OK
        $this->assertInstanceOf(JsonToken::class, $parser->parse($dummy));

        $this->expectException(EncodingException::class);
        $parser->setMaxJsonLength(16)->parse($dummy);
    }

    /**
     * @throws PasetoException
     * @throws \ParagonIE\Paseto\Exception\InvalidPurposeException
     * @throws \ParagonIE\Paseto\Exception\SecurityException
     * @throws \TypeError
     */
    public function testExtractFooter()
    {
        $footers = [
            [
                'token' => 'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0',
                'footer' => ''
            ],
            [
                'token' => 'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz',
                'footer' => 'Cuon Alpinus'
            ],
            [
                'token' => 'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
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
     */
    public function testFooterJSON()
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
     * @throws \Exception
     * @throws \TypeError
     */
    public function testTokenSignVerify()
    {
        $secretKey = new AsymmetricSecretKey('YELLOW SUBMARINE, BLACK WIZARDRY', new Version2());
        $publicKey = $secretKey->getPublicKey();
        $parser = new Parser(ProtocolCollection::default(), Purpose::public(), $publicKey);
        $tainted = 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAzOS0wMS0wMVQwMDowMDowMCswMDowMCJ9BAOu3lUQMVHnBcPSkuORw51yiGGQ3QFUMoJO9U0gRAdAOPQEZFsd0YM_GZuBcmrXEOD1Re-Ila8vfPrfM5S6Ag';

        $token = $parser->parse($tainted);
        $this->assertInstanceOf(JsonToken::class, $token);
    }
}
