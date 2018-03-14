<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    AsymmetricPublicKey,
    SymmetricKey
};
use ParagonIE\Paseto\Keys\Version1\{
    AsymmetricSecretKey as V1AsymmetricSecretKey,
    AsymmetricPublicKey as V1AsymmetricPublicKey,
    SymmetricKey as V1SymmetricKey
};
use ParagonIE\Paseto\Keys\Version2\{
    AsymmetricSecretKey as V2AsymmetricSecretKey,
    AsymmetricPublicKey as V2AsymmetricPublicKey,
    SymmetricKey as V2SymmetricKey
};
use ParagonIE\Paseto\Exception\InvalidPurposeException;

/**
 * Class Purpose
 * @package ParagonIE\Paseto
 */
final class Purpose
{
    /**
     * A whitelist of allowed values/modes. This simulates an enum.
     * @const array<int, string>
     */
    const WHITELIST = [
        'local',
        'public',
    ];

    /**
     * When sending, which type of key is expected for each mode.
     * @const array<string, string>
     */
    const EXPECTED_SENDING_KEYS = [
        'local'  => SymmetricKey::class,
        'public' => AsymmetricSecretKey::class,
    ];

    /**
     * Maps the fully-qualified class names for various SendingKey
     * objects to the expected purpose string.
     * @const array<string, string>
     */
    const SENDING_KEY_MAP = [
        SymmetricKey::class => 'local',
        V1SymmetricKey::class => 'local',
        V2SymmetricKey::class => 'local',
        AsymmetricSecretKey::class => 'public',
        V1AsymmetricSecretKey::class => 'public',
        V2AsymmetricSecretKey::class => 'public'
    ];

    /**
     * When receiving, which type of key is expected for each mode.
     * @const array<string, string>
     */
    const EXPECTED_RECEIVING_KEYS = [
        'local'  => SymmetricKey::class,
        'public' => AsymmetricPublicKey::class,
    ];

    /**
     * Maps the fully-qualified class names for various ReceivingKey
     * objects to the expected purpose string.
     * @const array<string, string>
     */
    const RECEIVING_KEY_MAP = [
        SymmetricKey::class => 'local',
        V1SymmetricKey::class => 'local',
        V2SymmetricKey::class => 'local',
        AsymmetricPublicKey::class => 'public',
        V1AsymmetricPublicKey::class => 'public',
        V2AsymmetricPublicKey::class => 'public'
    ];

    /**
     * Inverse of EXPECTED_SENDING_KEYS, evaluated and statically cached at
     * runtime.
     * @var array<string, string>
     */
    private static $sendingKeyToPurpose;

    /**
     * Inverse of EXPECTED_RECEIVING_KEYS, evaluated and statically cached at
     * runtime.
     * @var array<string, string>
     */
    private static $receivingKeyToPurpose;

    /**
     * @var string
     */
    private $purpose;

    /**
     * Allowed values in self::WHITELIST
     *
     * @param string $rawString
     * @throws InvalidPurposeException
     */
    public function __construct(string $rawString)
    {
        if (!self::isValid($rawString)) {
            throw new InvalidPurposeException('Unknown purpose: ' . $rawString);
        }

        $this->purpose = $rawString;
    }

    /**
     * Create a local purpose.
     *
     * @return self
     * @throws InvalidPurposeException
     */
    public static function local(): self
    {
        return new self('local');
    }

    /**
     * Create a public purpose.
     *
     * @return self
     * @throws InvalidPurposeException
     */
    public static function public(): self
    {
        return new self('public');
    }

    /**
     * Given a SendingKey, retrieve the corresponding Purpose.
     *
     * @param SendingKey $key
     *
     * @return self
     * @throws InvalidPurposeException
     */
    public static function fromSendingKey(SendingKey $key): self
    {
        if (empty(self::$sendingKeyToPurpose)) {
            /** @var array<string, string> */
            self::$sendingKeyToPurpose = self::SENDING_KEY_MAP;
        }

        return new self(self::$sendingKeyToPurpose[\get_class($key)]);
    }

    /**
     * Given a ReceivingKey, retrieve the corresponding Purpose.
     *
     * @param ReceivingKey $key
     *
     * @return self
     * @throws InvalidPurposeException
     */
    public static function fromReceivingKey(ReceivingKey $key): self
    {
        if (empty(self::$receivingKeyToPurpose)) {
            /** @var array<string, string> */
            self::$sendingKeyToPurpose = self::RECEIVING_KEY_MAP;
        }

        return new self(self::$receivingKeyToPurpose[\get_class($key)]);
    }

    /**
     * Compare the instance with $purpose in constant time.
     *
     * @param self $purpose
     * @return bool
     */
    public function equals(self $purpose): bool
    {
        return \hash_equals($purpose->purpose, $this->purpose);
    }

    /**
     * Determine whether new Purpose($rawString) will succeed prior to calling
     * it.
     *
     * @param string $rawString
     * @return bool
     */
    public static function isValid(string $rawString): bool
    {
        return \in_array($rawString, self::WHITELIST, true);
    }

    /**
     * Does the given $key correspond to the expected SendingKey for the
     * instance's mode?
     *
     * @param SendingKey $key
     * @return bool
     */
    public function isSendingKeyValid(SendingKey $key): bool
    {
        $expectedKeyType = $this->expectedSendingKeyType();
        return $key instanceof $expectedKeyType;
    }

    /**
     * Does the given $key correspond to the expected ReceivingKey for the
     * instance's mode?
     *
     * @param ReceivingKey $key
     * @return bool
     */
    public function isReceivingKeyValid(ReceivingKey $key): bool
    {
        $expectedKeyType = $this->expectedReceivingKeyType();
        return $key instanceof $expectedKeyType;
    }

    /**
     * Retrieve the class name as a string which corresponds to the expected
     * SendingKey for the instance's mode.
     *
     * @return string
     */
    public function expectedSendingKeyType(): string
    {
        /** @var string */
        $keyType = self::EXPECTED_SENDING_KEYS[$this->rawString()];

        return $keyType;
    }

    /**
     * Retrieve the class name as a string which corresponds to the expected
     * ReceivingKey for the instance's mode.
     *
     * @return string
     */
    public function expectedReceivingKeyType(): string
    {
        /** @var string */
        $keyType = self::EXPECTED_RECEIVING_KEYS[$this->rawString()];

        return $keyType;
    }

    /**
     * Retrieve the underlying raw string value for the instance's mode.
     *
     * @return string
     */
    public function rawString(): string
    {
        return $this->purpose;
    }
}
