<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

interface KeyRingInterface
{
    public function fetchKey(string $keyId = ''): KeyInterface;
}
