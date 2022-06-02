<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

trait TestTrait
{
    protected function assertIsStringType($var): void
    {
        $this->assertTrue(gettype($var) === 'string');
    }
}
