<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Parsing;

trait NonExpiringSupport
{
    /** @var bool $nonExpiring */
    protected bool $nonExpiring = false;

    /**
     * Do not set an expiration header by default.
     *
     * @param bool $nonExpiring
     * @return static
     */
    public function setNonExpiring(bool $nonExpiring): static
    {
        $this->nonExpiring = $nonExpiring;
        return $this;
    }
}
