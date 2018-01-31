<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Traits;

/**
 * Trait RegisteredClaims
 * @package ParagonIE\Paseto\Traits
 */
trait RegisteredClaims
{
    /**
     * @var array<string, string>
     *
     * Adopted from JWT for usability
     */
    public $registeredClaims = [
        'iss' => 'Issuer',
        'sub' => 'Subject',
        'aud' => 'Audience',
        'exp' => 'Expiration',
        'nbf' => 'Not Before',
        'iat' => 'Issued At',
        'jti' => 'Token Identifier'
    ];
}
