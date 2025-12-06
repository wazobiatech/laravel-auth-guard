<?php

namespace Wazobia\LaravelAuthGuard\Exceptions;  // <-- Correct namespace

use Exception;

class JwtAuthenticationException extends Exception  // <-- Correct class
{
    public function __construct(string $message = 'JWT Authentication failed', int $code = 401, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}