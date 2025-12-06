<?php

namespace Wazobia\LaravelAuthGuard\Exceptions;

use Exception;

class ProjectAuthenticationException extends Exception
{
    public function __construct(string $message = 'Project Authentication failed', int $code = 401, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}