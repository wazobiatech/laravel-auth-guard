<?php

namespace Wazobia\LaravelAuthGuard\Contracts;

interface ProjectAuthenticatable
{
    public function authenticate(string $apiKey, string $secret, string $service): array;
}