<?php

namespace Wazobia\LaravelAuthGuard\Contracts;

interface JwtAuthenticatable
{
    public function authenticate(string $token): array;
    public function revokeToken(string $jti, int $ttl = null): void;
}