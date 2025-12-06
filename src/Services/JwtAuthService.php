<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;
use Wazobia\LaravelAuthGuard\Contracts\JwtAuthenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtAuthService implements JwtAuthenticatable
{
    private JwksService $jwksService;
    private string $expectedIssuer;
    private int $cacheTtl;
    private string $cachePrefix;

    public function __construct(
        JwksService $jwksService,
        string $expectedIssuer,
        int $cacheTtl = 900
    ) {
        $this->jwksService = $jwksService;
        $this->expectedIssuer = $expectedIssuer;
        $this->cacheTtl = $cacheTtl;
        $this->cachePrefix = config('auth-guard.cache.prefix', 'auth_guard');
    }

    /**
     * Authenticate JWT token
     */
    public function authenticate(string $token): array
    {
        // Check cache first
        $cachedUser = $this->getCachedToken($token);
        if ($cachedUser) {
            $this->log('JWT cache hit', ['user' => $cachedUser['email']]);
            return $cachedUser;
        }

        // Decode token to get project UUID
        $projectUuid = $this->extractProjectUuid($token);
        
        // Get public key from JWKS
        $publicKey = $this->jwksService->getPublicKey($token, $projectUuid);
        
        // Validate token
        $user = $this->validateToken($token, $publicKey);
        
        // Cache the result
        $this->cacheToken($token, $user);
        
        $this->log('JWT authenticated', ['user' => $user['email']]);
        
        return $user;
    }

    /**
     * Extract project UUID from token
     */
    private function extractProjectUuid(string $token): ?string
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return null;
            }

            $payload = json_decode(base64_decode($parts[1]), true);
            return $payload['project_uuid'] ?? null;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Validate JWT token
     */
    private function validateToken(string $token, string $publicKey): array
    {
        try {
            $algorithm = config('auth-guard.jwt.algorithm', 'RS512');
            JWT::$leeway = config('auth-guard.jwt.leeway', 0);
            
            $decoded = JWT::decode($token, new Key($publicKey, $algorithm));
            $payload = (array) $decoded;

            // Validate structure
            if (!isset($payload['sub']) || !is_object($payload['sub'])) {
                throw new JwtAuthenticationException('Invalid JWT payload structure');
            }

            $sub = (array) $payload['sub'];
            if (!isset($sub['uuid'])) {
                throw new JwtAuthenticationException('Missing user UUID in token');
            }

            // Validate issuer
            if ($payload['iss'] !== $this->expectedIssuer) {
                throw new JwtAuthenticationException(
                    "Invalid issuer. Expected: {$this->expectedIssuer}, Got: {$payload['iss']}"
                );
            }

            // Check token revocation
            if (isset($payload['jti'])) {
                $this->checkTokenRevocation($payload['jti']);
            }

            return [
                'uuid' => $sub['uuid'],
                'email' => $sub['email'] ?? '',
                'name' => $sub['name'] ?? '',
                // 'raw_payload' => $payload,
            ];
        } catch (\Exception $e) {
            throw new JwtAuthenticationException(
                'Token validation failed: ' . $e->getMessage()
            );
        }
    }

    /**
     * Check if token is revoked
     */
    private function checkTokenRevocation(string $jti): void
    {
        $cacheKey = "{$this->cachePrefix}:revoked_token:{$jti}";
        if (Cache::has($cacheKey)) {
            throw new JwtAuthenticationException('Token has been revoked');
        }
    }

    /**
     * Cache validated token
     */
    private function cacheToken(string $token, array $user): void
    {
        try {
            $tokenHash = substr(base64_encode($token), 0, 32);
            $cacheKey = "{$this->cachePrefix}:validated_token:{$tokenHash}";
            Cache::put($cacheKey, $user, $this->cacheTtl);
        } catch (\Exception $e) {
            $this->log('Failed to cache token', ['error' => $e->getMessage()], 'warning');
        }
    }

    /**
     * Get cached token
     */
    private function getCachedToken(string $token): ?array
    {
        try {
            $tokenHash = substr(base64_encode($token), 0, 32);
            $cacheKey = "{$this->cachePrefix}:validated_token:{$tokenHash}";
            return Cache::get($cacheKey);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Revoke a token
     */
    public function revokeToken(string $jti, int $ttl = null): void
    {
        $cacheKey = "{$this->cachePrefix}:revoked_token:{$jti}";
        Cache::put($cacheKey, true, $ttl ?? $this->cacheTtl);
        $this->log('Token revoked', ['jti' => $jti]);
    }

    /**
     * Log message if logging is enabled
     */
    private function log(string $message, array $context = [], string $level = 'info'): void
    {
        if (config('auth-guard.logging.enabled', true)) {
            Log::channel(config('auth-guard.logging.channel', 'stack'))
                ->$level("[LaravelAuthGuard] {$message}", $context);
        }
    }
}