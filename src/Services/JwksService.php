<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;

class JwksService
{
    private string $mercuryBaseUrl;
    private ?string $defaultProjectUuid;
    private string $sharedSecret;
    private string $cachePrefix;

    public function __construct(
        string $mercuryBaseUrl,
        ?string $defaultProjectUuid,
        string $sharedSecret
    ) {
        $this->mercuryBaseUrl = $mercuryBaseUrl;
        $this->defaultProjectUuid = $defaultProjectUuid;
        $this->sharedSecret = $sharedSecret;
        $this->cachePrefix = config('auth-guard.cache.prefix', 'auth_guard');
    }

    /**
     * Get public key for token verification
     */
    public function getPublicKey(string $token, ?string $projectUuid): string
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new JwtAuthenticationException('Invalid JWT format');
        }

        $header = json_decode(base64_decode($parts[0]), true);
        if (!isset($header['kid'])) {
            throw new JwtAuthenticationException('Missing key ID (kid) in token header');
        }

        $jwks = $this->fetchJWKS($projectUuid);
        
        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] === $header['kid']) {
                return $this->jwkToPem($key);
            }
        }

        throw new JwtAuthenticationException("Key {$header['kid']} not found in JWKS");
    }

    /**
     * Fetch JWKS from endpoint
     */
    private function fetchJWKS(?string $projectUuid): array
    {
        $projectUuid = $projectUuid ?: $this->defaultProjectUuid;
        if (!$projectUuid) {
            throw new JwtAuthenticationException(
                'No project UUID found in token and no default project UUID configured'
            );
        }

        $cacheKey = "{$this->cachePrefix}:jwks:{$projectUuid}";
        
        // Check cache (10 minutes)
        return Cache::remember($cacheKey, 600, function () use ($projectUuid) {
            $path = "auth/projects/{$projectUuid}/.well-known/jwks.json";
            $url = "{$this->mercuryBaseUrl}/{$path}";
            
           $timestamp = (string) (time() * 1000);
            $signature = hash_hmac(
                'sha256',
                'GET' . "/{$path}" . $timestamp,
                $this->sharedSecret
            );

            $timeout = config('auth-guard.mercury.timeout', 10);
            $response = Http::timeout($timeout)
                ->withHeaders([
                    'Accept' => 'application/json',
                    'User-Agent' => 'Laravel-AuthGuard/1.0',
                    'X-Timestamp' => $timestamp,
                    'X-Signature' => $signature,
                ])
                ->get($url);

            if (!$response->successful()) {
                throw new JwtAuthenticationException(
                    "JWKS endpoint returned {$response->status()}: {$response->body()}"
                );
            }

            $data = $response->json();
            if (!isset($data['keys'])) {
                throw new JwtAuthenticationException('Invalid JWKS response: missing keys');
            }

            // Normalize response
            if (!is_array($data['keys'])) {
                $data['keys'] = [$data['keys']];
            }

            return $data;
        });
    }

    /**
     * Convert JWK to PEM format
     */
    private function jwkToPem(array $jwk): string
    {
        if ($jwk['kty'] !== 'RSA') {
            throw new JwtAuthenticationException('Unsupported key type: ' . $jwk['kty']);
        }

        $n = $this->base64UrlDecode($jwk['n']);
        $e = $this->base64UrlDecode($jwk['e']);

        $rsa = \phpseclib3\Crypt\RSA::loadPublicKey([
            'n' => new \phpseclib3\Math\BigInteger($n, 256),
            'e' => new \phpseclib3\Math\BigInteger($e, 256),
        ]);

        return $rsa->toString('PKCS8');
    }

    /**
     * Base64 URL decode
     */
    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Create token cache key - matches Node.js implementation
     */
    private function createTokenCacheKey(string $rawToken): string
    {
        $tokenHash = substr(hash('sha256', $rawToken), 0, 32);
        return "validated_token:{$tokenHash}";
    }

    /**
     * Cache validated token payload
     */
    public function cacheValidatedToken(array $payload, string $rawToken): void
    {
        try {
            $cacheKey = $this->createTokenCacheKey($rawToken);
            $cacheExpiryTime = config('auth-guard.cache.token_expiry', 3600); // Default 1 hour
            
            $cacheData = [
                'payload' => $payload,
                'cached_at' => time(),
                'token_preview' => substr($rawToken, 0, 50) . '...', // For debugging
            ];

            Cache::put($cacheKey, $cacheData, $cacheExpiryTime);
        } catch (\Exception $e) {
            // Log error but don't throw - caching is not critical
        }
    }

    /**
     * Get cached validated token
     */
    public function getCachedToken(string $rawToken): ?array
    {
        try {
            $cacheKey = $this->createTokenCacheKey($rawToken);
            $cachedData = Cache::get($cacheKey);

            if ($cachedData && is_array($cachedData) && isset($cachedData['payload'])) {
                $payload = $cachedData['payload'];
                
                // Double check expiration (in case cache TTL and token TTL differ)
                $now = time();
                if (isset($payload['exp']) && $payload['exp'] < $now) {
                    // Token expired, remove from cache
                    Cache::forget($cacheKey);
                    return null;
                }
                
                return $payload;
            }

            return null;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Clear cache for a specific token
     */
    public function clearTokenCache(string $rawToken): bool
    {
        try {
            $cacheKey = $this->createTokenCacheKey($rawToken);
            return Cache::forget($cacheKey);
        } catch (\Exception $e) {
            return false;
        }
    }
}