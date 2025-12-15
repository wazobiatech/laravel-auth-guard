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
     * Debug logging helper - only logs when JWT_DEBUG_LOGGING_ENABLED=true
     */
    private function debugLog(string $message, array $context = []): void
    {
        if (config('auth-guard.debug_logging.enabled', env('JWT_DEBUG_LOGGING_ENABLED', false))) {
            \Log::info("[JWT-DEBUG] {$message}", $context);
        }
    }

    /**
     * Error logging helper - always logs errors regardless of debug flag
     */
    private function errorLog(string $message, array $context = []): void
    {
        \Log::error("[JWT-ERROR] {$message}", $context);
    }

    /**
     * Get public key for USER JWT verification (per-project key set)
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

        if (!$projectUuid) {
            try {
                $payload = json_decode(base64_decode($parts[1]), true);
                if (is_array($payload) && isset($payload['project_uuid'])) {
                    $projectUuid = $payload['project_uuid'];
                }
            } catch (\Exception $e) {
                // Silently continue if payload can't be decoded
            }
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
     * Fetch per-project JWKS from Mercury
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
        
        return Cache::remember($cacheKey, 600, function () use ($projectUuid) {
            $path = "auth/project/.well-known/jwks.json";
            $url = "{$this->mercuryBaseUrl}/{$path}";
            
            $timestamp = (string) round(time() * 1000);
            $signature = hash_hmac(
                'sha256',
                'GET/' . $path . $timestamp,
                $this->sharedSecret
            );

            $timeout = config('auth-guard.mercury.timeout', 10);
            
            $this->debugLog('JWKS Request Starting', [
                'url' => $url,
                'timeout' => $timeout,
                'project_uuid' => $projectUuid,
                'mercury_base_url' => $this->mercuryBaseUrl,
                'path' => $path,
                'timestamp' => $timestamp,
                'signature_preview' => substr($signature, 0, 20) . '...',
                'shared_secret_preview' => substr($this->sharedSecret, 0, 10) . '...'
            ]);
            
            try {
                $this->debugLog('JWKS HTTP Request Initiating', [
                    'url' => $url,
                    'method' => 'GET',
                    'headers' => [
                        'Accept' => 'application/json',
                        'User-Agent' => 'Laravel-AuthGuard/1.0',
                        'X-Timestamp' => $timestamp,
                        'X-Signature' => substr($signature, 0, 20) . '...',
                    ]
                ]);
                
                $response = Http::timeout($timeout)
                    ->withHeaders([
                        'Accept' => 'application/json',
                        'User-Agent' => 'Laravel-AuthGuard/1.0',
                        'X-Timestamp' => $timestamp,
                        'X-Signature' => $signature,
                    ])
                    ->get($url);
                
                $this->debugLog('JWKS HTTP Response Received', [
                    'url' => $url,
                    'status_code' => $response->status(),
                    'headers' => $response->headers(),
                    'body_length' => strlen($response->body()),
                    'body_preview' => substr($response->body(), 0, 300),
                    'successful' => $response->successful()
                ]);
            
            } catch (\Exception $e) {
                $this->errorLog('JWKS HTTP Request Exception', [
                    'url' => $url,
                    'error_message' => $e->getMessage(),
                    'exception_class' => get_class($e),
                    'exception_code' => $e->getCode(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'trace_preview' => array_slice($e->getTrace(), 0, 3)
                ]);
                throw new JwtAuthenticationException(
                    "JWKS request to {$url} failed: " . $e->getMessage()
                );
            }
            
            if (!$response->successful()) {
                throw new JwtAuthenticationException(
                    "JWKS endpoint returned {$response->status()}: {$response->body()}"
                );
            }

            $data = $response->json();
            if (!isset($data['keys'])) {
                throw new JwtAuthenticationException('Invalid JWKS response: missing keys');
            }

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
     * Get public key for PROJECT TOKEN verification (global project key set)
     */
    public function getProjectTokenPublicKey(string $token): string
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new JwtAuthenticationException('Invalid project token format');
        }

        $header = json_decode(base64_decode($parts[0]), true);
        if (!isset($header['kid'])) {
            throw new JwtAuthenticationException('Missing key ID (kid) in project token header');
        }

        $jwks = $this->fetchGlobalProjectJWKS();
        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] === $header['kid']) {
                return $this->jwkToPem($key);
            }
        }

        throw new JwtAuthenticationException("Key {$header['kid']} not found in global project JWKS");
    }

    /**
     * Fetch global project JWKS used for project token verification (cached ~5 hours)
     */
    private function fetchGlobalProjectJWKS(): array
    {
        $cacheKey = "{$this->cachePrefix}:jwks:project_global";
        return Cache::remember($cacheKey, 18000, function () {
            $path = 'auth/project/.well-known/jwks.json';
            $url = "{$this->mercuryBaseUrl}/{$path}";

            $timestamp = (string) round(time() * 1000);
            $signature = hash_hmac(
                'sha256',
                'GET/' . $path . $timestamp,
                $this->sharedSecret
            );

            $timeout = config('auth-guard.mercury.timeout', 10);
            
            $this->debugLog('Global Project JWKS Request Starting', [
                'url' => $url,
                'timeout' => $timeout,
                'mercury_base_url' => $this->mercuryBaseUrl,
                'path' => $path,
                'cache_key' => $cacheKey,
                'timestamp' => $timestamp,
                'signature_preview' => substr($signature, 0, 20) . '...'
            ]);
            
            try {
                $this->debugLog('Global Project JWKS HTTP Request Initiating', [
                    'url' => $url,
                    'method' => 'GET',
                    'headers' => [
                        'Accept' => 'application/json',
                        'User-Agent' => 'Laravel-AuthGuard/1.0',
                        'X-Timestamp' => $timestamp,
                        'X-Signature' => substr($signature, 0, 20) . '...',
                    ]
                ]);
                
                $response = Http::timeout($timeout)
                    ->withHeaders([
                        'Accept' => 'application/json',
                        'User-Agent' => 'Laravel-AuthGuard/1.0',
                        'X-Timestamp' => $timestamp,
                        'X-Signature' => $signature,
                    ])
                    ->get($url);
                
                $this->debugLog('Global Project JWKS HTTP Response Received', [
                    'url' => $url,
                    'status_code' => $response->status(),
                    'headers' => $response->headers(),
                    'body_length' => strlen($response->body()),
                    'body_preview' => substr($response->body(), 0, 300),
                    'successful' => $response->successful()
                ]);
                
            } catch (\Exception $e) {
                $this->errorLog('Global Project JWKS HTTP Request Exception', [
                    'url' => $url,
                    'error_message' => $e->getMessage(),
                    'exception_class' => get_class($e),
                    'exception_code' => $e->getCode(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'trace_preview' => array_slice($e->getTrace(), 0, 3)
                ]);
                throw new JwtAuthenticationException(
                    "Global project JWKS request to {$url} failed: " . $e->getMessage()
                );
            }
            
            if (!$response->successful()) {
                throw new JwtAuthenticationException(
                    "Global project JWKS endpoint returned {$response->status()}: {$response->body()}"
                );
            }

            $data = $response->json();
            if (!isset($data['keys'])) {
                throw new JwtAuthenticationException('Invalid global project JWKS response: missing keys');
            }
            if (!is_array($data['keys'])) {
                $data['keys'] = [$data['keys']];
            }
            return $data;
        });
    }

    /**
     * Base64 URL decode helper
     */
    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}