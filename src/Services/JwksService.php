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
     * Get public key for USER JWT verification (per-project key set)
     */
    public function getPublicKey(string $token, ?string $projectUuid): string
    {
        \Log::info('JWT_AUTH: Starting user JWT verification', [
            'token_length' => strlen($token),
            'project_uuid' => $projectUuid,
            'method' => 'getPublicKey'
        ]);

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            \Log::error('JWT_ERROR: Invalid JWT format', [
                'parts_count' => count($parts),
                'expected' => 3
            ]);
            throw new JwtAuthenticationException('Invalid JWT format');
        }

        \Log::debug('JWT_PARSE: Token split into parts', [
            'header_length' => strlen($parts[0]),
            'payload_length' => strlen($parts[1]),
            'signature_length' => strlen($parts[2])
        ]);

        $header = json_decode(base64_decode($parts[0]), true);
        if (!isset($header['kid'])) {
            \Log::error('JWT_ERROR: Missing key ID in token header', [
                'header_keys' => array_keys($header ?? [])
            ]);
            throw new JwtAuthenticationException('Missing key ID (kid) in token header');
        }

        \Log::info('JWT_HEADER: Token header decoded', [
            'algorithm' => $header['alg'] ?? 'unknown',
            'key_id' => $header['kid'],
            'token_type' => $header['typ'] ?? 'unknown'
        ]);

        if (!$projectUuid) {
            \Log::debug('JWT_PARSE: Extracting project UUID from token payload');
            try {
                $payload = json_decode(base64_decode($parts[1]), true);
                if (is_array($payload) && isset($payload['project_uuid'])) {
                    $projectUuid = $payload['project_uuid'];
                    \Log::info('JWT_PAYLOAD: Project UUID extracted from token', [
                        'project_uuid' => $projectUuid,
                        'issuer' => $payload['iss'] ?? 'unknown',
                        'audience' => $payload['aud'] ?? 'unknown',
                        'expires_at' => isset($payload['exp']) ? date('Y-m-d H:i:s', $payload['exp']) : 'unknown'
                    ]);
                } else {
                    \Log::warning('JWT_WARNING: No project_uuid found in token payload', [
                        'payload_keys' => is_array($payload) ? array_keys($payload) : 'invalid_payload'
                    ]);
                }
            } catch (\Exception $e) {
                \Log::error('JWT_ERROR: Failed to decode token payload', [
                    'error' => $e->getMessage()
                ]);
            }
        }

        $jwks = $this->fetchJWKS($projectUuid);
        
        \Log::info('JWT_KEYS: Starting key matching process', [
            'required_kid' => $header['kid'],
            'available_keys' => count($jwks['keys']),
            'project_uuid' => $projectUuid
        ]);

        foreach ($jwks['keys'] as $index => $key) {
            \Log::debug('JWT_KEY_CHECK: Checking key', [
                'key_index' => $index,
                'key_id' => $key['kid'] ?? 'missing',
                'key_type' => $key['kty'] ?? 'unknown',
                'algorithm' => $key['alg'] ?? 'unknown',
                'is_match' => ($key['kid'] ?? '') === $header['kid']
            ]);

            if ($key['kid'] === $header['kid']) {
                \Log::info('JWT_SUCCESS: Key match found, converting to PEM', [
                    'matched_key_id' => $key['kid'],
                    'key_type' => $key['kty'],
                    'key_use' => $key['use'] ?? 'unknown'
                ]);
                return $this->jwkToPem($key);
            }
        }

        \Log::error('JWT_ERROR: Key not found in JWKS', [
            'required_kid' => $header['kid'],
            'available_kids' => array_column($jwks['keys'], 'kid'),
            'jwks_key_count' => count($jwks['keys'])
        ]);
        throw new JwtAuthenticationException("Key {$header['kid']} not found in JWKS");
    }

    /**
     * Fetch per-project JWKS from Mercury
     */
    private function fetchJWKS(?string $projectUuid): array
    {
        $projectUuid = $projectUuid ?: $this->defaultProjectUuid;
        if (!$projectUuid) {
            \Log::error('JWT_ERROR: No project UUID available', [
                'provided_uuid' => $projectUuid,
                'default_uuid' => $this->defaultProjectUuid
            ]);
            throw new JwtAuthenticationException(
                'No project UUID found in token and no default project UUID configured'
            );
        }

        \Log::info('JWT_JWKS: Starting JWKS fetch process', [
            'project_uuid' => $projectUuid,
            'mercury_base_url' => $this->mercuryBaseUrl
        ]);

        $cacheKey = "{$this->cachePrefix}:jwks:{$projectUuid}";
        
        \Log::debug('JWT_CACHE: Checking cache for JWKS', [
            'cache_key' => $cacheKey,
            'cache_ttl' => 600
        ]);

        return Cache::remember($cacheKey, 600, function () use ($projectUuid) {
            \Log::info('JWT_CACHE_MISS: Cache miss, fetching from Mercury', [
                'project_uuid' => $projectUuid
            ]);

            $path = "auth/project/.well-known/jwks.json";
            $url = "{$this->mercuryBaseUrl}/{$path}";
            
            $timestamp = (string) round(time() * 1000);
            $stringToSign = 'GET/' . $path . $timestamp;
            $signature = hash_hmac(
                'sha256',
                $stringToSign,
                $this->sharedSecret
            );

            \Log::info('JWT_REQUEST: Preparing JWKS request', [
                'url' => $url,
                'path' => $path,
                'timestamp' => $timestamp,
                'string_to_sign' => $stringToSign,
                'signature_length' => strlen($signature)
            ]);

            $timeout = config('auth-guard.mercury.timeout', 10);
            $headers = [
                'Accept' => 'application/json',
                'User-Agent' => 'Laravel-AuthGuard/1.0',
                'X-Timestamp' => $timestamp,
                'X-Signature' => $signature,
            ];

            \Log::debug('JWT_REQUEST_HEADERS: Request headers prepared', [
                'headers' => array_keys($headers),
                'timeout' => $timeout
            ]);

            $response = Http::timeout($timeout)
                ->withHeaders($headers)
                ->get($url);

            \Log::info('JWT_RESPONSE: Per-project JWKS response received', [
                'status' => $response->status(),
                'success' => $response->successful(),
                'response_size' => strlen($response->body()),
                'content_type' => $response->header('Content-Type'),
                'project_uuid' => $projectUuid,
                'url' => $url
            ]);
            
            if (!$response->successful()) {
                \Log::error('JWT_ERROR: JWKS request failed', [
                    'status' => $response->status(),
                    'reason' => $response->reason(),
                    'body' => $response->body(),
                    'url' => $url,
                    'headers_sent' => array_keys($headers)
                ]);
                throw new JwtAuthenticationException(
                    "JWKS endpoint returned {$response->status()}: {$response->body()}"
                );
            }

            $data = $response->json();
            
            \Log::debug('JWT_RESPONSE_PARSE: Parsing JWKS response', [
                'response_keys' => is_array($data) ? array_keys($data) : 'invalid_json',
                'has_keys_array' => isset($data['keys'])
            ]);

            if (!isset($data['keys'])) {
                \Log::error('JWT_ERROR: Invalid JWKS response structure', [
                    'response_keys' => is_array($data) ? array_keys($data) : 'not_array',
                    'response_sample' => is_array($data) ? array_slice($data, 0, 3, true) : $data
                ]);
                throw new JwtAuthenticationException('Invalid JWKS response: missing keys');
            }

            if (!is_array($data['keys'])) {
                \Log::warning('JWT_WARNING: Converting single key to array', [
                    'original_type' => gettype($data['keys'])
                ]);
                $data['keys'] = [$data['keys']];
            }

            \Log::info('JWT_JWKS_SUCCESS: JWKS fetched and cached successfully', [
                'keys_count' => count($data['keys']),
                'key_ids' => array_column($data['keys'], 'kid'),
                'project_uuid' => $projectUuid
            ]);

            return $data;
        });
    }

    /**
     * Convert JWK to PEM format
     */
    private function jwkToPem(array $jwk): string
    {
        \Log::debug('JWT_PEM: Converting JWK to PEM format', [
            'key_id' => $jwk['kid'] ?? 'unknown',
            'key_type' => $jwk['kty'] ?? 'unknown',
            'key_use' => $jwk['use'] ?? 'unknown',
            'algorithm' => $jwk['alg'] ?? 'unknown'
        ]);

        if ($jwk['kty'] !== 'RSA') {
            \Log::error('JWT_ERROR: Unsupported key type for PEM conversion', [
                'provided_type' => $jwk['kty'],
                'supported_type' => 'RSA'
            ]);
            throw new JwtAuthenticationException('Unsupported key type: ' . $jwk['kty']);
        }

        $n = $this->base64UrlDecode($jwk['n']);
        $e = $this->base64UrlDecode($jwk['e']);

        \Log::debug('JWT_PEM_DECODE: JWK components decoded', [
            'modulus_length' => strlen($n),
            'exponent_length' => strlen($e)
        ]);

        try {
            $rsa = \phpseclib3\Crypt\RSA::loadPublicKey([
                'n' => new \phpseclib3\Math\BigInteger($n, 256),
                'e' => new \phpseclib3\Math\BigInteger($e, 256),
            ]);

            $pem = $rsa->toString('PKCS8');
            
            \Log::info('JWT_PEM_SUCCESS: JWK successfully converted to PEM', [
                'key_id' => $jwk['kid'] ?? 'unknown',
                'pem_length' => strlen($pem)
            ]);

            return $pem;
        } catch (\Exception $e) {
            \Log::error('JWT_ERROR: Failed to convert JWK to PEM', [
                'key_id' => $jwk['kid'] ?? 'unknown',
                'error' => $e->getMessage(),
                'error_class' => get_class($e)
            ]);
            throw new JwtAuthenticationException('Failed to convert JWK to PEM: ' . $e->getMessage());
        }
    }

    /**
     * Get public key for PROJECT TOKEN verification (global project key set)
     */
    public function getProjectTokenPublicKey(string $token): string
    {
        \Log::info('JWT_AUTH: Starting project token verification', [
            'token_length' => strlen($token),
            'method' => 'getProjectTokenPublicKey'
        ]);

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            \Log::error('JWT_ERROR: Invalid project token format', [
                'parts_count' => count($parts),
                'expected' => 3
            ]);
            throw new JwtAuthenticationException('Invalid project token format');
        }

        \Log::debug('JWT_PARSE: Project token split into parts', [
            'header_length' => strlen($parts[0]),
            'payload_length' => strlen($parts[1]),
            'signature_length' => strlen($parts[2])
        ]);

        $header = json_decode(base64_decode($parts[0]), true);
        if (!isset($header['kid'])) {
            \Log::error('JWT_ERROR: Missing key ID in project token header', [
                'header_keys' => array_keys($header ?? [])
            ]);
            throw new JwtAuthenticationException('Missing key ID (kid) in project token header');
        }

        \Log::info('JWT_HEADER: Project token header decoded', [
            'algorithm' => $header['alg'] ?? 'unknown',
            'key_id' => $header['kid'],
            'token_type' => $header['typ'] ?? 'unknown'
        ]);

        $jwks = $this->fetchGlobalProjectJWKS();
        
        \Log::info('JWT_KEYS: Starting global project key matching', [
            'required_kid' => $header['kid'],
            'available_keys' => count($jwks['keys'])
        ]);

        foreach ($jwks['keys'] as $index => $key) {
            \Log::debug('JWT_KEY_CHECK: Checking global project key', [
                'key_index' => $index,
                'key_id' => $key['kid'] ?? 'missing',
                'key_type' => $key['kty'] ?? 'unknown',
                'is_match' => ($key['kid'] ?? '') === $header['kid']
            ]);

            if ($key['kid'] === $header['kid']) {
                \Log::info('JWT_SUCCESS: Global project key match found', [
                    'matched_key_id' => $key['kid'],
                    'key_type' => $key['kty']
                ]);
                return $this->jwkToPem($key);
            }
        }

        \Log::error('JWT_ERROR: Key not found in global project JWKS', [
            'required_kid' => $header['kid'],
            'available_kids' => array_column($jwks['keys'], 'kid'),
            'jwks_key_count' => count($jwks['keys'])
        ]);
        throw new JwtAuthenticationException("Key {$header['kid']} not found in global project JWKS");
    }

    /**
     * Fetch global project JWKS used for project token verification (cached ~5 hours)
     */
    private function fetchGlobalProjectJWKS(): array
    {
        \Log::info('JWT_GLOBAL_JWKS: Starting global project JWKS fetch', [
            'mercury_base_url' => $this->mercuryBaseUrl
        ]);

        $cacheKey = "{$this->cachePrefix}:jwks:project_global";
        
        \Log::debug('JWT_CACHE: Checking cache for global project JWKS', [
            'cache_key' => $cacheKey,
            'cache_ttl' => 18000 // 5 hours
        ]);

        return Cache::remember($cacheKey, 18000, function () {
            \Log::info('JWT_CACHE_MISS: Global cache miss, fetching from Mercury');

            $path = 'auth/project/.well-known/jwks.json';
            $url = "{$this->mercuryBaseUrl}/{$path}";

            $timestamp = (string) round(time() * 1000);
            $stringToSign = 'GET/' . $path . $timestamp;
            $signature = hash_hmac(
                'sha256',
                $stringToSign,
                $this->sharedSecret
            );

            \Log::info('JWT_REQUEST: Preparing global JWKS request', [
                'url' => $url,
                'path' => $path,
                'timestamp' => $timestamp,
                'string_to_sign' => $stringToSign,
                'signature_length' => strlen($signature)
            ]);

            $timeout = config('auth-guard.mercury.timeout', 10);
            $headers = [
                'Accept' => 'application/json',
                'User-Agent' => 'Laravel-AuthGuard/1.0',
                'X-Timestamp' => $timestamp,
                'X-Signature' => $signature,
            ];

            \Log::debug('JWT_REQUEST_HEADERS: Global JWKS request headers prepared', [
                'headers' => array_keys($headers),
                'timeout' => $timeout
            ]);

            $response = Http::timeout($timeout)
                ->withHeaders($headers)
                ->get($url);

            \Log::info('JWT_RESPONSE: Global project JWKS response received', [
                'status' => $response->status(),
                'success' => $response->successful(),
                'response_size' => strlen($response->body()),
                'content_type' => $response->header('Content-Type'),
                'url' => $url
            ]);
            
            if (!$response->successful()) {
                \Log::error('JWT_ERROR: Global JWKS request failed', [
                    'status' => $response->status(),
                    'reason' => $response->reason(),
                    'body' => $response->body(),
                    'url' => $url,
                    'headers_sent' => array_keys($headers)
                ]);
                throw new JwtAuthenticationException(
                    "Global project JWKS endpoint returned {$response->status()}: {$response->body()}"
                );
            }

            $data = $response->json();
            
            \Log::debug('JWT_RESPONSE_PARSE: Parsing global JWKS response', [
                'response_keys' => is_array($data) ? array_keys($data) : 'invalid_json',
                'has_keys_array' => isset($data['keys'])
            ]);

            if (!isset($data['keys'])) {
                \Log::error('JWT_ERROR: Invalid global JWKS response structure', [
                    'response_keys' => is_array($data) ? array_keys($data) : 'not_array',
                    'response_sample' => is_array($data) ? array_slice($data, 0, 3, true) : $data
                ]);
                throw new JwtAuthenticationException('Invalid global project JWKS response: missing keys');
            }

            if (!is_array($data['keys'])) {
                \Log::warning('JWT_WARNING: Converting single global key to array', [
                    'original_type' => gettype($data['keys'])
                ]);
                $data['keys'] = [$data['keys']];
            }

            \Log::info('JWT_GLOBAL_SUCCESS: Global project JWKS fetched and cached', [
                'keys_count' => count($data['keys']),
                'key_ids' => array_column($data['keys'], 'kid'),
                'cache_duration' => '5 hours'
            ]);

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