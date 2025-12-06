<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;
use Wazobia\LaravelAuthGuard\Contracts\ProjectAuthenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ProjectAuthService implements ProjectAuthenticatable
{
    private string $athensBaseUrl;
    private string $sharedSecret;
    private int $cacheTtl;
    private string $cachePrefix;

    public function __construct(
        string $athensBaseUrl,
        string $sharedSecret,
        int $cacheTtl = 900
    ) {
        $this->athensBaseUrl = $athensBaseUrl;
        $this->sharedSecret = $sharedSecret;
        $this->cacheTtl = $cacheTtl;
        $this->cachePrefix = config('auth-guard.cache.prefix', 'auth_guard');
    }

    /**
     * Authenticate project credentials
     */
    public function authenticate(string $apiKey, string $secret, string $service): array
    {
        $cacheKey = "{$this->cachePrefix}:project:{$apiKey}:{$secret}:{$service}";
        
        // Check cache first
        $cachedProject = Cache::get($cacheKey);
        if ($cachedProject) {
            $this->log('Project cache hit', ['projectUuid' => $cachedProject['projectUuid']]);
            return $cachedProject;
        }

        $this->log('Project cache miss - verifying with Athens');
        $project = $this->verifyWithAthens($apiKey, $secret, $service);
        
        // Cache the result
        Cache::put($cacheKey, $project, $this->cacheTtl);
        
        $this->log('Project authenticated', ['projectUuid' => $project['projectUuid']]);
        
        return $project;
    }

    /**
     * Verify credentials with Athens service
     */
    private function verifyWithAthens(string $appId, string $secret, string $service): array
    {
        $credentials = base64_encode("{$appId}:{$secret}:{$service}");
        $timestamp = (string) (time() * 1000);
        $algorithm = config('auth-guard.signature.algorithm', 'sha256');
        $signature = hash_hmac(
            $algorithm,
            'GET' . '/auth' . $timestamp,
            $this->sharedSecret
        );

        try {
            $timeout = config('auth-guard.athens.timeout', 10);
            $response = Http::timeout($timeout)
                ->withHeaders([
                    'Authorization' => "Basic {$credentials}",
                    'X-Timestamp' => $timestamp,
                    'X-Signature' => $signature,
                ])
                ->get("{$this->athensBaseUrl}/auth");

            if (!$response->successful()) {
                $errorMessage = $this->parseErrorResponse($response);
                throw new ProjectAuthenticationException($errorMessage);
            }

            $data = $response->json();
            if (!$data) {
                throw new ProjectAuthenticationException('No data received from Athens');
            }

            $this->log('Athens verification passed');
            
            return [
                'projectUuid' => $data['projectUuid'],
                'projectName' => $data['projectName'],
                // 'raw_response' => $data,
            ];
        } catch (\Exception $e) {
            $this->log('Athens verification failed', ['error' => $e->getMessage()], 'error');
            throw new ProjectAuthenticationException(
                'Athens verification failed: ' . $e->getMessage()
            );
        }
    }

    /**
     * Parse error response from Athens
     */
    private function parseErrorResponse($response): string
    {
        $data = $response->json();
        
        if (is_string($data)) {
            return $data;
        }
        
        if (is_array($data)) {
            if (isset($data['message'])) {
                return $data['message'];
            }
            if (isset($data['error'])) {
                return $data['error'];
            }
            return 'Athens returned error: ' . json_encode($data);
        }
        
        return "Athens returned {$response->status()}: {$response->body()}";
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