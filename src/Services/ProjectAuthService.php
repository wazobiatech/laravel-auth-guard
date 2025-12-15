<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;
use Wazobia\LaravelAuthGuard\Contracts\ProjectAuthenticatable;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Log;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Wazobia\LaravelAuthGuard\Services\JwksService;

class ProjectAuthService implements ProjectAuthenticatable
{
    private string $cachePrefix;

    public function __construct()
    {
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

    public function authenticateWithToken(string $token, string $serviceId): array
    {
        $this->debugLog('Project Authentication Starting', [
            'service_id' => $serviceId,
            'token_length' => strlen($token),
            'token_preview' => substr($token, 0, 50) . '...',
            'token_parts_count' => count(explode('.', $token))
        ]);
        
        try {
            $this->debugLog('Starting token decode and verification', [
                'service_id' => $serviceId
            ]);
            
            $payload = $this->decodeAndVerify($token);
            
            $this->debugLog('Token decode and verification completed', [
                'service_id' => $serviceId,
                'payload_keys' => array_keys($payload),
                'project_uuid' => $payload['project_uuid'] ?? 'missing',
                'enabled_services' => $payload['enabled_services'] ?? 'missing',
                'token_id' => $payload['token_id'] ?? 'missing'
            ]);

            foreach (['project_uuid','enabled_services','token_id'] as $field) {
                if (!isset($payload[$field])) {
                    throw new ProjectAuthenticationException("Invalid project token: missing {$field}");
                }
            }
            if (!is_array($payload['enabled_services'])) {
                throw new ProjectAuthenticationException('Invalid project token: enabled_services must be array');
            }

            // Check token revocation using auth Redis connection (no prefix, matches Node.js)
            $revocationKey = 'project_token:' . $payload['token_id'];
            
            $this->debugLog('Project Auth Token Revocation Check Starting', [
                'revocation_key' => $revocationKey,
                'token_id' => $payload['token_id'],
                'redis_connection' => 'auth',
                'project_uuid' => $payload['project_uuid'],
                'redis_config' => [
                    'host' => config('database.redis.auth.host'),
                    'port' => config('database.redis.auth.port'),
                    'database' => config('database.redis.auth.database')
                ]
            ]);
            
            try {
                // Use 'auth' connection without prefix
                $this->debugLog('Connecting to Redis auth connection', [
                    'connection_name' => 'auth',
                    'revocation_key' => $revocationKey
                ]);
                
                $redis = Redis::connection('auth');
                
                $this->debugLog('Redis connection established, checking key existence', [
                    'revocation_key' => $revocationKey,
                    'connection_status' => 'connected'
                ]);
                
                $exists = (int) $redis->exists($revocationKey);
                
                $this->debugLog('Redis revocation check completed', [
                    'revocation_key' => $revocationKey,
                    'exists' => $exists,
                    'is_blacklisted' => $exists === 1,
                    'will_reject_token' => $exists === 1
                ]);
                
                // If token exists in Redis → it's blacklisted → reject
                if ($exists === 1) {
                    throw new ProjectAuthenticationException('Token has been revoked or blacklisted');
                }
                
            } catch (ProjectAuthenticationException $e) {
                throw $e;
            } catch (\Exception $e) {
                $this->errorLog('Redis Connection Failed During Token Revocation Check', [
                    'error_message' => $e->getMessage(),
                    'exception_class' => get_class($e),
                    'exception_code' => $e->getCode(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'redis_connection' => 'auth',
                    'revocation_key' => $revocationKey,
                    'redis_config' => [
                        'host' => config('database.redis.auth.host'),
                        'port' => config('database.redis.auth.port'),
                        'database' => config('database.redis.auth.database'),
                        'url' => config('database.redis.auth.url')
                    ],
                    'trace_preview' => array_slice($e->getTrace(), 0, 3)
                ]);
                throw new ProjectAuthenticationException('Redis error during token revocation check: ' . $e->getMessage());
            } finally {
                try {
                    $this->debugLog('Disconnecting from Redis auth connection', [
                        'revocation_key' => $revocationKey
                    ]);
                    Redis::connection('auth')->disconnect();
                } catch (\Exception $e) {
                    $this->errorLog('Redis Disconnect Failed', [
                        'error_message' => $e->getMessage(),
                        'exception_class' => get_class($e)
                    ]);
                }
            }

            // Check secret version using auth connection
            try {
                $versionKey = 'project_secret_version:' . $payload['project_uuid'];
                $redis = Redis::connection('auth');
                $currentVersion = $redis->get($versionKey);
                
                if ($currentVersion !== null && $currentVersion !== false) {
                    $currentVersion = (int) $currentVersion;
                    $tokenVersion = (int) ($payload['secret_version'] ?? 0);
                    
                    if ($currentVersion > 0 && $tokenVersion < $currentVersion) {
                        throw new ProjectAuthenticationException(
                            'Token secret version outdated (token: ' . $tokenVersion . ', current: ' . $currentVersion . ')'
                        );
                    }
                }
            } catch (ProjectAuthenticationException $e) {
                throw $e;
            } catch (\Exception $e) {
                // Silently continue if secret version check fails
            }

            if (!in_array($serviceId, $payload['enabled_services'])) {
                throw new ProjectAuthenticationException(
                    "Service '{$serviceId}' not enabled for project {$payload['project_uuid']}", 403
                );
            }

            return [
                'project_uuid' => $payload['project_uuid'],
                'enabled_services' => $payload['enabled_services'],
                'secret_version' => $payload['secret_version'] ?? null,
                'token_id' => $payload['token_id'],
                'expires_at' => $payload['exp'] ?? null,
            ];

        } catch (ProjectAuthenticationException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new ProjectAuthenticationException(
                'Token validation failed: ' . $e->getMessage()
            );
        }
    }

    public function authenticate(string $apiKey, string $secret, string $service): array
    {
        throw new ProjectAuthenticationException(
            'Legacy App ID/Secret authentication is no longer supported. Please use project tokens.'
        );
    }

    private function decodeAndVerify(string $token): array
    {
        $this->debugLog('Token Decode and Verify Starting', [
            'token_length' => strlen($token),
            'token_preview' => substr($token, 0, 50) . '...'
        ]);
        
        try {
            $this->debugLog('Getting JWKS service instance', []);
            $jwks = app(JwksService::class);
            
            $this->debugLog('Fetching project token public key from JWKS', [
                'jwks_service_class' => get_class($jwks)
            ]);
            
            $publicKey = $jwks->getProjectTokenPublicKey($token);
            
            $this->debugLog('Public key retrieved successfully', [
                'public_key_length' => strlen($publicKey),
                'public_key_preview' => substr($publicKey, 0, 100) . '...'
            ]);

            $algorithm = config('auth-guard.jwt.algorithm', 'RS512');
            JWT::$leeway = config('auth-guard.jwt.leeway', 0);

            $decoded = JWT::decode($token, new Key($publicKey, $algorithm));
            $payload = (array) $decoded;

            $now = time();
            if (isset($payload['nbf']) && $now < (int) $payload['nbf']) {
                throw new ProjectAuthenticationException('Token cannot be used yet (nbf)');
            }
            if (isset($payload['iat']) && $now < (int) $payload['iat']) {
                throw new ProjectAuthenticationException('Token issued in the future (iat)');
            }
            if (isset($payload['exp']) && $now >= (int) $payload['exp']) {
                throw new ProjectAuthenticationException('Token has expired (exp)');
            }

            return $payload;
        } catch (ProjectAuthenticationException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new ProjectAuthenticationException('Project token verification failed: ' . $e->getMessage());
        }
    }

    private function log(string $message, array $context = [], string $level = 'info'): void
    {
        if (config('auth-guard.logging.enabled', true)) {
            Log::channel(config('auth-guard.logging.channel', 'stack'))
                ->$level("[LaravelAuthGuard] {$message}", $context);
        }
    }
}