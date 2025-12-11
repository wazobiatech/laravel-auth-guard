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

    public function authenticateWithToken(string $token, string $serviceId): array
    {
        try {
            \Log::emergency('PROJECT_TOKEN_DEBUG: Authentication started', [
                'token_preview' => substr($token, 0, 50) . '...',
                'token_length' => strlen($token),
                'service_id' => $serviceId
            ]);
            
            $payload = $this->decodeAndVerify($token);
            
            $this->log('Project token successfully decoded', [
                'payload_keys' => array_keys($payload),
                'project_uuid' => $payload['project_uuid'] ?? 'missing',
                'token_id' => $payload['token_id'] ?? 'missing',
                'enabled_services_count' => is_array($payload['enabled_services'] ?? null) ? count($payload['enabled_services']) : 0
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
            
            try {
                \Log::info('PROJECT_TOKEN_REDIS: Checking token blacklist', [
                    'token_id' => $payload['token_id'],
                    'redis_key' => $revocationKey
                ]);

                // Use 'auth' connection without prefix
                $redis = Redis::connection('auth');
                $exists = (int) $redis->exists($revocationKey);
                
                \Log::info('PROJECT_TOKEN_REDIS: Blacklist check result', [
                    'key' => $revocationKey,
                    'exists' => $exists,
                    'token_id' => $payload['token_id'],
                    'logic' => 'blacklist - token INVALID if IN redis, VALID if NOT in redis'
                ]);
                
                // CORRECT LOGIC: If token exists in Redis → it's blacklisted → reject
                if ($exists === 1) {
                    \Log::error('PROJECT_TOKEN_ERROR: Token found in blacklist', [
                        'token_id' => $payload['token_id'],
                        'redis_key' => $revocationKey
                    ]);
                    throw new ProjectAuthenticationException('Token has been revoked or blacklisted');
                }
                
                \Log::info('PROJECT_TOKEN_REDIS: Token not blacklisted, continuing', [
                    'token_id' => $payload['token_id']
                ]);
                
            } catch (ProjectAuthenticationException $e) {
                throw $e;
            } catch (\Exception $e) {
                \Log::error('PROJECT_TOKEN_ERROR: Redis connection error', [
                    'error' => $e->getMessage(),
                    'token_id' => $payload['token_id'] ?? 'unknown'
                ]);
                throw new ProjectAuthenticationException('Redis error during token revocation check: ' . $e->getMessage());
            } finally {
                Redis::connection('auth')->disconnect();
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
                $this->log('Secret version check failed', ['error' => $e->getMessage()], 'warning');
            }

            \Log::info('PROJECT_TOKEN_AUTH: Checking service authorization', [
                'required_service_id' => $serviceId,
                'enabled_services' => $payload['enabled_services'],
                'enabled_services_count' => count($payload['enabled_services']),
                'project_uuid' => $payload['project_uuid']
            ]);

            if (!in_array($serviceId, $payload['enabled_services'])) {
                \Log::error('PROJECT_TOKEN_ERROR: Service not authorized', [
                    'required_service_id' => $serviceId,
                    'enabled_services' => $payload['enabled_services'],
                    'project_uuid' => $payload['project_uuid']
                ]);
                throw new ProjectAuthenticationException(
                    "Service '{$serviceId}' not enabled for project {$payload['project_uuid']}", 403
                );
            }

            \Log::info('PROJECT_TOKEN_AUTH: Service authorization successful', [
                'service_id' => $serviceId,
                'project_uuid' => $payload['project_uuid']
            ]);

            $this->log('Project token validated successfully', [
                'project_uuid' => $payload['project_uuid'],
                'service_id' => $serviceId,
                'token_id' => $payload['token_id']
            ]);

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
            $this->log('Project token validation error', [
                'error' => $e->getMessage(),
                'service_id' => $serviceId
            ], 'error');
            throw new ProjectAuthenticationException(
                'Token validation failed: ' . $e->getMessage()
            );
        }
    }

    public function authenticate(string $apiKey, string $secret, string $service): array
    {
        $this->log('Legacy authenticate method called - please migrate to authenticateWithToken', [
            'api_key' => $apiKey,
            'service' => $service
        ], 'warning');
        
        throw new ProjectAuthenticationException(
            'Legacy App ID/Secret authentication is no longer supported. Please use project tokens.'
        );
    }

    private function decodeAndVerify(string $token): array
    {
        try {
            \Log::info('PROJECT_TOKEN_VERIFY: Starting JWT signature verification');
            
            $jwks = app(JwksService::class);
            $publicKey = $jwks->getProjectTokenPublicKey($token);

            \Log::info('PROJECT_TOKEN_VERIFY: Public key obtained, decoding JWT', [
                'pem_length' => strlen($publicKey)
            ]);

            $algorithm = config('auth-guard.jwt.algorithm', 'RS512');
            JWT::$leeway = config('auth-guard.jwt.leeway', 0);

            \Log::debug('PROJECT_TOKEN_VERIFY: JWT settings', [
                'algorithm' => $algorithm,
                'leeway' => JWT::$leeway
            ]);

            $decoded = JWT::decode($token, new Key($publicKey, $algorithm));
            $payload = (array) $decoded;

            \Log::info('PROJECT_TOKEN_VERIFY: JWT decoded successfully', [
                'payload_keys' => array_keys($payload),
                'project_uuid' => $payload['project_uuid'] ?? 'missing',
                'token_id' => $payload['token_id'] ?? 'missing',
                'expires_at' => isset($payload['exp']) ? date('Y-m-d H:i:s', $payload['exp']) : 'missing'
            ]);

            // Time-based validation
            $now = time();
            \Log::debug('PROJECT_TOKEN_VERIFY: Time validation', [
                'current_time' => $now,
                'current_time_readable' => date('Y-m-d H:i:s', $now),
                'nbf' => $payload['nbf'] ?? 'not_set',
                'iat' => $payload['iat'] ?? 'not_set',
                'exp' => $payload['exp'] ?? 'not_set'
            ]);

            if (isset($payload['nbf']) && $now < (int) $payload['nbf']) {
                \Log::error('PROJECT_TOKEN_ERROR: Token not yet valid', [
                    'nbf' => $payload['nbf'],
                    'nbf_readable' => date('Y-m-d H:i:s', $payload['nbf']),
                    'current_time' => $now
                ]);
                throw new ProjectAuthenticationException('Token cannot be used yet (nbf)');
            }
            if (isset($payload['iat']) && $now < (int) $payload['iat']) {
                \Log::error('PROJECT_TOKEN_ERROR: Token issued in future', [
                    'iat' => $payload['iat'],
                    'iat_readable' => date('Y-m-d H:i:s', $payload['iat']),
                    'current_time' => $now
                ]);
                throw new ProjectAuthenticationException('Token issued in the future (iat)');
            }
            if (isset($payload['exp']) && $now >= (int) $payload['exp']) {
                \Log::error('PROJECT_TOKEN_ERROR: Token expired', [
                    'exp' => $payload['exp'],
                    'exp_readable' => date('Y-m-d H:i:s', $payload['exp']),
                    'current_time' => $now
                ]);
                throw new ProjectAuthenticationException('Token has expired (exp)');
            }

            \Log::info('PROJECT_TOKEN_SUCCESS: JWT verification completed successfully', [
                'project_uuid' => $payload['project_uuid'] ?? 'missing',
                'token_id' => $payload['token_id'] ?? 'missing'
            ]);

            return $payload;
        } catch (ProjectAuthenticationException $e) {
            \Log::error('PROJECT_TOKEN_ERROR: Authentication exception', [
                'error' => $e->getMessage(),
                'code' => $e->getCode()
            ]);
            throw $e;
        } catch (\Exception $e) {
            \Log::error('PROJECT_TOKEN_ERROR: Unexpected verification error', [
                'error' => $e->getMessage(),
                'error_class' => get_class($e),
                'trace' => $e->getTraceAsString()
            ]);
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