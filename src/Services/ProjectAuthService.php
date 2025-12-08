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
            $payload = $this->decodeAndVerify($token);

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
                // Use 'auth' connection without prefix
                $redis = Redis::connection('auth');
                $exists = (int) $redis->exists($revocationKey);
                
                $this->log('Redis token check', [
                    'key' => $revocationKey,
                    'exists' => $exists,
                    'token_id' => $payload['token_id']
                ]);
                
                if ($exists === 0) {
                    throw new ProjectAuthenticationException('Token has been revoked or expired');
                }
            } catch (ProjectAuthenticationException $e) {
                throw $e;
            } catch (\Exception $e) {
                $this->log('Redis connection error', ['error' => $e->getMessage()], 'error');
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

            if (!in_array($serviceId, $payload['enabled_services'])) {
                throw new ProjectAuthenticationException(
                    "Service '{$serviceId}' not enabled for project {$payload['project_uuid']}", 403
                );
            }

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
            $jwks = app(JwksService::class);
            $publicKey = $jwks->getProjectTokenPublicKey($token);

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