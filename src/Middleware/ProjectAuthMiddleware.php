<?php

namespace Wazobia\LaravelAuthGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;

class ProjectAuthMiddleware
{
    private ProjectAuthService $authService;

    public function __construct(ProjectAuthService $authService)
    {
        $this->authService = $authService;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $apiKeyHeader = config('auth-guard.headers.project_id', 'x-app-id');
            $secretHeader = config('auth-guard.headers.project_secret', 'x-app-secret');
            $serviceHeader = config('auth-guard.headers.project_service', 'x-service-id');
            
            $apiKey = $request->header($apiKeyHeader);
            $secret = $request->header($secretHeader);
            $service = $request->header($serviceHeader);

            if (!$apiKey || !$secret || !$service) {
                throw new ProjectAuthenticationException(
                    "Missing project credentials ({$apiKeyHeader} or {$secretHeader} or {$serviceHeader})"
                );
            }

            $project = $this->authService->authenticate($apiKey, $secret, $service);
            
            // Attach project to request
            $request->merge(['auth_project' => $project]);

            return $next($request);
        } catch (ProjectAuthenticationException $e) {
            return response()->json([
                'error' => 'Project Authentication failed',
                'message' => $e->getMessage()
            ], 401);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Authentication error',
                'message' => $e->getMessage()
            ], 401);
        }
    }
}