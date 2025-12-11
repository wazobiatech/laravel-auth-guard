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

    public function handle(Request $request, Closure $next)
    {
        try {
            $tokenHeader = config('auth-guard.headers.project_token', 'x-project-token');
            $authHeader = $request->header($tokenHeader);

            \Log::info('ProjectAuthMiddleware: Processing request', [
                'expected_header' => $tokenHeader,
                'header_found' => !empty($authHeader),
                'header_value_preview' => $authHeader ? substr($authHeader, 0, 30) . '...' : null,
                'request_method' => $request->method(),
                'request_path' => $request->path()
            ]);

            if (!$authHeader) {
                \Log::warning('Missing project token header', [
                    'expected_header' => $tokenHeader,
                    'available_headers' => array_keys($request->headers->all())
                ]);
                
                throw new ProjectAuthenticationException(
                    "No project token provided, required_header: '{$tokenHeader}'"
                );
            }

            $token = str_starts_with($authHeader, 'Bearer ') 
                ? substr($authHeader, 7) 
                : $authHeader;

            if (empty($token)) {
                throw new ProjectAuthenticationException('Empty project token');
            }

            $serviceId = config('auth-guard.service_id', env('SERVICE_ID')) ?: null;
            if (!$serviceId) {
                \Log::warning('SERVICE_ID not configured for ProjectAuthMiddleware');
                throw new ProjectAuthenticationException('Service ID not configured');
            }

            $project = $this->authService->authenticateWithToken($token, $serviceId);

            $request->merge(['project' => $project]);
            $request->project = (object) $project;

            \Log::info('Project authentication successful', [
                'project_uuid' => $project['project_uuid'],
                'service_id' => $serviceId
            ]);

            return $next($request);

        } catch (ProjectAuthenticationException $e) {
            \Log::warning('Project authentication failed', [
                'error' => $e->getMessage(),
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent()
            ]);

            return response()->json([
                'error' => 'Project Authentication failed',
                'message' => $e->getMessage()
            ], $e->getCode() ?: 401);
        } catch (\Exception $e) {
            \Log::error('Project authentication error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'error' => 'Authentication service error',
                'message' => 'Internal authentication error'
            ], 500);
        }
    }
}