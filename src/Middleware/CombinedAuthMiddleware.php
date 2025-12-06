<?php

namespace Wazobia\LaravelAuthGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;

class CombinedAuthMiddleware
{
    private JwtAuthService $jwtService;
    private ProjectAuthService $projectService;

    public function __construct(
        JwtAuthService $jwtService,
        ProjectAuthService $projectService
    ) {
        $this->jwtService = $jwtService;
        $this->projectService = $projectService;
    }

    /**
     * Handle an incoming request with both authentications.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Run JWT authentication
        $jwtMiddleware = new JwtAuthMiddleware($this->jwtService);
        $jwtResponse = $jwtMiddleware->handle($request, function ($req) {
            return $req;
        });

        // Check if JWT auth failed
        if ($jwtResponse instanceof \Illuminate\Http\JsonResponse && $jwtResponse->status() === 401) {
            return $jwtResponse;
        }

        // Run Project authentication
        $projectMiddleware = new ProjectAuthMiddleware($this->projectService);
        $projectResponse = $projectMiddleware->handle($request, function ($req) {
            return $req;
        });

        // Check if Project auth failed
        if ($projectResponse instanceof \Illuminate\Http\JsonResponse && $projectResponse->status() === 401) {
            return $projectResponse;
        }

        // Both authentications passed
        return $next($request);
    }
}