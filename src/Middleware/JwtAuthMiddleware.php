<?php

namespace Wazobia\LaravelAuthGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;

class JwtAuthMiddlewareRaw
{
    private JwtAuthService $authService;

    public function __construct(JwtAuthService $authService)
    {
        $this->authService = $authService;
    }

    /**
     * Raw middleware that throws exceptions instead of returning JSON responses
     * This matches the Node.js behavior more closely
     */
    public function handle(Request $request, Closure $next)
    {
        $headerName = config('auth-guard.headers.jwt', 'Authorization');
        $token = $this->extractToken($request, $headerName);
        
        if (!$token) {
            throw new JwtAuthenticationException('No authorization header provided');
        }

        $user = $this->authService->authenticate($token);
        
        $request->merge(['user' => $user]);
        $request->setUserResolver(function () use ($user) {
            return (object) $user;
        });

        return $next($request);
    }

    private function extractToken(Request $request, string $headerName): ?string
    {
        $authHeader = $request->header($headerName);
        if (!authHeader) {
            return null;
        }

        if (str_starts_with($authHeader, 'Bearer ')) {
            return substr($authHeader, 7);
        }

        return $authHeader;
    }
}