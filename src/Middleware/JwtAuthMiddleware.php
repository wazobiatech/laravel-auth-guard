<?php

namespace Wazobia\LaravelAuthGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;

class JwtAuthMiddleware
{
    private JwtAuthService $authService;

    public function __construct(JwtAuthService $authService)
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
            $headerName = config('auth-guard.headers.jwt', 'Authorization');
            $token = $this->extractToken($request, $headerName);
            
            if (!$token) {
                throw new JwtAuthenticationException('No authorization token provided');
            }

            $user = $this->authService->authenticate($token);
            
            // Attach user to request
            $request->merge(['auth_user' => $user]);
            $request->setUserResolver(function () use ($user) {
                return (object) $user;
            });

            return $next($request);
        } catch (JwtAuthenticationException $e) {
            return response()->json([
                'error' => 'JWT Authentication failed',
                'message' => $e->getMessage()
            ], 401);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Authentication error',
                'message' => $e->getMessage()
            ], 401);
        }
    }

    /**
     * Extract token from request header
     *
     * @param Request $request
     * @param string $headerName
     * @return string|null
     */
    private function extractToken(Request $request, string $headerName): ?string
    {
        $authHeader = $request->header($headerName);
        if (!$authHeader) {
            return null;
        }

        if (str_starts_with($authHeader, 'Bearer ')) {
            return substr($authHeader, 7);
        }

        return $authHeader;
    }
}