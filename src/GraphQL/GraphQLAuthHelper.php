<?php

namespace Wazobia\LaravelAuthGuard\GraphQL;

use Closure;
use Exception;
use Wazobia\LaravelAuthGuard\Middleware\JwtAuthMiddleware;
use Wazobia\LaravelAuthGuard\Middleware\ProjectAuthMiddleware;
use Wazobia\LaravelAuthGuard\Middleware\CombinedAuthMiddleware;

class GraphQLAuthHelper
{
    /**
     * JWT authentication for GraphQL
     */
    public static function jwtAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        $middleware = app(JwtAuthMiddleware::class);
        
        $response = $middleware->handle($request, function ($req) use ($next, $root, $args, $context, $info) {
            return $next($root, $args, $context, $info);
        });

        if ($response instanceof \Illuminate\Http\JsonResponse && $response->status() === 401) {
            $data = $response->getData(true);
            throw new Exception($data['message'] ?? 'JWT Authentication failed');
        }

        return $response;
    }

    /**
     * Project authentication for GraphQL
     */
    public static function projectAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        $middleware = app(ProjectAuthMiddleware::class);
        
        $response = $middleware->handle($request, function ($req) use ($next, $root, $args, $context, $info) {
            return $next($root, $args, $context, $info);
        });

        if ($response instanceof \Illuminate\Http\JsonResponse && $response->status() === 401) {
            $data = $response->getData(true);
            throw new Exception($data['message'] ?? 'Project Authentication failed');
        }

        return $response;
    }

    /**
     * Combined authentication for GraphQL
     */
    public static function combinedAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        $middleware = app(CombinedAuthMiddleware::class);
        
        $response = $middleware->handle($request, function ($req) use ($next, $root, $args, $context, $info) {
            return $next($root, $args, $context, $info);
        });

        if ($response instanceof \Illuminate\Http\JsonResponse && $response->status() === 401) {
            $data = $response->getData(true);
            throw new Exception($data['message'] ?? 'Authentication failed');
        }

        return $response;
    }
}