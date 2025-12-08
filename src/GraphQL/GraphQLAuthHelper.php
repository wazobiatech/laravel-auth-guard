<?php

namespace Wazobia\LaravelAuthGuard\GraphQL;

use Closure;
use Exception;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;

class GraphQLAuthHelper
{
    /**
     * JWT authentication for GraphQL
     */
    public static function jwtAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        
        try {
            // Get the service directly instead of middleware
            $jwtService = app(JwtAuthService::class);
            
            $headerName = config('auth-guard.headers.jwt', 'Authorization');
            $authHeader = $request->header($headerName);
            
            if (!$authHeader) {
                throw new Exception('No authorization header provided');
            }
            
            // Extract token
            $token = str_starts_with($authHeader, 'Bearer ') 
                ? substr($authHeader, 7) 
                : $authHeader;
            
            if (!$token) {
                throw new Exception('Empty authorization token');
            }
            
            // Authenticate
            $user = $jwtService->authenticate($token);
            
            // Convert to object
            $userObject = (object) $user;
            
            // Set user in request
            $request->merge(['user' => $user]);
            $request->setUserResolver(function () use ($userObject) {
                return $userObject;
            });
            
            // Use custom property name (not $context->user which is typed)
            $context->authUser = $userObject;
            
            return $next($root, $args, $context, $info);
            
        } catch (Exception $e) {
            throw new Exception('JWT Authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Project authentication for GraphQL
     */
    public static function projectAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        
        try {
            // Get the service directly instead of middleware
            $projectService = app(ProjectAuthService::class);
            
            $tokenHeader = config('auth-guard.headers.project_token', 'x-project-token');
            $authHeader = $request->header($tokenHeader);
            
            if (!$authHeader) {
                throw new Exception("No project token provided, required_header: '{$tokenHeader}'");
            }
            
            // Extract token
            $token = str_starts_with($authHeader, 'Bearer ') 
                ? substr($authHeader, 7) 
                : $authHeader;
            
            if (empty($token)) {
                throw new Exception('Empty project token');
            }
            
            // Get service ID
            $serviceId = config('auth-guard.service_id', env('SERVICE_ID'));
            if (!$serviceId) {
                throw new Exception('Service ID not configured');
            }
            
            // Authenticate
            $project = $projectService->authenticateWithToken($token, $serviceId);
            
            // Convert to object
            $projectObject = (object) $project;
            
            // Set project in request
            $request->merge(['project' => $project]);
            $request->project = $projectObject;
            
            // Use custom property name
            $context->authProject = $projectObject;
            
            return $next($root, $args, $context, $info);
            
        } catch (Exception $e) {
            throw new Exception('Project Authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Combined authentication for GraphQL
     */
    public static function combinedAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        
        try {
            // Run JWT authentication first
            $jwtService = app(JwtAuthService::class);
            
            $jwtHeader = config('auth-guard.headers.jwt', 'Authorization');
            $authHeader = $request->header($jwtHeader);
            
            if (!$authHeader) {
                throw new Exception('No authorization header provided');
            }
            
            $token = str_starts_with($authHeader, 'Bearer ') 
                ? substr($authHeader, 7) 
                : $authHeader;
            
            if (!$token) {
                throw new Exception('Empty authorization token');
            }
            
            $user = $jwtService->authenticate($token);
            $userObject = (object) $user;
            
            $request->merge(['user' => $user]);
            $request->setUserResolver(function () use ($userObject) {
                return $userObject;
            });
            
            // Use custom property name
            $context->authUser = $userObject;
            
            // Run Project authentication second
            $projectService = app(ProjectAuthService::class);
            
            $projectHeader = config('auth-guard.headers.project_token', 'x-project-token');
            $projectAuthHeader = $request->header($projectHeader);
            
            if (!$projectAuthHeader) {
                throw new Exception("No project token provided, required_header: '{$projectHeader}'");
            }
            
            $projectToken = str_starts_with($projectAuthHeader, 'Bearer ') 
                ? substr($projectAuthHeader, 7) 
                : $projectAuthHeader;
            
            if (empty($projectToken)) {
                throw new Exception('Empty project token');
            }
            
            $serviceId = config('auth-guard.service_id', env('SERVICE_ID'));
            if (!$serviceId) {
                throw new Exception('Service ID not configured');
            }
            
            $project = $projectService->authenticateWithToken($projectToken, $serviceId);
            $projectObject = (object) $project;
            
            $request->merge(['project' => $project]);
            $request->project = $projectObject;
            
            // Use custom property name
            $context->authProject = $projectObject;
            
            return $next($root, $args, $context, $info);
            
        } catch (Exception $e) {
            throw new Exception('Authentication failed: ' . $e->getMessage());
        }
    }
}