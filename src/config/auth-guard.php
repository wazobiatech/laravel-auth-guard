<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Mercury Service Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for JWT validation and JWKS endpoints
    |
    */
    'mercury' => [
        'base_url' => env('MERCURY_BASE_URL', 'http://localhost:4000'),
        'timeout' => env('MERCURY_TIMEOUT', 10),
    ],

    /*
    |--------------------------------------------------------------------------
    | Athens Service Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for project authentication service
    |
    */
    'athens' => [
        'base_url' => env('ATHENS_BASE_URL', 'http://localhost:3000'),
        'project_uuid' => env('ATHENS_PROJECT_UUID'),
        'timeout' => env('ATHENS_TIMEOUT', 10),
    ],

    /*
    |--------------------------------------------------------------------------
    | Signature Configuration
    |--------------------------------------------------------------------------
    |
    | Shared secret for HMAC signature validation
    |
    */
    'signature' => [
        'shared_secret' => env('SIGNATURE_SHARED_SECRET', ''),
        'algorithm' => env('SIGNATURE_ALGORITHM', 'sha256'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Configuration
    |--------------------------------------------------------------------------
    |
    | Cache settings for tokens and JWKS
    |
    */
    'cache' => [
        'ttl' => env('AUTH_CACHE_TTL', 900), // 15 minutes
        'prefix' => env('AUTH_CACHE_PREFIX', 'auth_guard'),
        'driver' => env('AUTH_CACHE_DRIVER', 'redis'),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT Configuration
    |--------------------------------------------------------------------------
    |
    | JWT specific settings
    |
    */
    'jwt' => [
        'algorithm' => env('JWT_ALGORITHM', 'RS512'),
        'leeway' => env('JWT_LEEWAY', 0),
        'required_claims' => ['iss', 'sub', 'exp'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Enable/disable debug logging
    |
    */
    'logging' => [
        'enabled' => env('AUTH_GUARD_LOGGING', true),
        'channel' => env('AUTH_GUARD_LOG_CHANNEL', 'stack'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Headers Configuration
    |--------------------------------------------------------------------------
    |
    | Custom header names for authentication
    |
    */
    'headers' => [
        'jwt' => env('AUTH_JWT_HEADER', 'Authorization'),
        'project_id' => env('AUTH_PROJECT_ID_HEADER', 'x-app-id'),
        'project_secret' => env('AUTH_PROJECT_SECRET_HEADER', 'x-app-secret'),
        'project_service' => env('AUTH_PROJECT_SERVICE_HEADER', 'x-service-id')
    ],
];