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
    | Default Project UUID (fallback for per-project JWKS)
    |--------------------------------------------------------------------------
    |
    | Matches Node/Python behavior: if a user JWT does not include project_uuid
    | claim, we fall back to this value (NEXUS_ID). If neither is present, auth
    | fails with an explicit error.
    */
    'default_project_uuid' => env('NEXUS_ID'),

    /*
    |--------------------------------------------------------------------------
    | Service ID Configuration
    |--------------------------------------------------------------------------
    |
    | The ID of the current service for project authentication
    |
    */
    'service_id' => env('SERVICE_ID'),

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
        'project_token' => env('AUTH_PROJECT_TOKEN_HEADER', 'x-project-token'),
    ],
];