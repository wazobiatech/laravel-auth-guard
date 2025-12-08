# Laravel Auth Guard

<div align="center">

![Laravel](https://img.shields.io/badge/Laravel-9%2B%20%7C%2010%20%7C%2011%20%7C%2012-FF2D20?style=for-the-badge&logo=laravel&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Required-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

**Enterprise-grade JWT and Project authentication middleware for Laravel applications**

[Installation](#installation) • [Configuration](#configuration) • [Usage](#usage) • [GraphQL Support](#graphql-setup-lighthouse) • [Documentation](#documentation)

</div>

---

## 🎯 Features

- **JWT Authentication** - Secure user authentication with RS512 algorithm
- **Project-Level Authentication** - HMAC-based project token validation
- **Combined Auth** - Support for dual authentication (JWT + Project)
- **JWKS Support** - Automatic public key rotation and caching
- **GraphQL Directives** - First-class Lighthouse GraphQL integration
- **Redis-Powered** - Fast token validation and revocation with Redis caching
- **Token Revocation** - Built-in support for revoking compromised tokens
- **Docker-Ready** - Works seamlessly in containerized environments
- **Auto-Discovery** - Laravel package auto-discovery support

---

## 📋 Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Redis Setup](#redis-setup)
  - [Service Provider](#service-provider)
- [GraphQL Setup](#graphql-setup-lighthouse)
- [Usage](#usage)
  - [REST API Routes](#rest-api-routes)
  - [GraphQL Schema](#graphql-schema)
  - [Resolvers](#graphql-resolvers)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)
- [Support](#support)

---

## ⚙️ Requirements

| Requirement | Version |
|-------------|---------|
| PHP | `^8.0` |
| Laravel | `^9.0 \| ^10.0 \| ^11.0 \| ^12.0` |
| Redis | `Latest` |
| Predis or PhpRedis | `Latest` |
| Lighthouse GraphQL | `^6.0 \| ^7.0` *(optional)* |

---

## 📦 Installation

### Step 1: Install the Package

```bash
composer require wazobia/laravel-auth-guard
```

The service provider will be automatically registered via Laravel's package discovery.

### Step 2: Install Redis Client

**Option A: Predis (PHP Redis client)**
```bash
composer require predis/predis
```

**Option B: PhpRedis Extension (Better Performance)**

```bash
# Ubuntu/Debian
sudo apt-get install php-redis

# Alpine Linux (Docker)
apk add php81-pecl-redis

# macOS
pecl install redis
```

### Step 3: Publish Configuration

```bash
php artisan vendor:publish --tag=auth-guard-config
```

This creates `config/auth-guard.php` in your project.

---

## 🔧 Configuration

### Environment Variables

Add these required variables to your `.env` file:

```properties
# Mercury Authentication Service
MERCURY_BASE_URL=https://mercury.{domain}.com
MERCURY_TIMEOUT=10

# HMAC Signature for JWKS Requests
SIGNATURE_SHARED_SECRET=AAAA***************************************
SIGNATURE_ALGORITHM=sha256

# Project Configuration
NEXUS_ID=26337ab1-****-********-********
SERVICE_ID=f4e2d3b1-****-****-****-************

# Redis Configuration
REDIS_CLIENT=predis
REDIS_URL=redis://:password@localhost/0
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=null
REDIS_DB=0
REDIS_CACHE_DB=1

# Cache Settings
CACHE_EXPIRY_TIME=900
AUTH_CACHE_TTL=900
AUTH_CACHE_PREFIX=auth_guard
AUTH_CACHE_DRIVER=redis

# JWT Settings
JWT_ALGORITHM=RS512
JWT_LEEWAY=0

# Custom Headers (Optional)
AUTH_JWT_HEADER=Authorization
AUTH_PROJECT_TOKEN_HEADER=x-project-token

# Logging
AUTH_GUARD_LOGGING=true
AUTH_GUARD_LOG_CHANNEL=stack
```

> **💡 Docker Users:** If using Docker Compose, set `REDIS_HOST=redis` (the service name), not `127.0.0.1`

### Redis Setup

Update `config/database.php`:

```php
<?php

return [
    // ... other config

    'redis' => [
        'client' => env('REDIS_CLIENT', 'predis'),

        'options' => [
            'cluster' => env('REDIS_CLUSTER', 'redis'),
            'prefix' => env('REDIS_PREFIX', Str::slug(env('APP_NAME', 'laravel'), '_').'_database_'),
        ],

        'default' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_DB', '0'),
        ],

        'cache' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_CACHE_DB', '1'),
        ],
        
        'auth' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_DB', '0'),
            'prefix' => '', // No prefix!
        ],
    ],
];
```

### Verify Redis Connection

```bash
php artisan tinker
```

Test inside Tinker:
```php
Redis::ping();  // Should return: "+PONG"

Redis::set('test', 'Hello');
Redis::get('test');  // Should return: "Hello"

exit
```

### Service Provider

If not using auto-discovery, add to `config/app.php`:

```php
'providers' => [
    // ...
    Wazobia\LaravelAuthGuard\AuthGuardServiceProvider::class,
],
```

---

## 🎨 GraphQL Setup (Lighthouse)

### Step 1: Install Lighthouse

```bash
composer require nuwave/lighthouse
```

### Step 2: Configure Directives

Edit `config/lighthouse.php` and add the directive namespace:

```php
<?php

return [
    'namespaces' => [
        'models' => ['App', 'App\\Models'],
        'queries' => 'App\\GraphQL\\Queries',
        'mutations' => 'App\\GraphQL\\Mutations',
        'subscriptions' => 'App\\GraphQL\\Subscriptions',
        'interfaces' => 'App\\GraphQL\\Interfaces',
        'unions' => 'App\\GraphQL\\Unions',
        'scalars' => 'App\\GraphQL\\Scalars',
        
        'directives' => [
            'App\\GraphQL\\Directives',
            'Wazobia\\LaravelAuthGuard\\GraphQL\\Directives', // ← Add this line
        ],
    ],
];
```

### Step 3: Clear All Caches

```bash
php artisan cache:clear
php artisan config:clear
php artisan route:clear
php artisan lighthouse:clear-cache
composer dump-autoload
```

### Step 4: Validate Schema

```bash
php artisan lighthouse:validate-schema
```

---

## 🚀 Usage

### REST API Routes

Create routes in `routes/api.php`:

```php
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

// Public route (no authentication)
Route::get('/public', function () {
    return ['message' => 'Public endpoint'];
});

// JWT Authentication only
Route::middleware('jwt.auth')->group(function () {
    Route::get('/user/profile', function (Request $request) {
        $user = $request->user();
        return [
            'uuid' => $user->uuid,
            'email' => $user->email,
            'name' => $user->name,
        ];
    });
});

// Project Authentication only
Route::middleware('project.auth')->group(function () {
    Route::get('/project/info', function (Request $request) {
        $project = $request->project;
        return [
            'project_uuid' => $project->project_uuid,
            'enabled_services' => $project->enabled_services,
        ];
    });
});

// Combined Authentication (JWT + Project)
Route::middleware('combined.auth')->group(function () {
    Route::post('/secure/resource', function (Request $request) {
        return [
            'user' => $request->user(),
            'project' => $request->project,
            'message' => 'Both authentications passed'
        ];
    });
});
```

### GraphQL Schema

Create or update `graphql/schema.graphql`:

```graphql
type Query {
  # Public query
  hello: String!
  
  # JWT authentication required
  me: User! @jwtAuth
  
  # Project authentication required
  projectInfo: Project! @projectAuth
  
  # Both authentications required
  secureData: SecureData! @combinedAuth
}

type Mutation {
  updateProfile(name: String!): User! @jwtAuth
  updateProjectSettings(settings: JSON!): Project! @projectAuth
  createResource(data: JSON!): Resource! @combinedAuth
}

type User {
  uuid: ID!
  email: String!
  name: String!
}

type Project {
  project_uuid: ID!
  enabled_services: [String!]!
  secret_version: Int
}

type SecureData {
  id: ID!
  content: String!
  user: User!
  project: Project!
}
```

### GraphQL Resolvers

**app/GraphQL/Queries/Me.php**

```php
<?php

namespace App\GraphQL\Queries;

class Me
{
    public function __invoke($rootValue, array $args, $context)
    {
        $user = $context->request->user();
        return [
            'uuid' => $user->uuid,
            'email' => $user->email,
            'name' => $user->name,
        ];
    }
}
```

**app/GraphQL/Queries/ProjectInfo.php**

```php
<?php

namespace App\GraphQL\Queries;

class ProjectInfo
{
    public function __invoke($rootValue, array $args, $context)
    {
        $project = $context->request->project;
        
        return [
            'project_uuid' => $project->project_uuid,
            'enabled_services' => $project->enabled_services,
            'secret_version' => $project->secret_version,
        ];
    }
}
```

---

## 🧪 Testing

### REST API with cURL

**JWT Authentication**
```bash
curl -X GET http://localhost:8000/api/user/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Accept: application/json"
```

**Project Authentication**
```bash
curl -X GET http://localhost:8000/api/project/info \
  -H "x-project-token: YOUR_PROJECT_TOKEN" \
  -H "Accept: application/json"
```

**Combined Authentication**
```bash
curl -X POST http://localhost:8000/api/secure/resource \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "x-project-token: YOUR_PROJECT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": "test"}'
```

### GraphQL Queries

**Query with JWT Auth**
```bash
curl -X POST http://localhost:8000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"query":"{ me { uuid email name } }"}'
```

**Expected Response:**
```json
{
  "data": {
    "me": {
      "uuid": "user-uuid-here",
      "email": "user@example.com",
      "name": "John Doe"
    }
  }
}
```

### GraphQL Playground

1. Access GraphQL Playground at `http://localhost:8000/graphql-playground`
2. Add headers in the bottom left:

```json
{
  "Authorization": "Bearer YOUR_JWT_TOKEN",
  "x-project-token": "Bearer YOUR_PROJECT_TOKEN"
}
```

3. Run queries:

```graphql
query {
  me {
    uuid
    email
    name
  }
  
  projectInfo {
    project_uuid
    enabled_services
  }
}
```

---

## 🔍 Troubleshooting

<details>
<summary><strong>❌ "No directive found for jwtAuth"</strong></summary>

**Solution:**
1. Add directive namespace to `config/lighthouse.php`
2. Clear all caches:
```bash
php artisan config:clear
php artisan lighthouse:clear-cache
composer dump-autoload
```
</details>

<details>
<summary><strong>❌ "Class Predis\Client not found"</strong></summary>

**Solution:**
```bash
composer require predis/predis
php artisan config:clear
```

Or change `.env`:
```properties
REDIS_CLIENT=phpredis
```
</details>

<details>
<summary><strong>❌ "Could not connect to Redis"</strong></summary>

**Solution:**

1. Verify Redis is running:
```bash
redis-cli ping  # Should return: PONG
```

2. Check your `.env`:
```properties
# For Docker
REDIS_HOST=redis

# For local
REDIS_HOST=127.0.0.1
```

3. Test connection:
```bash
php artisan tinker
Redis::ping();
```
</details>

<details>
<summary><strong>❌ "JWKS endpoint returned 401"</strong></summary>

**Solution:**

Check that `SIGNATURE_SHARED_SECRET` in `.env` matches your Mercury service configuration.
</details>

<details>
<summary><strong>❌ "Token has been revoked or expired"</strong></summary>

**Solution:**

The project token is either:
- Not found in Redis (expired)
- Manually revoked

Generate a new project token from your provisioning service.
</details>

### Docker-Specific Issues

**Redis Connection Refused**

Update `docker-compose.yml`:
```yaml
services:
  app:
    depends_on:
      - redis
    environment:
      - REDIS_HOST=redis
      
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
```

**PhpRedis Not Installed**

Add to your `Dockerfile`:
```dockerfile
RUN pecl install redis && docker-php-ext-enable redis
```

Then rebuild:
```bash
docker-compose build --no-cache
docker-compose up -d
```

---

## 🔥 Advanced Usage

### Programmatic Token Validation

```php
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;

class AuthController
{
    public function validateJwt(JwtAuthService $jwtService, Request $request)
    {
        try {
            $token = $request->bearerToken();
            $user = $jwtService->authenticate($token);
            
            return response()->json(['user' => $user]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
    
    public function validateProject(ProjectAuthService $projectService, Request $request)
    {
        try {
            $token = $request->header('x-project-token');
            $serviceId = config('auth-guard.service_id');
            
            $project = $projectService->authenticateWithToken($token, $serviceId);
            
            return response()->json(['project' => $project]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
}
```

### Token Revocation

```php
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;

Route::post('/logout', function (JwtAuthService $jwtService, Request $request) {
    $jti = $request->input('jti'); // JWT ID from token payload
    $ttl = 3600; // Revoke for 1 hour
    
    $jwtService->revokeToken($jti, $ttl);
    
    return response()->json(['message' => 'Token revoked']);
})->middleware('jwt.auth');
```

---

## 📚 Documentation

| Topic | Description |
|-------|-------------|
| **Middleware** | `jwt.auth`, `project.auth`, `combined.auth` |
| **Directives** | `@jwtAuth`, `@projectAuth`, `@combinedAuth` |
| **Services** | `JwtAuthService`, `ProjectAuthService` |
| **Caching** | Redis-based JWKS and token caching |

---

## 🤝 Support

For issues or questions:

- **GitHub Issues:** [Report an issue](https://github.com/wazobia/laravel-auth-guard/issues)
- **Email:** developer@wazobia.tech
- **Documentation:** [Full Documentation](https://docs.wazobia.tech)

---

## 📄 License

This package is open-sourced software licensed under the [MIT license](LICENSE.md).

---

<div align="center">

**Made with ❤️ by [Wazobia Technologies](https://wazobia.tech)**

⭐ Star us on GitHub if this helped you!

</div>