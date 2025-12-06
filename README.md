# Wazobia Laravel Auth Guard

A comprehensive JWT and Project authentication package for Laravel with JWKS support, Redis caching, and GraphQL integration.

## Features

- 🔐 JWT authentication with JWKS support (RS512)
- 🏢 Project/API key authentication
- 🔄 Combined authentication (JWT + Project)
- 💾 Redis caching for performance
- 📊 GraphQL support (Laravel Lighthouse)
- ⚡ Auto-discovery and zero-config setup
- 🛡️ Token revocation support
- 📝 Comprehensive logging

## Requirements

- PHP >= 8.0
- Laravel >= 9.0
- Redis (recommended for caching)

## Installation

### Via Composer

```bash
composer require wazobia/laravel-auth-guard
```

### Publish Configuration (Optional)

```bash
php artisan vendor:publish --tag=auth-guard-config
```

## Configuration

Add the following to your `.env` file:

```env
# Mercury Service (JWT/JWKS)
MERCURY_BASE_URL=http://your-mercury-service.com
MERCURY_TIMEOUT=10

# Athens Service (Project Auth)
ATHENS_BASE_URL=http://your-athens-service.com
ATHENS_PROJECT_UUID=your-default-project-uuid
ATHENS_TIMEOUT=10

# Shared Secret for HMAC
SIGNATURE_SHARED_SECRET=your-shared-secret

# Cache Settings
AUTH_CACHE_TTL=900
AUTH_CACHE_PREFIX=auth_guard
AUTH_CACHE_DRIVER=redis

# JWT Settings
JWT_ALGORITHM=RS512
JWT_LEEWAY=0

# Logging
AUTH_GUARD_LOGGING=true
AUTH_GUARD_LOG_CHANNEL=stack

# Custom Headers (optional)
AUTH_JWT_HEADER=Authorization
AUTH_PROJECT_ID_HEADER=x-app-id
AUTH_PROJECT_SECRET_HEADER=x-app-secret
```

## Usage

### Route Middleware

#### JWT Authentication Only

```php
Route::middleware(['jwt.auth'])->group(function () {
    Route::get('/user/profile', function (Request $request) {
        $user = $request->auth_user;
        return response()->json($user);
    });
});
```

#### Project Authentication Only

```php
Route::middleware(['project.auth'])->group(function () {
    Route::get('/project/info', function (Request $request) {
        $project = $request->auth_project;
        return response()->json($project);
    });
});
```

#### Combined Authentication (JWT + Project)

```php
Route::middleware(['combined.auth'])->group(function () {
    Route::get('/secure/data', function (Request $request) {
        return response()->json([
            'user' => $request->auth_user,
            'project' => $request->auth_project,
        ]);
    });
});
```

### Controller Usage

```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class SecureController extends Controller
{
    public function __construct()
    {
        // Apply middleware to all methods
        $this->middleware('combined.auth');
        
        // Or apply to specific methods
        $this->middleware('jwt.auth')->only(['index', 'show']);
        $this->middleware('project.auth')->only(['store']);
    }

    public function index(Request $request)
    {
        $user = $request->auth_user;
        $project = $request->auth_project;
        
        return response()->json([
            'user_uuid' => $user['uuid'],
            'user_email' => $user['email'],
            'project_uuid' => $project['projectUuid'] ?? null,
            'project_name' => $project['projectName'] ?? null,
        ]);
    }
}
```

### GraphQL Support (Laravel Lighthouse)

If you have Laravel Lighthouse installed, the package automatically registers GraphQL directives:

```graphql
type Query {
    # JWT authentication required
    userProfile: User @jwtAuth
    
    # Project authentication required
    projectData: Project @projectAuth
    
    # Both JWT and Project authentication required
    sensitiveData: SecureData @combinedAuth
    
    # No authentication required
    publicData: PublicInfo
}

type Mutation {
    updateProfile(input: ProfileInput!): User @jwtAuth
    createResource(input: ResourceInput!): Resource @combinedAuth
}

On your resolver
public function create($root, array $args, GraphQLContext $context, ResolveInfo $resolveInfo): array
    {
        Log::info('Creating', [
            'auth_user' => $context->request->auth_user,
            'auth_project' => $context->request->auth_project,
            'args' => $args
        ]);
        ...continue ur execution/statements
    }
```

### Programmatic Usage

```php
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;

class AuthController extends Controller
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
    
    public function validateToken(Request $request)
    {
        try {
            // Validate JWT token
            $token = $request->bearerToken();
            $user = $this->jwtService->authenticate($token);
            
            return response()->json(['user' => $user]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
    
    public function revokeToken(Request $request)
    {
        // Revoke a JWT token by its JTI
        $jti = $request->input('jti');
        $this->jwtService->revokeToken($jti);
        
        return response()->json(['message' => 'Token revoked']);
    }
}
```

## Request Data Access

After successful authentication, the middleware adds the following to the request:

### JWT Authentication
```php
$request->auth_user = [
    'uuid' => 'user-uuid',
    'email' => 'user@example.com',
    'name' => 'User Name',
    'raw_payload' => [...] // Original JWT payload
];

// Also accessible via
$request->user(); // Returns object
```

### Project Authentication
```php
$request->auth_project = [
    'projectUuid' => 'project-uuid',
    'projectName' => 'Project Name',
    'raw_response' => [...] // Original Athens response
];
```

## Error Responses

All authentication failures return a 401 status with JSON:

```json
{
    "error": "JWT Authentication failed",
    "message": "Token expired"
}
```

## Testing

### Mocking Services

```php
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;

class AuthTest extends TestCase
{
    public function test_jwt_authentication()
    {
        $this->mock(JwtAuthService::class)
            ->shouldReceive('authenticate')
            ->once()
            ->andReturn([
                'uuid' => 'test-uuid',
                'email' => 'test@example.com',
                'name' => 'Test User',
            ]);

        $response = $this->withHeaders([
            'Authorization' => 'Bearer test.jwt.token',
        ])->get('/api/user/profile');

        $response->assertStatus(200);
        $response->assertJson([
            'uuid' => 'test-uuid',
            'email' => 'test@example.com',
        ]);
    }
    
    public function test_combined_authentication()
    {
        // Mock both services
        $this->mock(JwtAuthService::class)
            ->shouldReceive('authenticate')
            ->andReturn([
                'uuid' => 'user-uuid',
                'email' => 'user@example.com',
                'name' => 'Test User',
            ]);
            
        $this->mock(ProjectAuthService::class)
            ->shouldReceive('authenticate')
            ->andReturn([
                'projectUuid' => 'project-uuid',
                'projectName' => 'Test Project',
            ]);

        $response = $this->withHeaders([
            'Authorization' => 'Bearer test.jwt.token',
            'x-app-id' => 'test-app-id',
            'x-app-secret' => 'test-secret',
        ])->get('/api/secure/data');

        $response->assertStatus(200);
    }
}
```

## Advanced Configuration

### Custom Cache Keys

```php
// config/auth-guard.php
'cache' => [
    'prefix' => 'my_app_auth',
    'ttl' => 1800, // 30 minutes
],
```

### Custom Headers

```php
// config/auth-guard.php
'headers' => [
    'jwt' => 'X-Access-Token',
    'project_id' => 'X-API-Key',
    'project_secret' => 'X-API-Secret',
],
```

### Disable Logging

```php
// config/auth-guard.php
'logging' => [
    'enabled' => false,
],
```

## Troubleshooting

### Redis Connection Issues

Ensure Redis is properly configured in your `.env`:

```env
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379
CACHE_DRIVER=redis
```

### JWKS Fetch Errors

Check that:
1. Mercury service is accessible
2. SIGNATURE_SHARED_SECRET is correct
3. Project UUID exists in the JWT or ATHENS_PROJECT_UUID is set

### Token Validation Errors

Common issues:
- Expired tokens (check JWT_LEEWAY setting)
- Wrong issuer (verify MERCURY_BASE_URL)
- Invalid signature (ensure JWKS endpoint is returning correct keys)

## Support

For issues, questions, or contributions, please visit:
[GitHub Repository](https://github.com/wazobia/laravel-auth-guard)

## License

MIT License. See [LICENSE](LICENSE) file for details.