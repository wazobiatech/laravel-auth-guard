<?php

namespace Wazobia\LaravelAuthGuard;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use Wazobia\LaravelAuthGuard\Middleware\JwtAuthMiddleware;
use Wazobia\LaravelAuthGuard\Middleware\ProjectAuthMiddleware;
use Wazobia\LaravelAuthGuard\Middleware\CombinedAuthMiddleware;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Services\JwksService;

class AuthGuardServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge config
        $this->mergeConfigFrom(
            __DIR__ . '/config/auth-guard.php', 
            'auth-guard'
        );

        // Register services as singletons
        $this->app->singleton(JwksService::class, function ($app) {
            return new JwksService(
                config('auth-guard.mercury.base_url'),
                config('auth-guard.default_project_uuid'),
                config('auth-guard.signature.shared_secret')
            );
        });

        $this->app->singleton(JwtAuthService::class, function ($app) {
            return new JwtAuthService(
                $app->make(JwksService::class),
                config('auth-guard.mercury.base_url'),
                config('auth-guard.cache.ttl')
            );
        });

        $this->app->singleton(ProjectAuthService::class, function ($app) {
            return new ProjectAuthService();
        });

        // Register middleware aliases
        $this->app->singleton('auth.jwt', function ($app) {
            return new JwtAuthMiddleware($app->make(JwtAuthService::class));
        });

        $this->app->singleton('auth.project', function ($app) {
            return new ProjectAuthMiddleware($app->make(ProjectAuthService::class));
        });

        $this->app->singleton('auth.combined', function ($app) {
            return new CombinedAuthMiddleware(
                $app->make(JwtAuthService::class),
                $app->make(ProjectAuthService::class)
            );
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/config/auth-guard.php' => config_path('auth-guard.php'),
        ], 'auth-guard-config');

        // Register middleware
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('jwt.auth', JwtAuthMiddleware::class);
        $router->aliasMiddleware('project.auth', ProjectAuthMiddleware::class);
        $router->aliasMiddleware('combined.auth', CombinedAuthMiddleware::class);

        // Register GraphQL directives if Lighthouse is installed
        if (class_exists('Nuwave\Lighthouse\LighthouseServiceProvider')) {
            $this->registerGraphQLDirectives();
        }
    }

    /**
     * Register GraphQL directives
     */
    protected function registerGraphQLDirectives(): void
    {
        // Register directive classes
        $this->app->bind(
            'Nuwave\Lighthouse\Schema\Directives\JwtAuthDirective',
            \Wazobia\LaravelAuthGuard\GraphQL\Directives\JwtAuthDirective::class
        );

        $this->app->bind(
            'Nuwave\Lighthouse\Schema\Directives\ProjectAuthDirective',
            \Wazobia\LaravelAuthGuard\GraphQL\Directives\ProjectAuthDirective::class
        );

        $this->app->bind(
            'Nuwave\Lighthouse\Schema\Directives\CombinedAuthDirective',
            \Wazobia\LaravelAuthGuard\GraphQL\Directives\CombinedAuthDirective::class
        );
    }
}