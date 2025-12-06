<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Closure;
use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Wazobia\LaravelAuthGuard\GraphQL\GraphQLAuthHelper;

class JwtAuthDirective extends BaseDirective implements FieldMiddleware
{
    public static function definition(): string
    {
        return /** @lang GraphQL */ '
            """
            Requires JWT authentication for this field
            """
            directive @jwtAuth on FIELD_DEFINITION
        ';
    }

    public function handleField($fieldValue, Closure $next)
    {
        return function ($root, array $args, $context, $info) use ($next, $fieldValue) {
            return GraphQLAuthHelper::jwtAuth($root, $args, $context, $info, function () use ($next, $fieldValue, $root, $args, $context, $info) {
                return $next($fieldValue)($root, $args, $context, $info);
            });
        };
    }
}