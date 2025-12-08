<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Closure;
use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Nuwave\Lighthouse\Schema\Values\FieldValue;
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

    public function handleField(FieldValue $fieldValue): void
    {
        $fieldValue->wrapResolver(fn (callable $resolver) => function ($root, array $args, $context, $info) use ($resolver) {
            return GraphQLAuthHelper::jwtAuth($root, $args, $context, $info, fn () => $resolver($root, $args, $context, $info));
        });
    }
}