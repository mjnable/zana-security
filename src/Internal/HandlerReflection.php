<?php

declare(strict_types=1);

namespace Zana\Security\Internal;

use Closure;

/**
 * Reflects the matched route handler (the "_handler" request attribute) so
 * middleware can read attributes on its class and method.
 *
 * @internal
 */
final class HandlerReflection
{
    /**
     * @return list<\ReflectionClass<object>|\ReflectionMethod|\ReflectionFunction>
     */
    public static function targets(mixed $handler): array
    {
        return match (true) {
            $handler instanceof Closure => [new \ReflectionFunction($handler)],
            is_string($handler) && class_exists($handler) => self::classAndMethod($handler, '__invoke'),
            is_array($handler) && is_string($handler[0] ?? null) && is_string($handler[1] ?? null) && class_exists($handler[0]) => self::classAndMethod($handler[0], $handler[1]),
            default => [],
        };
    }

    /**
     * @param class-string $attribute
     */
    public static function has(mixed $handler, string $attribute): bool
    {
        foreach (self::targets($handler) as $target) {
            if ($target->getAttributes($attribute) !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * The attribute on the method, otherwise on the class.
     *
     * @template T of object
     * @param class-string<T> $attribute
     * @return T|null
     */
    public static function firstAttribute(mixed $handler, string $attribute): ?object
    {
        foreach (array_reverse(self::targets($handler)) as $target) {
            foreach ($target->getAttributes($attribute) as $found) {
                return $found->newInstance();
            }
        }

        return null;
    }

    /**
     * @param class-string $class
     *
     * @return list<\ReflectionClass<object>|\ReflectionMethod>
     */
    private static function classAndMethod(string $class, string $method): array
    {
        $reflection = new \ReflectionClass($class);

        return $reflection->hasMethod($method) ? [$reflection, $reflection->getMethod($method)] : [$reflection];
    }
}
