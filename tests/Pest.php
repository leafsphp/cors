<?php

declare(strict_types=1);

function corsIsOriginAllowed($allowedOrigin): bool
{
    $method = new ReflectionMethod(\Leaf\Http\Cors::class, 'isOriginAllowed');
    $method->setAccessible(true);

    return (bool) $method->invoke(null, $allowedOrigin);
}

function corsConfig(): array
{
    $property = new ReflectionProperty(\Leaf\Http\Cors::class, 'config');
    $property->setAccessible(true);

    return $property->getValue();
}
