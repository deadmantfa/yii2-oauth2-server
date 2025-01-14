<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/components',
        __DIR__ . '/controllers',
        __DIR__ . '/models',
        __DIR__ . '/rbac',
    ])
    // uncomment to reach your current PHP version
    // ->withPhpSets()
    ->withRootFiles()
    ->withTypeCoverageLevel(20)
    ->withDeadCodeLevel(20)
    ->withCodeQualityLevel(20);
