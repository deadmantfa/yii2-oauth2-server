<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use yii\caching\Dependency;

interface RepositoryCacheInterface
{
    public function getCacheDuration(): ?int;

    public function getCacheDependency(): ?Dependency;

    /**
     * @return $this
     */
    public function setCacheDuration(int $cacheDuration): static;

    /**
     * @return $this
     */
    public function setCacheDependency(Dependency $cacheDependency): static;

    /**
     * @return $this
     */
    public function setCache(?array $cache): static;
}
