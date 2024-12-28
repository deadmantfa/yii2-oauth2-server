<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use yii\caching\Dependency;

interface RepositoryCacheInterface
{
    /**
     * @return int|null
     */
    public function getCacheDuration(): ?int;

    /**
     * @return Dependency|null
     */
    public function getCacheDependency(): ?Dependency;

    /**
     * @param int $cacheDuration
     * @return $this
     */
    public function setCacheDuration(int $cacheDuration): static;

    /**
     * @param Dependency $cacheDependency
     * @return $this
     */
    public function setCacheDependency(Dependency $cacheDependency): static;

    /**
     * @param array|null $cache
     * @return $this
     */
    public function setCache(?array $cache): static;
}
