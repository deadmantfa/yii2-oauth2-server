<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use yii\caching\Dependency;

trait RepositoryCacheTrait
{
    private ?int $_cacheDuration = null;
    private ?Dependency $_cacheDependency = null;

    public function getCacheDuration(): ?int
    {
        return $this->_cacheDuration;
    }

    public function setCacheDuration(int $cacheDuration): static
    {
        $this->_cacheDuration = $cacheDuration;
        return $this;
    }

    public function getCacheDependency(): ?Dependency
    {
        return $this->_cacheDependency;
    }

    public function setCacheDependency(Dependency $cacheDependency): static
    {
        $this->_cacheDependency = $cacheDependency;
        return $this;
    }

    public function setCache(?array $cache): static
    {
        if (isset($cache['cacheDuration'])) {
            $this->setCacheDuration($cache['cacheDuration']);
        }

        if (isset($cache['cacheDependency'])) {
            $this->setCacheDependency($cache['cacheDependency']);
        }

        return $this;
    }
}
