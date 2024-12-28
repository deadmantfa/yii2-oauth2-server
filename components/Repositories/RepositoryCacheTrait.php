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

    public function setCacheDuration(int $cacheDuration): self
    {
        $this->_cacheDuration = $cacheDuration;
        return $this;
    }

    public function getCacheDependency(): ?Dependency
    {
        return $this->_cacheDependency;
    }

    public function setCacheDependency(?Dependency $cacheDependency): self
    {
        $this->_cacheDependency = $cacheDependency;
        return $this;
    }

    public function setCache(?array $config): self
    {
        if (isset($config['cacheDuration'])) {
            $this->setCacheDuration((int)$config['cacheDuration']);
        }

        if (isset($config['cacheDependency'])) {
            $this->setCacheDependency($config['cacheDependency']);
        }

        return $this;
    }
}
