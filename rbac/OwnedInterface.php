<?php

namespace deadmantfa\yii2\oauth2\server\rbac;

use yii\web\IdentityInterface;

/**
 * Interface OwnableInterface
 * @package app\components\rbac
 */
interface OwnedInterface
{
    /**
     * @see IdentityInterface::getId()
     * @return integer|string|null
     */
    public function getOwnerId();
}
