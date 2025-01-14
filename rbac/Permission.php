<?php

namespace deadmantfa\yii2\oauth2\server\rbac;

use yii\base\Configurable;
use yii\helpers\ArrayHelper;
use yii\rbac\ManagerInterface;

/**
 * Class Permission
 * @package deadmantfa\yii2\oauth2\server\rbac
 */
class Permission extends \yii\rbac\Permission implements Configurable
{
    /**
     * @var array child permissions configuration array
     */
    private $_children = [];


    /**
     * {@inheritdoc}
     */
    public function init(): void
    {
        parent::init();

        /** @var ManagerInterface $authManager */
        $authManager = \Yii::$app->authManager;
        $authManager->add($this);

        $this->prepareChildren($authManager);
    }

    /**
     * @internal
     * @return $this
     */
    protected function prepareChildren(ManagerInterface &$authManager): static
    {
        foreach ($this->getChildren() as $permissionName => $permission) {

            if (is_string($permission)) {
                $permission = class_exists($permission)
                    ? ['class' => $permission]
                    : ['name' => $permission];
            }

            if (is_array($permission)) {
                $permission = \Yii::createObject(
                    ArrayHelper::merge([
                        'class' => self::class,
                        'name' => $permissionName,
                    ], $permission)
                );
            }

            $authManager->add($permission);

            if ($authManager->canAddChild($this, $permission)) {
                $authManager->removeChild($this, $permission);
                $authManager->addChild($this, $permission);
            }
        }

        return $this;
    }

    /**
     * @return array
     */
    public function getChildren()
    {
        return $this->_children;
    }

    /**
     * @param array $children
     */
    public function setChildren($children): void
    {
        $this->_children = $children;
    }
}
