<?php

namespace deadmantfa\yii2\oauth2\server\rbac;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use yii\rbac\Item;
use yii\rbac\Rule;

/**
 * Checks whether associated RBAC item was granted for the access token.
 *
 * @package deadmantfa\yii2\oauth2\server\rbac
 */
class GrantedRule extends Rule
{
    /**
     * {@inheritdoc}
     */
    public $name = 'granted';

    /**
     * {@inheritdoc}
     */
    public function init(): void
    {
        parent::init();
        $this->createdAt = $this->updatedAt = time();
    }

    /**
     * {@inheritdoc}
     */
    public function execute($user, $item, $params)
    {
        $identity = \Yii::$app->user->identity;

        if (
            !$identity instanceof AccessTokenEntityInterface
            || !$item instanceof Item
        ) {
            return false;
        }

        return in_array($item->name, array_map(
                function (ScopeEntityInterface $scopeEntity): string {
                    return $scopeEntity->getIdentifier();
                }, $identity->getScopes()
            ));
    }
}
