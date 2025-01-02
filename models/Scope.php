<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use yii\db\ActiveRecord;

class Scope extends ActiveRecord implements ScopeEntityInterface
{
    public static function tableName(): string
    {
        return '{{%auth__scope}}';
    }

    /**
     * @inheritdoc
     * @return ClientQuery
     */
    public static function find(): ScopeQuery
    {
        return new ScopeQuery(get_called_class());
    }

    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }
}
