<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use Exception;
use yii\db\ActiveQuery;

class ClientQuery extends ActiveQuery
{
    public function active(): self
    {
        return $this->andWhere([Client::tableName() . '.status' => Client::STATUS_ACTIVE]);
    }

    /**
     * @throws Exception
     */
    public function grant(string|int $grantType): self
    {
        $grantTypeId = is_numeric($grantType) ? $grantType : Client::getGrantTypeId($grantType, -999);
        return $this->andWhere([Client::tableName() . '.grant_type' => $grantTypeId]);
    }

    public function identifier($clientIdentifier): self
    {
        return $this->andWhere([Client::tableName() . '.identifier' => $clientIdentifier]);
    }
}
