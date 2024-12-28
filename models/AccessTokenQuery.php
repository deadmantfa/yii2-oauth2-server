<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use yii\db\ActiveQuery;

class AccessTokenQuery extends ActiveQuery
{
    public function type(int $type): self
    {
        return $this->andWhere(['type' => $type]);
    }

    public function expired(): self
    {
        return $this;
    }
}
