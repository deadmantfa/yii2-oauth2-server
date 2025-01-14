<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use yii\db\ActiveQuery;

trait TokenQueryTrait
{
    /**
     * Filters active tokens.
     */
    public function active(): static
    {
        /** @var ActiveQuery $this */
        /** @var AccessToken|RefreshToken $modelClass */
        $modelClass = $this->modelClass;
        return $this->andWhere(['status' => $modelClass::STATUS_ACTIVE]);
    }

    /**
     * Filters revoked tokens.
     */
    public function revoked(): static
    {
        /** @var ActiveQuery $this */
        /** @var AccessToken|RefreshToken $modelClass */
        $modelClass = $this->modelClass;
        return $this->andWhere(['<>', 'status', $modelClass::STATUS_ACTIVE]);
    }
}
