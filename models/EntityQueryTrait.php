<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use yii\db\ActiveQuery;
use yii\db\ActiveRecord;

trait EntityQueryTrait
{
    /**
     * Filters by identifier.
     *
     * @param string|int $identifier
     * @param string|null $tableName
     * @return EntityQueryTrait
     */
    public function identifier(string|int $identifier, ?string $tableName = null): static
    {
        if ($tableName === null) {
            /** @var ActiveRecord $modelClass */
            $modelClass = $this->modelClass;
            $tableName = $modelClass::tableName();
        }

        /** @var ActiveQuery $this */
        return $this->andWhere([$tableName . '.`identifier`' => $identifier]);
    }
}
