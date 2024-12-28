<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use yii\db\ActiveRecordInterface;

trait EntityTrait
{
    /**
     * Gets the entity's identifier.
     *
     * @return string|int|null
     */
    public function getIdentifier(): string|int|null
    {
        /** @var ActiveRecordInterface $this */
        return $this->getAttribute('identifier');
    }

    /**
     * Sets the entity's identifier.
     *
     * @param string|int $identifier
     */
    public function setIdentifier(string|int $identifier): void
    {
        /** @var ActiveRecordInterface $this */
        $this->setAttribute('identifier', $identifier);
    }
}
