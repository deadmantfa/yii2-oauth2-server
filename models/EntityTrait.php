<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use LogicException;
use Yii;
use yii\db\ActiveRecordInterface;

trait EntityTrait
{
    /**
     * Gets the entity's identifier.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        if (empty($this->identifier)) {
            Yii::error('AccessToken identifier is missing.', 'auth');
            throw new LogicException('AccessToken identifier must not be null or empty.');
        }

        return $this->identifier;
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
