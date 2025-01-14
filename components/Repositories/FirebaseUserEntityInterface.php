<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

interface FirebaseUserEntityInterface
{
    /**
     * Return the user's identifier.
     */
    public function getIdentifier(): string;
}
