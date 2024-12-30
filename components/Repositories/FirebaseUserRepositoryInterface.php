<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\RepositoryInterface;

interface FirebaseUserRepositoryInterface extends RepositoryInterface
{
    /**
     * Get a user entity.
     *
     * @param string $firebaseId
     * @param string $grantType The grant type used
     * @param ClientEntityInterface $clientEntity
     */
    public function getUserEntityByFirebaseId(
        string                $firebaseId,
        string                $grantType,
        ClientEntityInterface $clientEntity
    );


}
