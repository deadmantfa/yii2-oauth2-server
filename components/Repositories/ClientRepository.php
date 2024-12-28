<?php

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use deadmantfa\yii2\oauth2\server\models\Client;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use yii\base\Component;

class ClientRepository extends Component implements ClientRepositoryInterface
{
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $client = Client::findByIdentifier($clientIdentifier);
        if (!$client) {
            return null;
        }

        return $client;
    }

    /**
     * Validate the client (client_id, secret, grant_type).
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool
    {
        // Reuse your existing findEntity logic to check secret + grant
        $client = Client::findEntity($clientIdentifier, $grantType, $clientSecret, true);
        return $client !== null;
    }
}