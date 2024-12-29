<?php

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Yii;
use yii\base\Component;

class ClientRepository extends Component implements ClientRepositoryInterface
{
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $modelClass = Yii::$app->getModule('oauth2')->getModel('Client');
        $client = $modelClass::findByIdentifier($clientIdentifier);

        if (!$client) {
            return null;
        }

        return $client;
    }

    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool
    {
        $modelClass = Yii::$app->getModule('oauth2')->getModel('Client');
        $client = $modelClass::findEntity($clientIdentifier, $grantType, $clientSecret, true);

        return $client !== null;
    }
}