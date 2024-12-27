<?php
/**
 *
 */

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use deadmantfa\yii2\oauth2\server\models\Client;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use yii\base\Component;

/**
 * Class ClientRepository
 * @package deadmantfa\yii2\oauth2\server\components\Repositories
 */
class ClientRepository extends Component implements ClientRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getClientEntity(
        $clientIdentifier,
        $grantType,
        $clientSecret = null,
        $mustValidateSecret = true
    ) {
        return Client::findEntity(
            $clientIdentifier,
            $grantType,
            $clientSecret,
            $mustValidateSecret
        );
    }
}
