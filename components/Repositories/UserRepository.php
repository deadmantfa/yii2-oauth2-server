<?php

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use api\modules\v1\models\User;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

class UserRepository implements UserRepositoryInterface
{

    /**
     * @throws OAuthServerException
     */
    public function getUserEntityByUserCredentials(string $username, string $password, string $grantType, ClientEntityInterface $clientEntity): User
    {

        // Find user by username
        $user = User::findOne(['username' => $username]);

        if (!$user) {
            throw OAuthServerException::invalidCredentials();
        }

        // Verify password
        if (!password_verify($password, $user->password_hash)) {
            throw OAuthServerException::invalidCredentials();
        }

        return $user;
    }
}