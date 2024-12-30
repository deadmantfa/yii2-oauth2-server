<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use deadmantfa\yii2\oauth2\server\models\AccessToken;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use RuntimeException;
use Yii;
use yii\db\Exception;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * @throws Exception
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $model = new AccessToken();
        $model->client_id = $accessTokenEntity->getClient()->getId();
        $model->user_id = $accessTokenEntity->getUserIdentifier();
        $model->identifier = $accessTokenEntity->getIdentifier();
        $model->expired_at = $accessTokenEntity->getExpiryDateTime()->getTimestamp(); // Ensure expired_at is set
        $model->status = AccessToken::STATUS_ACTIVE;

        if (!$model->save()) {
            Yii::error('Failed to save access token: ' . json_encode($model->getErrors()), 'auth');
            throw new RuntimeException('Failed to save access token');
        }
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $token = AccessToken::findOne(['identifier' => $tokenId]);
        $token?->updateAttributes(['is_revoked' => true]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $token = AccessToken::findOne(['identifier' => $tokenId]);
        return !$token || $token->is_revoked;
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        // Ensure no pre-existing tokens are reused
        $newToken = new AccessToken();
        $newToken->setClient($clientEntity);
        $newToken->setUserIdentifier($userIdentifier);
        foreach ($scopes as $scope) {
            $newToken->addScope($scope);
        }

        return $newToken;
    }
}
