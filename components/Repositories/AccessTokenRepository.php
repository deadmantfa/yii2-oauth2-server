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
    public function persistNewAccessToken(AccessTokenEntityInterface $accessToken): void
    {
        $model = new AccessToken();
        $model->client_id = $accessToken->getClient()->getIdentifier();
        $model->user_id = $accessToken->getUserIdentifier();
        $model->identifier = $accessToken->getIdentifier();
        $model->expired_at = $accessToken->getExpiryDateTime()->getTimestamp(); // Ensure expired_at is set
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
        return !$token || (bool)$token->is_revoked;
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        $token = new AccessToken();
        $token->client_id = $clientEntity->getIdentifier();
        $token->user_id = $userIdentifier;

        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }

        return $token;
    }
}
