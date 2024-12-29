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
        Yii::info('Persisting new access token with expiry: ' . $accessTokenEntity->getExpiryDateTime()->format('Y-m-d H:i:s'), 'auth');
        $token = new AccessToken([
            'identifier' => $accessTokenEntity->getIdentifier(),
            'expiry_date_time' => $accessTokenEntity->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'user_id' => $accessTokenEntity->getUserIdentifier(),
            'scopes' => json_encode($accessTokenEntity->getScopes()),
        ]);

        if (!$token->save()) {
            throw new RuntimeException('Failed to save access token.');
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
