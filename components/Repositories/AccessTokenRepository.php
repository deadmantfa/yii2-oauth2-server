<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use DateMalformedStringException;
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
     * @throws DateMalformedStringException
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        // $accessTokenEntity IS the AR instance
        if (!$accessTokenEntity instanceof AccessToken) {
            throw new RuntimeException('Invalid AccessToken entity type');
        }
        $accessTokenEntity->identifier = $accessTokenEntity->getIdentifier();
        $accessTokenEntity->expired_at = $accessTokenEntity->getExpiryDateTime()->getTimestamp();
        $accessTokenEntity->status = AccessToken::STATUS_ACTIVE;

        if (!$accessTokenEntity->save()) {
            Yii::error('Failed to save access token: ' . json_encode($model->getErrors()), 'auth');
            throw new RuntimeException('Failed to save access token');
        }
        Yii::info('Saved AccessToken AR: ' . var_export($accessTokenEntity->id, true), 'auth');
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

        $newToken->status = AccessToken::STATUS_ACTIVE;
        // Generate a unique identifier for the token
//        $newToken->setIdentifier(Yii::$app->security->generateRandomString(40));
        return $newToken;
    }
}
