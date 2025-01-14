<?php

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use DateMalformedStringException;
use deadmantfa\yii2\oauth2\server\models\AccessToken;
use deadmantfa\yii2\oauth2\server\models\RefreshToken;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use LogicException;
use RuntimeException;
use Throwable;
use Yii;
use yii\base\Component;
use yii\caching\Dependency;
use yii\caching\TagDependency;
use yii\db\Exception;

/**
 * Class RefreshTokenRepository
 * @package deadmantfa\yii2\oauth2\server\components\Repositories
 */
class RefreshTokenRepository extends Component implements RefreshTokenRepositoryInterface, RepositoryCacheInterface
{
    use RepositoryCacheTrait;


    /**
     * {}
     *
     * @return RefreshTokenEntityInterface|RefreshToken
     */
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshToken();
    }

    /**
     * {@inheritdoc}
     *
     * @throws OAuthServerException|Exception|DateMalformedStringException
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        if (!$refreshTokenEntity instanceof RefreshToken) {
            throw new RuntimeException('Invalid RefreshToken entity.');
        }

        $accessToken = $refreshTokenEntity->getAccessToken();
        if ($accessToken->status !== AccessToken::STATUS_ACTIVE) {
            throw new LogicException('Cannot persist RefreshToken with an invalid or revoked AccessToken.');
        }

        $refreshTokenEntity->expired_at = $refreshTokenEntity->getExpiryDateTime()->getTimestamp();

        if (!$refreshTokenEntity->save()) {
            Yii::error('Failed to save RefreshToken: ' . json_encode($refreshTokenEntity->getErrors()), 'auth');
            throw OAuthServerException::serverError('Failed to save refresh token.');
        }
    }

    /**
     * {}
     * @throws Throwable
     */
    public function isRefreshTokenRevoked($tokenId): bool
    {
        $token = $this->getCachedToken($tokenId);
        return !$token || $token->status === RefreshToken::STATUS_REVOKED;
    }

    /**
     * @param $tokenId
     * @param int|null $duration
     * @param Dependency|null $dependency
     */
    protected function getCachedToken(string|int $tokenId, int $duration = null, Dependency $dependency = null): ?RefreshToken
    {
        try {
            $token = RefreshToken::getDb()
                ->cache(
                    function () use ($tokenId) {
                        return RefreshToken::find()
                            ->identifier($tokenId)
                            ->active()->one();
                    },
                    $duration,
                    $dependency instanceof Dependency
                        ? $dependency
                        : new TagDependency(['tags' => static::class])
                );
        } catch (Throwable $exception) {
            $token = null;
        }

        return $token;
    }

    /**
     * {}
     */
    public function revokeRefreshToken($tokenId): void
    {
        $token = $this->getCachedToken($tokenId);
        if ($token !== null) {
            $token->updateAttributes(['status' => RefreshToken::STATUS_REVOKED]);
            TagDependency::invalidate(Yii::$app->cache, static::class);
        }
    }
}
