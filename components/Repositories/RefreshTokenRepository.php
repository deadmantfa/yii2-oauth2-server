<?php

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use deadmantfa\yii2\oauth2\server\models\RefreshToken;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
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
     * @param RefreshTokenEntityInterface|RefreshToken $refreshTokenEntity
     * @return RefreshTokenEntityInterface|RefreshToken
     * @throws OAuthServerException|Exception
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        if ($refreshTokenEntity instanceof RefreshToken) {
            $refreshTokenEntity->expired_at = $refreshTokenEntity->getExpiryDateTime()->getTimestamp();
            if (!$refreshTokenEntity->save()) {
                throw OAuthServerException::serverError('Failed to save refresh token.');
            }
        } else {
            throw new RuntimeException('Invalid refresh token entity.');
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
     * @return RefreshToken|null
     */
    protected function getCachedToken($tokenId, int $duration = null, Dependency $dependency = null): ?RefreshToken
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
        if ($token) {
            $token->updateAttributes(['status' => RefreshToken::STATUS_REVOKED]);
            TagDependency::invalidate(Yii::$app->cache, static::class);
        }
    }
}
