<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use deadmantfa\yii2\oauth2\server\models\Client;
use deadmantfa\yii2\oauth2\server\models\Scope;
use Exception;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Throwable;
use yii\db\ActiveQuery;

class ScopeRepository implements ScopeRepositoryInterface, RepositoryCacheInterface
{
    use RepositoryCacheTrait;

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        try {
            return Scope::getDb()
                ->cache(
                    fn() => Scope::find()->identifier($identifier)->one(),
                    $this->getCacheDuration(),
                    $this->getCacheDependency()
                );
        } catch (Throwable $e) {
            // Log or handle exception as needed
            return null;
        }
    }

    public function finalizeScopes(
        array                 $scopes,
        string                $grantType,
        ClientEntityInterface $clientEntity,
        ?string               $userIdentifier = null,
        ?string               $authCodeId = null
    ): array
    {
        try {
            /** @var Client $clientEntity */
            return $clientEntity::getDb()
                ->cache(
                    function () use ($scopes, $grantType, $clientEntity, $userIdentifier) {
                        $query = $clientEntity->getRelatedScopes(
                            fn(ActiveQuery $query) => $this->applyScopeFilters($query, $scopes, $grantType, $userIdentifier)
                        );
                        return $query->all();
                    },
                    $this->getCacheDuration(),
                    $this->getCacheDependency()
                );
        } catch (Throwable $e) {
            // Log or handle exception as needed
            return [];
        }
    }

    /**
     * @throws Exception
     */
    private function applyScopeFilters(
        ActiveQuery $query,
        array       $scopes,
        string      $grantType,
        ?string     $userIdentifier
    ): void
    {
        if ($scopes === []) {
            $query->andWhere(['is_default' => true]);
        }

        $query->andWhere(['or', ['user_id' => null], ['user_id' => $userIdentifier]])
            ->andWhere(['or', ['grant_type' => null], ['grant_type' => Client::getGrantTypeId($grantType)]]);

        if ($scopes !== []) {
            $query->andWhere(['in', 'identifier', $scopes]);
        }
    }
}
