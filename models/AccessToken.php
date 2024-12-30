<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\models;

use DateMalformedStringException;
use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Builder;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use LogicException;
use Yii;
use yii\base\InvalidConfigException;
use yii\db\ActiveQuery;
use yii\db\ActiveRecord;
use yii\filters\RateLimitInterface;
use yii\helpers\ArrayHelper;
use yii\helpers\VarDumper;

/**
 * Class AccessToken
 * @package deadmantfa\yii2\oauth2\server\models
 *
 * @property integer $id
 * @property integer $client_id
 * @property integer $user_id
 * @property string $identifier
 * @property string $mac_key
 * @property string $mac_algorithm
 * @property integer $type
 * @property integer $allowance
 * @property integer $allowance_updated_at
 * @property integer $created_at
 * @property integer $updated_at
 * @property integer $expired_at
 * @property integer $status
 *
 * @property Client $relatedClient
 * @property Scope[] $grantedScopes
 *
 * @todo save transaction
 */
class AccessToken extends ActiveRecord implements AccessTokenEntityInterface, RateLimitInterface
{
    use EntityTrait;
    use AccessTokenTrait, TokenEntityTrait;

    const TYPE_BEARER = 1;
    const TYPE_MAC = 2;

    const MAC_ALGORITHM_HMAC_SHA1 = 1;
    const MAC_ALGORITHM_HMAC_SHA256 = 2;

    const STATUS_ACTIVE = 1;
    const STATUS_REVOKED = -10;
    /**
     * @var mixed|null
     */
    public mixed $is_revoked;


    /**
     * {@inheritdoc}
     */
    public static function tableName(): string
    {
        return '{{%auth__access_token}}';
    }

    /**
     * {@inheritdoc}
     * @return AccessTokenQuery
     */
    public static function find(): AccessTokenQuery
    {
        return new AccessTokenQuery(get_called_class());
    }

    /**
     * @throws Exception
     */
    public function getMacAlgorithm()
    {
        return ArrayHelper::getValue(
            static::algorithms(),
            $this->mac_algorithm,
            'hmac-sha-256'
        );
    }

    public static function algorithms(): array
    {
        return [
            static::MAC_ALGORITHM_HMAC_SHA1 => 'hmac-sha-1',
            static::MAC_ALGORITHM_HMAC_SHA256 => 'hmac-sha-256',
        ];
    }

    public function rules(): array
    {
        return [
            [['client_id'], 'required'], // identifier
            [['user_id'], 'default'],
            ['identifier', 'default', 'value' => function () {
                return Yii::$app->security->generateRandomString(40);
            }],
            ['expired_at', 'default', 'value' => time() + 3600], // Default expiry
            ['expired_at', 'integer'],
            ['type', 'default', 'value' => static::TYPE_BEARER],
            ['type', 'in', 'range' => [static::TYPE_BEARER, static::TYPE_MAC]],
            ['mac_algorithm', 'default', 'value' => static::MAC_ALGORITHM_HMAC_SHA256],
            ['mac_algorithm', 'in', 'range' => array_keys(static::algorithms())],
            [['!allowance'], 'default'],
            [['!allowance_updated_at', '!created_at', '!updated_at'], 'default', 'value' => time()],
            ['status', 'default', 'value' => static::STATUS_ACTIVE],
            ['status', 'in', 'range' => [static::STATUS_REVOKED, static::STATUS_ACTIVE]],
        ];
    }

    /**
     * @throws InvalidConfigException
     */
    public function getGrantedScopes(): ActiveQuery
    {
        return $this->hasMany(Scope::class, ['id' => 'scope_id'])
            ->viaTable('{{auth__access_token_scope}}', ['access_token_id' => 'id']);
    }

    /**
     * {@inheritdoc}
     */
    public function getClient(): ClientEntityInterface
    {
        $client = $this->relatedClient;

        Yii::info('AccessToken::getClient(): Resolved client: ' . VarDumper::dumpAsString($client), 'auth');

        if (!$client instanceof ClientEntityInterface) {
            Yii::error('AccessToken::getClient() failed. No valid client entity found for client_id: ' . $this->client_id, 'auth');
            throw new LogicException('AccessToken::getClient(): Unable to resolve a valid client entity.');
        }

        return $client;
    }

    /**
     * @throws DateMalformedStringException
     */

    public function getExpiryDateTime(): DateTimeImmutable
    {
        if (empty($this->expired_at)) {
            Yii::error('The "expired_at" property is not set in AccessToken. Identifier: ' . $this->identifier, 'auth');
            throw new LogicException('The "expired_at" property must be set before calling getExpiryDateTime.');
        }

        return new DateTimeImmutable('@' . $this->expired_at);
    }

    public function getScopes(): array
    {
        if (empty($this->scopes)) {
            $this->scopes = $this->grantedScopes;
        }

        return array_values($this->scopes);
    }

    public function getRelatedClient(): ActiveQuery
    {
        $clientClass = Yii::$app->getModule('oauth2')->modelMap['Client'] ?? Client::class;
        Yii::info('AccessToken::getRelatedClient() using client class: ' . $clientClass, 'auth');
        return $this->hasOne($clientClass, ['identifier' => 'client_id']);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserIdentifier(): ?string
    {
        return (string)$this->user_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setUserIdentifier($identifier): void
    {
        $this->user_id = $identifier;
    }

    /**
     * {@inheritdoc}
     */
    public function getRateLimit($request, $action): array
    {
        return [1000, 600];
    }

    /**
     * {@inheritdoc}
     */
    public function loadAllowance($request, $action): array
    {
        return [
            $this->allowance === null ? 1000 : $this->allowance,
            $this->allowance_updated_at
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function saveAllowance($request, $action, $allowance, $timestamp): void
    {
        $this->updateAttributes([
            'allowance' => $allowance,
            'allowance_updated_at' => $timestamp,
            'updated_at' => $timestamp,
        ]);
    }

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        // Assuming you want to store it for later use
        $this->privateKey = $privateKey;
    }

    public function setExpiryDateTime(DateTimeImmutable $dateTime): void
    {
        $this->expired_at = $dateTime->getTimestamp();
    }

    public function setClient(ClientEntityInterface $client): void
    {
        $this->client_id = $client->getId();
    }

    public function addScope(ScopeEntityInterface $scope): void
    {
        // Ensure $this->scopes is initialized
        if (!is_array($this->scopes)) {
            $this->scopes = [];
        }
        $this->scopes[] = $scope;
    }

    /**
     * Override it in order to set additional public or private claims.
     *
     * @param Builder $builder
     * @return Builder
     * @see https://tools.ietf.org/html/rfc7519#section-4
     */
    protected function finalizeJWTBuilder(Builder $builder): Builder
    {
        return $builder;
    }
}
