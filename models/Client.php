<?php
/**
 *
 */

namespace deadmantfa\yii2\oauth2\server\models;

use deadmantfa\yii2\oauth2\server\components\ResponseTypes\BearerTokenResponse;
use deadmantfa\yii2\oauth2\server\components\ResponseTypes\MacTokenResponse;
use Exception;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Throwable;
use Yii;
use yii\base\InvalidConfigException;
use yii\db\ActiveQuery;
use yii\db\ActiveRecord;
use yii\helpers\ArrayHelper;

/**
 * Class Client
 * @package deadmantfa\yii2\oauth2\server\models
 *
 * @property integer $id
 * @property string $identifier
 * @property string $secret
 * @property string $name
 * @property string $redirect_uri
 * @property integer $token_type
 * @property integer $grant_type
 * @property integer $created_at
 * @property integer $updated_at
 * @property integer $status
 *
 * @property Scope[] $relatedScopes
 * @property Scope[] $relatedScopesDefault
 */
class Client extends ActiveRecord implements ClientEntityInterface
{
    const STATUS_DISABLED = -1;
    const STATUS_ACTIVE = 1;

    const TOKEN_TYPE_BEARER = AccessToken::TYPE_BEARER;
    const TOKEN_TYPE_MAC = AccessToken::TYPE_MAC;

    const GRANT_TYPE_AUTHORIZATION_CODE = 1;
    const GRANT_TYPE_IMPLICIT = 2;
    const GRANT_TYPE_PASSWORD = 3;
    const GRANT_TYPE_CLIENT_CREDENTIALS = 4;
    const GRANT_TYPE_REFRESH_TOKEN = 5;
    const GRANT_TYPE_REVOKE = 6;

    /**
     * @var ResponseTypeInterface
     */
    private ?ResponseTypeInterface $_responseType = null;


    /**
     * @inheritdoc
     */
    public static function tableName(): string
    {
        return '{{%auth__client}}';
    }

    /**
     * @param string $clientIdentifier
     * @param int|string $grantType
     * @param null $clientSecret
     * @param bool $mustValidateSecret
     * @return static|null
     */

    public static function findEntity(
        string     $clientIdentifier,
        string|int $grantType,
        ?string    $clientSecret = null,
        bool       $mustValidateSecret = true
    ): ?static
    {
        try {
            Yii::info('DB Query: ' . static::find()->active()->identifier($clientIdentifier)->grant($grantType)->createCommand()->getRawSql(), 'auth');
            $clientEntity = static::getDb()->cache(
                fn() => static::find()
                    ->active()
                    ->identifier($clientIdentifier)
                    ->grant($grantType)
                    ->one()
            );

            if (
                $clientEntity instanceof static &&
                (
                    !$clientEntity->getIsConfidential() ||
                    !$mustValidateSecret ||
                    static::secretVerify($clientSecret, $clientEntity->secret)
                )
            ) {
                return $clientEntity;
            }
        } catch (Throwable $e) {
            // Log or handle exception if necessary
        }

        return null;
    }

    /**
     * @inheritdoc
     * @return ClientQuery
     */
    public static function find(): ClientQuery
    {
        return new ClientQuery(get_called_class());
    }

    public function getIsConfidential(): bool
    {
        return $this->secret !== null;
    }

    public static function secretVerify(?string $secret, string $hash): bool
    {
        return $secret !== null && password_verify($secret, $hash);
    }

    /**
     * @throws Exception
     */
    public static function getGrantTypeId($grantType, $default = null)
    {
        return ArrayHelper::getValue(array_flip(static::grants()), $grantType, $default);
    }

    public static function grants(): array
    {
        return [
            static::GRANT_TYPE_AUTHORIZATION_CODE => 'authorization_code',
            static::GRANT_TYPE_IMPLICIT => 'implicit',
            static::GRANT_TYPE_PASSWORD => 'password',
            static::GRANT_TYPE_CLIENT_CREDENTIALS => 'client_credentials',
            static::GRANT_TYPE_REFRESH_TOKEN => 'refresh_token',
            static::GRANT_TYPE_REVOKE => 'revoke',
        ];
    }

    public static function secretHash($secret): string
    {
        return password_hash($secret, PASSWORD_DEFAULT);
    }

    public static function findByIdentifier(string $clientIdentifier): array|ActiveRecord|null
    {
        return static::find()
            ->active()
            ->identifier($clientIdentifier)
            ->one() ?: null;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRedirectUri(): array|string
    {
        return $this->redirect_uri;
    }


    public function getResponseType(): ResponseTypeInterface
    {
        if ($this->_responseType === null) {
            $this->_responseType = $this->token_type === self::TOKEN_TYPE_MAC
                ? new MacTokenResponse()
                : new BearerTokenResponse();
        }

        return $this->_responseType;
    }

    /**
     * @param callable|null $callable
     * @return ClientQuery|ActiveQuery
     * @throws InvalidConfigException
     */
    public function getRelatedScopes(callable $callable = null): ActiveQuery|ClientQuery
    {
        return $this->hasMany(Scope::class, ['id' => 'scope_id'])
            ->viaTable('{{auth__client_scope}}', ['client_id' => 'id'], $callable);
    }

    public function isConfidential(): bool
    {
        return true;
    }
}
