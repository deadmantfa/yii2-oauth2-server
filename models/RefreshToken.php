<?php

namespace deadmantfa\yii2\oauth2\server\models;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use yii\db\ActiveRecord;

/**
 * Class RefreshToken
 * @package deadmantfa\yii2\oauth2\server\models
 *
 * @property integer $id
 * @property integer $access_token_id
 * @property string $identifier
 * @property integer $created_at
 * @property integer $updated_at
 * @property integer $status
 *
 * @property AccessToken $accessToken
 *
 * @todo model save transaction
 * @todo expiry date time + remove rt trait
 */
class RefreshToken extends ActiveRecord implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;

    const STATUS_ACTIVE = 1;
    const STATUS_REVOKED = -10;


    /**
     * {@inheritdoc}
     */
    public static function tableName(): string
    {
        return '{{%auth__refresh_token}}';
    }

    /**
     * {@inheritdoc}
     * @return RefreshTokenQuery
     */
    public static function find(): RefreshTokenQuery
    {
        return new RefreshTokenQuery(get_called_class());
    }

    /**
     * {@inheritdoc}
     */
    public function rules(): array
    {
        return [
            [['access_token_id', 'identifier'], 'required'],
            ['access_token_id', 'exist', 'targetClass' => AccessToken::class, 'targetAttribute' => 'id'],
            ['identifier', 'unique'],
            [['created_at', 'updated_at'], 'default', 'value' => time()],
            ['status', 'default', 'value' => static::STATUS_ACTIVE],
            ['status', 'in', 'range' => [static::STATUS_REVOKED, static::STATUS_ACTIVE]],
        ];
    }


    /**
     * Returns the related `AccessToken` entity.
     *
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->hasOne(AccessToken::class, ['id' => 'access_token_id'])->one();
    }

    /**
     * {@inheritdoc}
     *
     * @param AccessTokenEntityInterface|ActiveRecord $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken): void
    {
        if (
            !$this->isRelationPopulated('accessToken') &&
            $accessToken instanceof AccessToken
        ) {
            $this->setAttributes(['access_token_id' => $accessToken->getPrimaryKey()]);
            $this->populateRelation('accessToken', $accessToken);
        }
    }
}
