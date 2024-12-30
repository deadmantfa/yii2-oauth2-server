<?php

namespace deadmantfa\yii2\oauth2\server\models;

use DateMalformedStringException;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use LogicException;
use Yii;
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
        $accessToken = $this->hasOne(AccessToken::class, ['id' => 'access_token_id'])->one();

        if (!$accessToken) {
            Yii::error('RefreshToken::getAccessToken() failed. No valid access token found for access_token_id: ' . $this->access_token_id, 'auth');
            throw new LogicException('Invalid access token for refresh token with identifier: ' . $this->identifier);
        }

        if ($accessToken->status !== AccessToken::STATUS_ACTIVE) {
            Yii::error('RefreshToken::getAccessToken() found a revoked access token for access_token_id: ' . $this->access_token_id, 'auth');
            throw new LogicException('Access token is revoked for refresh token with identifier: ' . $this->identifier);
        }

        return $accessToken;
    }

    /**
     * {@inheritdoc}
     *
     * @param AccessTokenEntityInterface|ActiveRecord $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken): void
    {
        Yii::info('AccessToken PK check: ' . var_export($accessToken->getPrimaryKey(), true), 'auth');
        if (!$accessToken instanceof AccessToken) {
            Yii::error('Invalid AccessToken entity passed to setAccessToken.', 'auth');
            throw new LogicException('Invalid AccessToken entity.');
        }

        Yii::info('AccessToken details: ' . json_encode([
                'id' => $accessToken->id ?? null,
                'status' => $accessToken->status ?? null,
                'identifier' => $accessToken->identifier ?? null,
            ]), 'auth');

        if ($accessToken->status !== AccessToken::STATUS_ACTIVE) {
            Yii::error('Attempting to associate a revoked AccessToken with RefreshToken. AccessToken ID: ' . $accessToken->id, 'auth');
            throw new LogicException('Cannot associate a revoked AccessToken with RefreshToken.');
        }

        $this->access_token_id = $accessToken->getPrimaryKey();
        $this->populateRelation('accessToken', $accessToken);
    }

    public function setExpiryDateTime(DateTimeImmutable $dateTime): void
    {
        $this->expired_at = $dateTime->getTimestamp();
    }

    /**
     * @throws DateMalformedStringException
     */
    public function getExpiryDateTime(): DateTimeImmutable
    {
        if (empty($this->expired_at)) {
            throw new LogicException('The "expired_at" property must be set before calling getExpiryDateTime.');
        }

        return new DateTimeImmutable('@' . $this->expired_at);
    }
}
