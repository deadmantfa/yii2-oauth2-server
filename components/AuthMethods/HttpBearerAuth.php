<?php
namespace deadmantfa\yii2\oauth2\server\components\AuthMethods;

use deadmantfa\yii2\oauth2\server\components\AuthorizationValidators\BearerTokenValidator;
use deadmantfa\yii2\oauth2\server\components\Repositories\BearerTokenRepository;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class HttpBearerAuth extends AuthMethod
{
    /**
     * @var string the HTTP authentication realm
     */
    public $realm = 'api';

    private $_authorizationValidator;
    private $_accessTokenRepository;


    /**
     * {@inheritdoc}
     */
    public function challenge($response)
    {
        $response->getHeaders()->set('WWW-Authenticate', "Bearer realm=\"{$this->realm}\"");
    }

    /**
     * @return string
     */
    protected function getTokenType()
    {
        return 'Bearer';
    }

    /**
     * @return AuthorizationValidatorInterface
     * @throws \yii\base\InvalidConfigException
     */
    protected function getAuthorizationValidator()
    {
        if (!$this->_authorizationValidator instanceof AuthorizationValidatorInterface) {
            $this->_authorizationValidator = new BearerTokenValidator($this->getAccessTokenRepository());
        }

        return $this->_authorizationValidator;
    }

    /**
     * @return AccessTokenRepositoryInterface
     * @throws \yii\base\InvalidConfigException
     */
    protected function getAccessTokenRepository()
    {
        if (!$this->_accessTokenRepository instanceof AccessTokenRepositoryInterface) {
            $this->_accessTokenRepository = new BearerTokenRepository();
        }

        return $this->_accessTokenRepository;
    }
}
