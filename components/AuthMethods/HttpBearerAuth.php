<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\AuthMethods;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Yii;
use yii\base\InvalidConfigException;

class HttpBearerAuth extends AuthMethod
{
    public string $realm = 'api';

    private ?AuthorizationValidatorInterface $_authorizationValidator = null;
    private ?AccessTokenRepositoryInterface $_accessTokenRepository = null;

    public function challenge($response): void
    {
        $response->getHeaders()->set('WWW-Authenticate', "Bearer realm=\"$this->realm\"");
    }

    protected function getTokenType(): string
    {
        return 'Bearer';
    }

    /**
     * @throws InvalidConfigException
     */
    protected function getAuthorizationValidator(): AuthorizationValidatorInterface
    {
        if ($this->_authorizationValidator === null) {
            $this->_authorizationValidator = new BearerTokenValidator($this->getAccessTokenRepository());
        }
        return $this->_authorizationValidator;
    }

    /**
     * @throws InvalidConfigException
     */
    protected function getAccessTokenRepository(): AccessTokenRepositoryInterface
    {
        if ($this->_accessTokenRepository === null) {
            $this->_accessTokenRepository = Yii::createObject(AccessTokenRepositoryInterface::class);
        }
        return $this->_accessTokenRepository;
    }
}
