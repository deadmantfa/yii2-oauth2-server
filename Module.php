<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server;

use deadmantfa\yii2\oauth2\server\components\Psr7\ServerRequest;
use deadmantfa\yii2\oauth2\server\components\Psr7\ServerResponse;
use deadmantfa\yii2\oauth2\server\components\Repositories\BearerTokenRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\ClientRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\MacTokenRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\ScopeRepository;
use deadmantfa\yii2\oauth2\server\components\ResponseTypes\MacTokenResponse;
use deadmantfa\yii2\oauth2\server\components\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Yii;
use yii\base\Application;
use yii\base\BootstrapInterface;
use yii\base\InvalidConfigException;
use yii\helpers\ArrayHelper;
use yii\rest\UrlRule;
use yii\web\GroupUrlRule;

class Module extends \yii\base\Module implements BootstrapInterface
{
    public $controllerMap = [];
    public array $urlManagerRules = [];
    public $privateKey;
    public $publicKey;
    public $encryptionKey;
    public $enableGrantTypes;
    public $cache = [];

    private ?AuthorizationServer $_authorizationServer = null;
    private ?ResponseTypeInterface $_responseType = null;
    private ?ServerRequest $_serverRequest = null;
    private ?ServerResponse $_serverResponse = null;

    public function bootstrap($app): void
    {
        if ($app instanceof Application) {
            $app->urlManager->addRules(
                (new GroupUrlRule([
                    'ruleConfig' => [
                        'class' => UrlRule::class,
                        'pluralize' => false,
                        'only' => ['create', 'options'],
                    ],
                    'rules' => ArrayHelper::merge([
                        ['controller' => $this->uniqueId . '/authorize'],
                        ['controller' => $this->uniqueId . '/revoke'],
                        ['controller' => $this->uniqueId . '/token'],
                    ], $this->urlManagerRules),
                ]))->rules,
                false
            );
        }
    }

    public function init(): void
    {
        parent::init();

        if (!$this->privateKey instanceof CryptKey) {
            $this->privateKey = new CryptKey($this->privateKey);
        }

        if (!$this->publicKey instanceof CryptKey) {
            $this->publicKey = new CryptKey($this->publicKey);
        }
    }

    /**
     * @throws InvalidConfigException
     */
    public function getAuthorizationServer(): AuthorizationServer
    {
        if (!$this->_authorizationServer instanceof AuthorizationServer) {
            $this->_authorizationServer = new AuthorizationServer(
                $this->getClientRepository(),
                $this->getAccessTokenRepository(),
                $this->getScopeRepository(),
                $this->privateKey,
                $this->encryptionKey,
                $this->_responseType
            );

            if (is_callable($this->enableGrantTypes)) {
                call_user_func($this->enableGrantTypes, $this);
            } else {
                throw new InvalidConfigException('No grant types enabled.');
            }
        }

        return $this->_authorizationServer;
    }

    /**
     * @throws InvalidConfigException
     */
    public function getClientRepository(): ClientRepositoryInterface
    {
        return Yii::createObject(ClientRepository::class);
    }

    public function getAccessTokenRepository(): AccessTokenRepositoryInterface
    {
        $responseType = $this->_responseType ?? $this->getResponseType();

        if ($responseType instanceof MacTokenResponse) {
            return new MacTokenRepository($this->encryptionKey);
        }

        return new BearerTokenRepository();
    }

    public function getResponseType(): ResponseTypeInterface
    {
        if ($this->_responseType === null) {
            $this->_responseType = new MacTokenResponse();
        }

        return $this->_responseType;
    }

    /**
     * @throws InvalidConfigException
     */
    public function getScopeRepository(): ScopeRepositoryInterface
    {
        return Yii::createObject(ScopeRepository::class);
    }

    /**
     * @throws InvalidConfigException
     */
    public function getServerRequest(): ServerRequest
    {
        if (!$this->_serverRequest instanceof ServerRequest) {
            $this->_serverRequest = new ServerRequest(Yii::$app->request);
        }

        return $this->_serverRequest;
    }

    public function getServerResponse(): ServerResponse
    {
        if (!$this->_serverResponse instanceof ServerResponse) {
            $this->_serverResponse = new ServerResponse();
        }

        return $this->_serverResponse;
    }
}
