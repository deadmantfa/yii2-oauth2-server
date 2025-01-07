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
use InvalidArgumentException;
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
    public $components = [];
    public $cache = [];
    public $modelMap = [
        'Client' => 'deadmantfa\yii2\oauth2\server\models\Client',
    ];
    private ?AuthorizationServer $_authorizationServer = null;
    private ?ServerRequest $_serverRequest = null;
    private ?ServerResponse $_serverResponse = null;
    private ?ResponseTypeInterface $_responseType = null;

    /**
     * Whether or not to apply a CORS filter automatically in plugin controllers.
     */
    public bool $enableCors = false;

    /**
     * Default or user-provided CORS config passed to Yii2's \yii\filters\Cors.
     */
    public array $corsConfig = [
        'class' => \yii\filters\Cors::class,
        'cors'  => [
            // Default CORS settings
            'Origin'                           => ['*'],
            'Access-Control-Allow-Credentials' => true,
            'Access-Control-Max-Age'           => 3600,
            'Access-Control-Allow-Methods'     => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
            'Access-Control-Allow-Headers'     => [
                'Authorization', 'Content-Type', 'X-Requested-With', 'Accept', 'Origin', 'Cache-Control', 'Pragma',
            ],
        ],
    ];
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

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        $this->privateKey = $this->createCryptKey($this->privateKey);
        $this->publicKey = $this->createCryptKey($this->publicKey);
    }

    /**
     * @throws InvalidConfigException
     */
    protected function createCryptKey(string $keyPath): CryptKey
    {
        if (!file_exists($keyPath)) {
            throw new InvalidConfigException("Key file not found: $keyPath");
        }
        return new CryptKey($keyPath);
    }

    /**
     * @throws InvalidConfigException
     */
    public function getAuthorizationServer(): AuthorizationServer
    {
        if (!$this->_authorizationServer instanceof AuthorizationServer) {
            $this->_authorizationServer = new AuthorizationServer(
                $this->getComponent('clientRepository'),
                $this->getComponent('accessTokenRepository'),
                $this->getComponent('scopeRepository'),
                $this->privateKey,
                $this->publicKey,
                $this->encryptionKey
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
    public function getComponent(string $name): object
    {
        if (!isset($this->components[$name])) {
            throw new InvalidConfigException("Component '$name' is not configured.");
        }

        $componentConfig = $this->components[$name];
        if (is_array($componentConfig)) {
            if (isset($this->cache[$name])) {
                $componentConfig = ArrayHelper::merge($componentConfig, ['cache' => $this->cache[$name]]);
            }
        }

        return Yii::createObject($componentConfig);
    }

    /**
     * @throws InvalidConfigException
     */
    public function __get($name)
    {
        // Resolve repositories dynamically from components.
        if (isset($this->components[$name])) {
            return $this->getComponent($name);
        }

        return parent::__get($name);
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

    /**
     * @throws InvalidConfigException
     */
    public function getServerResponse(): ServerResponse
    {
        if (!$this->_serverResponse instanceof ServerResponse) {
            $this->_serverResponse = new ServerResponse();
        }

        return $this->_serverResponse;
    }

    public function getModel($name)
    {
        if (!isset($this->modelMap[$name])) {
            throw new InvalidArgumentException("Model '{$name}' not found in the model map.");
        }
        return $this->modelMap[$name];
    }

    /**
     * This method can be used by controllers to retrieve the final CORS behavior array.
     */
    public function getCorsBehavior(): ?array
    {
        if (!$this->enableCors) {
            return null;
        }
        // Return the full behavior array
        return $this->corsConfig;
    }
}
