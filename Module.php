<?php

namespace deadmantfa\yii2\oauth2\server;

use deadmantfa\yii2\oauth2\server\components\Psr7\ServerRequest;
use deadmantfa\yii2\oauth2\server\components\Psr7\ServerResponse;
use deadmantfa\yii2\oauth2\server\components\Repositories\BearerTokenRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\ClientRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\MacTokenRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\RefreshTokenRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\RepositoryCacheInterface;
use deadmantfa\yii2\oauth2\server\components\Repositories\ScopeRepository;
use deadmantfa\yii2\oauth2\server\components\ResponseTypes\MacTokenResponse;
use deadmantfa\yii2\oauth2\server\components\Server\AuthorizationServer;
use deadmantfa\yii2\oauth2\server\controllers\AuthorizeController;
use deadmantfa\yii2\oauth2\server\controllers\RevokeController;
use deadmantfa\yii2\oauth2\server\controllers\TokenController;
use deadmantfa\yii2\oauth2\server\models\Client;
use Exception;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Yii;
use yii\base\Application;
use yii\base\BootstrapInterface;
use yii\base\InvalidConfigException;
use yii\filters\Cors;
use yii\helpers\ArrayHelper;
use yii\rest\UrlRule;
use yii\web\GroupUrlRule;

/**
 * Class Module
 * @package deadmantfa\yii2\oauth2\server
 *
 * @property-read AuthorizationServer $authorizationServer
 * @property-read AccessTokenRepositoryInterface $accessTokenRepository
 * @property ClientRepositoryInterface $clientRepository
 * @property RefreshTokenRepositoryInterface $refreshTokenRepository
 * @property ScopeRepositoryInterface $scopeRepository
 * @property UserRepositoryInterface $userRepository
 * @property ResponseTypeInterface $responseType
 *
 * @todo: ability to define access token type for refresh token grant, client-refresh grant type connection review
 */
class Module extends \yii\base\Module implements BootstrapInterface
{
    /**
     * @var array
     */
    public $controllerMap = [
        'authorize' => [
            'class' => AuthorizeController::class,
            'as corsFilter' => Cors::class,
        ],
        'revoke' => [
            'class' => RevokeController::class,
            'as corsFilter' => Cors::class,
        ],
        'token' => [
            'class' => TokenController::class,
            'as corsFilter' => Cors::class,
        ],
    ];

    /**
     * @var array
     */
    public $urlManagerRules = [];

    /**
     * @var CryptKey|string
     */
    public $privateKey;

    /**
     * @var CryptKey|string
     */
    public $publicKey;

    /**
     * @var callable
     */
    public $enableGrantTypes;

    /**
     * @var array
     */
    public $cache;

    /**
     * @var AuthorizationServer
     */
    private $_authorizationServer;
    /**
     * @var string
     */
    private $_encryptionKey;

    /**
     * @var ServerRequest
     */
    private $_serverRequest;
    /**
     * @var ServerResponse
     */
    private $_serverResponse;
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $_accessTokenRepository;

    /**
     * @var ClientEntityInterface|Client
     */
    private $_clientEntity;
    /**
     * @var ResponseTypeInterface
     */
    private $_responseType;

    public function __construct($id, $parent = null, $config = [])
    {
        parent::__construct($id, $parent, ArrayHelper::merge([
            'components' => [
                'userRepository' => [
                    'class' => Yii::$app->user->identityClass,
                ],
                'clientRepository' => [
                    'class' => ClientRepository::class,
                ],
                'scopeRepository' => [
                    'class' => ScopeRepository::class,
                ],
                'refreshTokenRepository' => [
                    'class' => RefreshTokenRepository::class,
                ],
            ],
        ], $config));
    }

    /**
     * Sets module's URL manager rules on application's bootstrap.
     * @param Application $app
     */
    public function bootstrap($app): void
    {
        $app->getUrlManager()
            ->addRules((new GroupUrlRule([
                'ruleConfig' => [
                    'class' => UrlRule::class,
                    'pluralize' => false,
                    'only' => ['create', 'options']
                ],
                'rules' => ArrayHelper::merge([
                    ['controller' => $this->uniqueId . '/authorize'],
                    ['controller' => $this->uniqueId . '/revoke'],
                    ['controller' => $this->uniqueId . '/token'],
                ], $this->urlManagerRules)
            ]))->rules, false);
    }

    /**
     * {@inheritdoc}
     */
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
     * @return AuthorizationServer
     * @throws OAuthServerException
     */
    public function getAuthorizationServer(): AuthorizationServer
    {
        if (!$this->_authorizationServer instanceof AuthorizationServer) {
            $this->prepareAuthorizationServer();
        }

        return $this->_authorizationServer;
    }

    /**
     * @throws OAuthServerException
     * @throws Exception
     */
    protected function prepareAuthorizationServer(): void
    {
        $this->_responseType = ArrayHelper::getValue($this, 'clientEntity.responseType');

        $this->_authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->_encryptionKey,
            $this->_responseType
        );

        if (is_callable($this->enableGrantTypes) !== true) {
            $this->enableGrantTypes = function (Module &$module) {
                throw OAuthServerException::unsupportedGrantType();
            };
        }

        call_user_func_array($this->enableGrantTypes, [&$this]);
    }

    /**
     * @return BearerTokenRepository|MacTokenRepository|AccessTokenRepositoryInterface
     * @throws InvalidConfigException
     */
    public function getAccessTokenRepository(): MacTokenRepository|AccessTokenRepositoryInterface|BearerTokenRepository
    {
        if (!$this->_accessTokenRepository instanceof AccessTokenRepositoryInterface) {
            $this->_accessTokenRepository = $this->prepareAccessTokenRepository();
        }

        if ($this->_accessTokenRepository instanceof RepositoryCacheInterface) {
            $this->_accessTokenRepository->setCache(
                ArrayHelper::getValue($this->cache, AccessTokenRepositoryInterface::class)
            );
        }

        return $this->_accessTokenRepository;
    }

    /**
     * @return BearerTokenRepository|MacTokenRepository
     * @throws InvalidConfigException
     */
    protected function prepareAccessTokenRepository(): MacTokenRepository|BearerTokenRepository
    {
        if ($this->_responseType instanceof MacTokenResponse) {
            return new MacTokenRepository($this->_encryptionKey);
        }

        return new BearerTokenRepository();
    }

    /**
     * @return ServerRequest
     */
    public function getServerRequest(): ServerRequest
    {
        if (!$this->_serverRequest instanceof ServerRequest) {
            $request = Yii::$app->request;
            $this->_serverRequest = (new ServerRequest($request))
                ->withParsedBody($request->bodyParams);
        }

        return $this->_serverRequest;
    }

    /**
     * @return ServerResponse
     */
    public function getServerResponse(): ServerResponse
    {
        if (!$this->_serverResponse instanceof ServerResponse) {
            $this->_serverResponse = new ServerResponse();
        }

        return $this->_serverResponse;
    }

    /**
     * @param string $encryptionKey
     */
    public function setEncryptionKey(string $encryptionKey): void
    {
        $this->_encryptionKey = $encryptionKey;
    }

    /**
     * @return ClientEntityInterface
     * @throws OAuthServerException
     */
    protected function getClientEntity(): Client|ClientEntityInterface
    {
        if (!$this->_clientEntity instanceof ClientEntityInterface) {
            $request = Yii::$app->request;

            // Typically from Basic Auth or from the request body:
            $clientIdentifier = $request->getAuthUser() ?: $request->post('client_id');
            $clientSecret = $request->getAuthPassword() ?: $request->post('client_secret');
            $grantType = $request->post('grant_type');

            // 1) Fetch client by ID
            $clientEntity = $this->clientRepository->getClientEntity($clientIdentifier);
            if (!$clientEntity) {
                throw OAuthServerException::invalidClient();
            }

            // 2) Validate the secret + grant type
            $isValid = $this->clientRepository->validateClient($clientIdentifier, $clientSecret, $grantType);
            if (!$isValid) {
                throw OAuthServerException::invalidClient();
            }

            $this->_clientEntity = $clientEntity;
        }

        return $this->_clientEntity;
    }

    /**
     * @param ClientEntityInterface $clientEntity
     */
    public function setClientEntity(ClientEntityInterface $clientEntity): void
    {
        $this->_clientEntity = $clientEntity;
    }
}
