<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server;

use deadmantfa\yii2\oauth2\server\components\Repositories\AccessTokenRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\ClientRepository;
use deadmantfa\yii2\oauth2\server\components\Repositories\ScopeRepository;
use deadmantfa\yii2\oauth2\server\components\Server\AuthorizationServer;
use deadmantfa\yii2\oauth2\server\components\Server\ResourceServer;
use Yii;
use yii\base\BootstrapInterface;
use yii\base\InvalidConfigException;
use yii\web\Application;

class Module extends \yii\base\Module implements BootstrapInterface
{
    public $defaultRoute = 'authorize';

    public function init(): void
    {
        parent::init();

        if (Yii::$app instanceof Application) {
            $this->configureServers();
        }
    }

    protected function configureServers(): void
    {
        Yii::$container->set(AuthorizationServer::class, fn() => $this->createAuthorizationServer());
        Yii::$container->set(ResourceServer::class, fn() => $this->createResourceServer());
    }

    /**
     * @throws InvalidConfigException
     */
    protected function createAuthorizationServer(): AuthorizationServer
    {
        $privateKeyPath = Yii::getAlias('@app/config/private.key');
        if (!file_exists($privateKeyPath)) {
            throw new InvalidConfigException('Private key file is missing.');
        }

        $encryptionKey = getenv('OAUTH2_ENCRYPTION_KEY');
        if ($encryptionKey === false) {
            throw new InvalidConfigException('Encryption key is not set.');
        }

        return new AuthorizationServer(
            Yii::createObject(ClientRepository::class),
            Yii::createObject(AccessTokenRepository::class),
            Yii::createObject(ScopeRepository::class),
            $privateKeyPath,
            $encryptionKey
        );
    }

    /**
     * @throws InvalidConfigException
     */
    protected function createResourceServer(): ResourceServer
    {
        $publicKeyPath = Yii::getAlias('@app/config/public.key');
        if (!file_exists($publicKeyPath)) {
            throw new InvalidConfigException('Public key file is missing.');
        }

        return new ResourceServer(
            Yii::createObject(AccessTokenRepository::class),
            $publicKeyPath
        );
    }

    public function bootstrap($app): void
    {
        if ($app instanceof Application) {
            $app->urlManager->addRules([
                'POST oauth2/authorize' => 'oauth2/authorize/index',
                'POST oauth2/token' => 'oauth2/token/index',
                'POST oauth2/revoke' => 'oauth2/revoke/index',
            ], false);
        }
    }
}
