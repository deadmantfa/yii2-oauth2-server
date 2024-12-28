<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\AuthMethods;

use deadmantfa\yii2\oauth2\server\components\Exception\OAuthHttpException;
use deadmantfa\yii2\oauth2\server\components\Psr7\ServerRequest;
use deadmantfa\yii2\oauth2\server\components\Repositories\RepositoryCacheInterface;
use deadmantfa\yii2\oauth2\server\components\Server\ResourceServer;
use Exception;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Throwable;
use Yii;
use yii\helpers\ArrayHelper;
use yii\rbac\BaseManager;
use yii\web\HttpException;
use yii\web\IdentityInterface;
use yii\web\Request;
use yii\web\Response;
use yii\web\User;

abstract class AuthMethod extends \yii\filters\auth\AuthMethod
{
    public CryptKey|string $publicKey;
    public bool $setAuthManagerDefaultRoles = true;
    public array $cache = [];

    /**
     * @throws HttpException
     * @throws OAuthHttpException
     * @throws Exception
     */
    public function authenticate($user, $request, $response): ?IdentityInterface
    {
        if (!$this->tokenTypeExists($request)) {
            return null;
        }

        $accessTokenRepository = $this->getAccessTokenRepository();

        if ($accessTokenRepository instanceof RepositoryCacheInterface) {
            $accessTokenRepository->setCache(
                ArrayHelper::getValue($this->cache, AccessTokenRepositoryInterface::class)
            );
        }

        return $this->validate(
            new ResourceServer(
                $accessTokenRepository,
                $this->publicKey,
                $this->getAuthorizationValidator()
            ),
            new ServerRequest(
                $this->request ?: Yii::$app->getRequest()
            ),
            $this->response ?: Yii::$app->getResponse(),
            $this->user ?: Yii::$app->getUser()
        );
    }

    protected function tokenTypeExists(Request $request): bool
    {
        $authHeader = $request->getHeaders()->get('Authorization');
        return $authHeader !== null && $this->getTokenType() !== null &&
            preg_match('/^' . $this->getTokenType() . '\s+(.*?)$/', $authHeader);
    }

    protected abstract function getTokenType(): string;

    protected abstract function getAccessTokenRepository(): AccessTokenRepositoryInterface;

    /**
     * @throws OAuthHttpException
     * @throws HttpException
     */
    protected function validate(
        ResourceServer $resourceServer,
        ServerRequest  $serverRequest,
        Response       $response,
        User           $user
    ): ?IdentityInterface
    {
        try {
            $serverRequest = $resourceServer->validateAuthenticatedRequest($serverRequest);

            $identity = $user->loginByAccessToken(
                $serverRequest->getAttribute('oauth_access_token_id'),
                static::class
            );

            if ($identity === null || $serverRequest->getAttribute('oauth_user_id') !== $identity->getId()) {
                $this->handleFailure($response);
            }

            /** @var BaseManager $authManager */
            $authManager = Yii::$app->authManager;
            if ($authManager instanceof BaseManager && $this->setAuthManagerDefaultRoles) {
                $authManager->defaultRoles = $serverRequest->getAttribute('oauth_scopes', []);
            }

            return $identity;
        } catch (OAuthServerException $e) {
            throw new OAuthHttpException($e);
        } catch (Throwable $e) {
            throw new HttpException(500, 'Unable to validate the request.', 0, YII_DEBUG ? $e : null);
        }
    }

    /**
     * @throws OAuthServerException
     */
    public function handleFailure($response): void
    {
        throw OAuthServerException::accessDenied();
    }

    protected abstract function getAuthorizationValidator(): AuthorizationValidatorInterface;
}
