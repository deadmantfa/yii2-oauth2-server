<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\controllers;

use deadmantfa\yii2\oauth2\server\models\AccessToken;
use deadmantfa\yii2\oauth2\server\Module;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\StreamInterface;
use Throwable;
use yii\rest\ActiveController;
use yii\rest\OptionsAction;
use yii\web\HttpException;

class RevokeController extends ActiveController
{
    public $modelClass = AccessToken::class;

    public function actions(): array
    {
        return [
            'options' => ['class' => OptionsAction::class],
        ];
    }

    /**
     * @throws HttpException
     */
    public function actionCreate(): StreamInterface
    {
        /** @var Module $module */
        $module = $this->module;

        try {
            $response = $module->getAuthorizationServer()
                ->respondToRevokeTokenRequest(
                    $module->getServerRequest(),
                    $module->getServerResponse()
                );

            return $response->getBody();
        } catch (OAuthServerException|Throwable $exception) {
            throw new HttpException($exception->statusCode ?? $exception->getHttpStatusCode(), $exception->getMessage(), 0);
        }
    }
}
