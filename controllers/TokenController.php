<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\controllers;

use deadmantfa\yii2\oauth2\server\models\AccessToken;
use deadmantfa\yii2\oauth2\server\Module;
use League\OAuth2\Server\Exception\OAuthServerException;
use Throwable;
use yii\helpers\Json;
use yii\rest\ActiveController;
use yii\rest\OptionsAction;
use yii\web\BadRequestHttpException;
use yii\web\HttpException;

class TokenController extends ActiveController
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
     * @throws BadRequestHttpException
     */
    public function actionCreate(): array
    {
        /** @var Module $module */
        $module = $this->module;

        try {
            $response = $module->getAuthorizationServer()
                ->respondToAccessTokenRequest(
                    $module->getServerRequest(),
                    $module->getServerResponse()
                );

            return Json::decode((string)$response->getBody());
        } catch (OAuthServerException|Throwable $exception) {
            throw new HttpException($exception->statusCode ?? $exception->getHttpStatusCode(), $exception->getMessage(), 0);
        }
    }
}
