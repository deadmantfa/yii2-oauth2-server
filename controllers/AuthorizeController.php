<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\controllers;

use deadmantfa\yii2\oauth2\server\Module;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use stdClass;
use Throwable;
use yii\helpers\Json;
use yii\rest\ActiveController;
use yii\rest\OptionsAction;
use yii\web\HttpException;

class AuthorizeController extends ActiveController
{
    public $modelClass = '';

    public function actions(): array
    {
        return [
            'options' => ['class' => OptionsAction::class],
        ];
    }

    public function behaviors(): array
    {
        $behaviors = parent::behaviors();

        // Retrieve the module's getCorsBehavior()
        // (only returns something if enableCors=true)
        /** @var Module $module */
        $module = $this->module;
        $corsBehavior = $module->getCorsBehavior();

        if ($corsBehavior !== null) {
            // Insert the CORS config into this controller's behaviors
            $behaviors['cors'] = $corsBehavior;
        }

        return $behaviors;
    }

    /**
     * Handles the initial authorization request.
     *
     * @throws HttpException
     */
    public function actionIndex(): array
    {
        /** @var Module $module */
        $module = $this->module;

        try {
            // Fetch the AuthorizationServer instance
            $authServer = $module->getAuthorizationServer();

            // Initialize AuthorizationRequest
            /** @var AuthorizationRequest $authRequest */
            $authRequest = $authServer->validateAuthorizationRequest($module->getServerRequest());

            // Optional: customize the AuthorizationRequest
            $authRequest->setUser(new stdClass()); // Replace with actual user entity
            $authRequest->setAuthorizationApproved(true); // Approve or deny the request programmatically

            // Generate the response
            $response = $authServer->completeAuthorizationRequest(
                $authRequest,
                $module->getServerResponse()
            );

            return Json::decode((string)$response->getBody());
        } catch (OAuthServerException|Throwable $exception) {
            throw new HttpException($exception->statusCode ?? $exception->getHttpStatusCode(), $exception->getMessage(), 0);
        }
    }
}
