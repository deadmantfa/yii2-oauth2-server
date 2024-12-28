<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Events;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use yii\helpers\Json;

class AuthorizationEvent
{
    public const USER_AUTHENTICATION_SUCCEED = 'user.authentication.succeed';

    public ServerRequestInterface $request;
    public ResponseInterface $response;
    private ?Plain $_token = null;
    private Configuration $jwtConfig;

    public function __construct(
        ServerRequestInterface $request,
        ResponseInterface      $response,
        Configuration          $jwtConfig
    )
    {
        $this->request = $request;
        $this->response = $response;
        $this->jwtConfig = $jwtConfig;
    }

    /**
     * Retrieves and parses the access token from the response.
     */
    public function getToken(): ?Plain
    {
        if ($this->_token === null) {
            $responseBody = (string)$this->response->getBody();
            $response = Json::decode($responseBody);

            if (isset($response['access_token'])) {
                $parsedToken = $this->jwtConfig->parser()->parse($response['access_token']);
                if ($parsedToken instanceof Plain) {
                    $this->_token = $parsedToken;
                }
            }
        }

        return $this->_token;
    }
}
