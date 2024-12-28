<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\ResponseTypes;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use Psr\Http\Message\ResponseInterface;

class MacTokenResponse extends AbstractResponseType
{
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $expireDateTime = $this->accessToken->getExpiryDateTime()->getTimestamp();

        $jwtAccessToken = $this->accessToken->convertToJWT($this->privateKey);

        $responseParams = [
            'token_type' => 'mac',
            'expires_in' => $expireDateTime - time(),
            'access_token' => (string)$jwtAccessToken,
            'kid' => $this->accessToken->identifier,
            'mac_key' => $this->accessToken->mac_key,
            'mac_algorithm' => $this->accessToken->getMacAlgorithm(),
        ];

        if ($this->refreshToken instanceof RefreshTokenEntityInterface) {
            $refreshTokenData = [
                'client_id' => $this->accessToken->getClient()->getIdentifier(),
                'refresh_token_id' => $this->refreshToken->getIdentifier(),
                'access_token_id' => $this->accessToken->getIdentifier(),
                'scopes' => $this->accessToken->getScopes(),
                'user_id' => $this->accessToken->getUserIdentifier(),
                'expire_time' => $this->refreshToken->getExpiryDateTime()->getTimestamp(),
            ];

            $responseParams['refresh_token'] = $this->encrypt(json_encode($refreshTokenData));
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(json_encode($responseParams));

        return $response;
    }
}
