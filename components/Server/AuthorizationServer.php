<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Server;

use deadmantfa\yii2\oauth2\server\components\Grant\RevokeGrant;
use deadmantfa\yii2\oauth2\server\components\ResponseTypes\RevokeResponse;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationServer extends \League\OAuth2\Server\AuthorizationServer
{
    protected CryptKeyInterface $publicKey;

    public function __construct(
        ClientRepositoryInterface      $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface       $scopeRepository,
        CryptKeyInterface|string       $privateKey,
        CryptKeyInterface|string       $publicKey,           // <--- Add this
        string                         $encryptionKey = null,
        ?EventDispatcherInterface      $eventDispatcher = null
    )
    {
        // Call parent constructor
        parent::__construct($clientRepository, $accessTokenRepository, $scopeRepository, $privateKey, $encryptionKey, $eventDispatcher);

        // Initialize your $publicKey

        if ($publicKey instanceof CryptKeyInterface === false) {
            $publicKey = new CryptKey($publicKey);
        }
        $this->publicKey = $publicKey;
    }

    /**
     * Handles token revocation requests.
     *
     * @throws OAuthServerException
     */
    public function respondToRevokeTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface      $response
    ): ResponseInterface
    {
        $revokeGrant = $this->getEnabledGrantTypes()['revoke'] ?? null;

        if ($revokeGrant instanceof RevokeGrant) {
            $this->responseType = new RevokeResponse();
            return $revokeGrant
                ->respondToRevokeTokenRequest($request, $this->getResponseType())
                ->generateHttpResponse($response);
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Get the enabled grant types.
     */
    public function getEnabledGrantTypes(): array
    {
        return $this->enabledGrantTypes;
    }

    /**
     * Get a parameter from the request body.
     *
     * @param mixed $default
     */
    protected function getRequestParameter(string $parameter, ServerRequestInterface $request, $default = null): mixed
    {
        $parsedBody = $request->getParsedBody();
        if (is_array($parsedBody) && array_key_exists($parameter, $parsedBody)) {
            return $parsedBody[$parameter];
        }

        return $default;
    }
}
