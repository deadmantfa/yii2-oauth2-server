<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\AuthorizationValidators;

use deadmantfa\yii2\oauth2\server\components\Mac;
use Lcobucci\JWT\Configuration;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

class MacTokenValidator implements AuthorizationValidatorInterface
{
    private AccessTokenRepositoryInterface $accessTokenRepository;
    private Configuration $jwtConfig;

    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, Configuration $jwtConfig)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->jwtConfig = $jwtConfig;
    }

    /**
     * Validates the authorization.
     *
     * @throws OAuthServerException
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        $authHeader = $request->getHeaderLine('Authorization');
        if ($authHeader === '' || $authHeader === '0') {
            throw OAuthServerException::accessDenied('Missing "Authorization" header.');
        }

        try {
            // Process the header to extract and validate the token
            $jwt = (new Mac($authHeader))->validate()->getJwt();

            // Validate JWT claims using configured constraints
            if (!$this->jwtConfig->validator()->validate($jwt, ...$this->jwtConfig->validationConstraints())) {
                throw OAuthServerException::accessDenied('Invalid JWT.');
            }

            // Check if the access token is revoked
            if ($this->accessTokenRepository->isAccessTokenRevoked($jwt->claims()->get('jti'))) {
                throw OAuthServerException::accessDenied('Access token has been revoked.');
            }

            // Attach validated claims to the request
            return $request
                ->withAttribute('oauth_access_token_id', $jwt->claims()->get('jti'))
                ->withAttribute('oauth_client_id', $jwt->claims()->get('aud'))
                ->withAttribute('oauth_user_id', $jwt->claims()->get('sub'))
                ->withAttribute('oauth_scopes', $jwt->claims()->get('scopes'));
        } catch (Throwable $e) {
            throw OAuthServerException::accessDenied($e->getMessage());
        }
    }
}
