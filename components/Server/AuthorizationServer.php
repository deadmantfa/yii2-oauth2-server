<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Server;

use deadmantfa\yii2\oauth2\server\components\Events\AuthorizationEvent;
use deadmantfa\yii2\oauth2\server\components\Grant\RevokeGrant;
use deadmantfa\yii2\oauth2\server\components\ResponseTypes\RevokeResponse;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationServer extends \League\OAuth2\Server\AuthorizationServer
{
    /**
     * Handles the token request and emits an authorization event.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws OAuthServerException
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface      $response
    ): ResponseInterface
    {
        $response = parent::respondToAccessTokenRequest($request, $response);

        // Emit the authorization event
        $this->getEmitter()->emit(
            new AuthorizationEvent(
                $request,
                $response,
                $this->getJwtConfiguration() // Ensure JWT configuration is passed
            )
        );

        return $response;
    }

    /**
     * Returns the JWT configuration instance for token parsing and validation.
     *
     * @return Configuration
     */
    private function getJwtConfiguration(): Configuration
    {
        // Use a proper RSA key for signing and validation
        $signer = new Sha256();
        $publicKey = InMemory::file('/path/to/public.key'); // Replace with actual public key path
        $privateKey = InMemory::file('/path/to/private.key'); // Replace with actual private key path

        // Create JWT Configuration
        $jwtConfig = Configuration::forAsymmetricSigner($signer, $privateKey, $publicKey);

        // Set validation constraints
        $jwtConfig->setValidationConstraints(
            new StrictValidAt(new SystemClock())
        );

        return $jwtConfig;
    }

    /**
     * Handles token revocation requests.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws OAuthServerException
     */
    public function respondToRevokeTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface      $response
    ): ResponseInterface
    {
        $revokeGrant = $this->enabledGrantTypes['revoke'] ?? null;

        if ($revokeGrant instanceof RevokeGrant) {
            $this->responseType = new RevokeResponse();
            return $revokeGrant
                ->respondToRevokeTokenRequest($request, $this->getResponseType())
                ->generateHttpResponse($response);
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Get a parameter from the request body.
     *
     * @param string $parameter
     * @param ServerRequestInterface $request
     * @param mixed $default
     * @return mixed
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
