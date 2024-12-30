<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Server;

use DateTimeZone;
use deadmantfa\yii2\oauth2\server\components\Events\AuthorizationEvent;
use deadmantfa\yii2\oauth2\server\components\Grant\RevokeGrant;
use deadmantfa\yii2\oauth2\server\components\ResponseTypes\RevokeResponse;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
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
        $publicKey = InMemory::file($this->publicKey->getKeyContents()); // Replace with actual public key path
        $privateKey = InMemory::file($this->privateKey); // Replace with actual private key path

        // Create JWT Configuration
        $jwtConfig = Configuration::forAsymmetricSigner($signer, $privateKey, $publicKey);

        // Set validation constraints
        $jwtConfig->setValidationConstraints(
            new StrictValidAt(new SystemClock(new DateTimeZone('UTC')))
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
     *
     * @return array
     */
    public function getEnabledGrantTypes(): array
    {
        return $this->enabledGrantTypes;
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
