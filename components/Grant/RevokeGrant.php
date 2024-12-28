<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Grant;

use DateInterval;
use Exception;
use Lcobucci\JWT\Configuration;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

class RevokeGrant extends AbstractGrant
{
    protected CryptKey $publicKey;
    protected Configuration $jwtConfig;

    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        CryptKey                        $publicKey,
        Configuration                   $jwtConfig
    )
    {
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->publicKey = $publicKey;
        $this->jwtConfig = $jwtConfig;
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface  $responseType,
        DateInterval           $accessTokenTTL
    ): ResponseTypeInterface
    {
        throw new LogicException('This grant does not use this method.');
    }

    public function respondToRevokeTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface  $response
    ): ResponseTypeInterface
    {
        $client = $this->validateClient($request);
        $this->invalidateToken($request, $client->getIdentifier());

        return $response;
    }

    /**
     * @throws OAuthServerException
     */
    protected function invalidateToken(ServerRequestInterface $request, string $clientId): void
    {
        $tokenTypeHint = $this->getRequestParameter('token_type_hint', $request) ?? '';
        $callStack = $tokenTypeHint === 'refresh_token'
            ? ['invalidateRefreshToken', 'invalidateAccessToken']
            : ['invalidateAccessToken', 'invalidateRefreshToken'];

        foreach ($callStack as $function) {
            if ($this->$function($request, $clientId)) {
                break;
            }
        }
    }

    public function getIdentifier(): string
    {
        return 'revoke';
    }

    /**
     * @throws OAuthServerException
     */
    protected function invalidateAccessToken(ServerRequestInterface $request, string $clientId): bool
    {
        $accessToken = $this->getRequestParameter('token', $request);
        if (!$accessToken) {
            throw OAuthServerException::invalidRequest('token');
        }

        try {
            $token = $this->jwtConfig->parser()->parse($accessToken);
        } catch (Exception $e) {
            return false;
        }

        $constraints = $this->jwtConfig->validationConstraints();
        if (!$this->jwtConfig->validator()->validate($token, ...$constraints)) {
            throw OAuthServerException::accessDenied('Access token could not be verified.');
        }

        $claims = $token->claims();
        if ($claims->get('aud') !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OAuthServerException::invalidRefreshToken('Token is not linked to client.');
        }

        $this->accessTokenRepository->revokeAccessToken($claims->get('jti'));
        return true;
    }

    /**
     * @throws OAuthServerException
     */
    protected function invalidateRefreshToken(ServerRequestInterface $request, string $clientId): bool
    {
        $encryptedRefreshToken = $this->getRequestParameter('token', $request);
        if (!$encryptedRefreshToken) {
            throw OAuthServerException::invalidRequest('token');
        }

        try {
            $refreshToken = $this->decrypt($encryptedRefreshToken);
        } catch (Exception $e) {
            return false;
        }

        $refreshTokenData = json_decode($refreshToken, true);
        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OAuthServerException::invalidRefreshToken('Token is not linked to client.');
        }

        $this->accessTokenRepository->revokeAccessToken($refreshTokenData['access_token_id']);
        $this->refreshTokenRepository->revokeRefreshToken($refreshTokenData['refresh_token_id']);

        return true;
    }
}
